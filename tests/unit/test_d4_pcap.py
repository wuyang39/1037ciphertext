from __future__ import annotations

import struct
from pathlib import Path

import pytest

from infra.pcap_tls import PcapError, analyse_capture, render_summary


PCAP_PORTS = (47100, 47101)


def _ipv4_tcp(
    *,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    payload: bytes,
    sequence: int = 1,
    flags: int = 0x18,
) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence, 0, 5 << 4, flags, 65535, 0, 0)
    tcp += payload
    total = 20 + len(tcp)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        6,
        0,
        bytes(int(part) for part in source.split(".")),
        bytes(int(part) for part in destination.split(".")),
    )
    return ipv4 + tcp


def _ethernet_ipv4_tcp(**kwargs) -> bytes:
    ethernet = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
    return ethernet + _ipv4_tcp(**kwargs)


def _sll2_ipv4_tcp(**kwargs) -> bytes:
    """A frame as ``tcpdump -i any`` writes it: a 20-byte cooked v2 header."""
    sll2 = struct.pack("!HHIHBB", 0x0800, 0, 1, 1, 0, 6) + b"\x00" * 8
    assert len(sll2) == 20
    return sll2 + _ipv4_tcp(**kwargs)


def _pcap(packets: list[bytes], linktype: int = 1) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    body = bytearray()
    for index, packet in enumerate(packets):
        body += struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet))
        body += packet
    return header + bytes(body)


def _record(content_type: int, body: bytes) -> bytes:
    return struct.pack("!BHH", content_type, 0x0303, len(body)) + body


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _client_hello(versions: tuple[int, ...] = (0x0304,)) -> bytes:
    body = b"\x03\x03" + b"\x00" * 32
    body += b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    extension = (
        struct.pack("!HH", 43, 1 + 2 * len(versions))
        + bytes([2 * len(versions)])
        + b"".join(struct.pack("!H", version) for version in versions)
    )
    body += struct.pack("!H", len(extension)) + extension
    return body


def _server_hello(version: int = 0x0304) -> bytes:
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
    body += b"\x13\x01"
    body += b"\x00"
    extension = struct.pack("!HH", 43, 2) + struct.pack("!H", version)
    body += struct.pack("!H", len(extension)) + extension
    return body


def _payloads(
    client_versions: tuple[int, ...] = (0x0304,),
    server_version: int = 0x0304,
) -> tuple[bytes, bytes, bytes]:
    """(client hello, server hello, application data) as TLS records."""
    return (
        _record(22, _handshake(1, _client_hello(client_versions))),
        _record(22, _handshake(2, _server_hello(server_version))),
        _record(23, b"\x17\x03\x03"),
    )


def _client_next_sequence() -> int:
    """Where the next segment of the client direction has to start."""
    client_payload, _, data_payload = _payloads()
    return 1 + len(client_payload) + len(data_payload)


def _handshake_packets(
    client_versions: tuple[int, ...] = (0x0304,),
    server_version: int = 0x0304,
    frame=_ethernet_ipv4_tcp,
) -> list[bytes]:
    # A real capture carries sequence numbers, and the analyser reassembles by
    # them, so the fixtures advance the per-direction sequence instead of
    # parking every segment at 1.
    client_payload, server_payload, data_payload = _payloads(
        client_versions, server_version
    )
    return [
        frame(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=client_payload,
            sequence=1,
        ),
        frame(
            source="10.0.0.2",
            source_port=47101,
            destination="10.0.0.1",
            destination_port=47100,
            payload=server_payload,
            sequence=1,
        ),
        frame(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=data_payload,
            sequence=1 + len(client_payload),
        ),
    ]


def test_capture_with_tls13_records_only_is_green(tmp_path: Path) -> None:
    capture = tmp_path / "tls.pcap"
    capture.write_bytes(_pcap(_handshake_packets()))
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["tls_only"] is True
    assert summary["non_tls_payload_bytes"] == 0
    assert summary["tls13_flows"] == 1
    assert summary["tls12_or_lower_flows"] == 0
    assert summary["verdict"] == "tls13_only"
    assert "tls13_only" in render_summary(summary)


def test_cooked_v2_capture_from_tcpdump_any_is_parsed(tmp_path: Path) -> None:
    """``tcpdump -i any`` writes Linux SLL2 frames, not Ethernet ones."""
    capture = tmp_path / "any.pcap"
    capture.write_bytes(
        _pcap(_handshake_packets(frame=_sll2_ipv4_tcp), linktype=276)
    )
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["packets_on_expected_ports"] == 3
    assert summary["tls_only"] is True
    assert summary["non_tls_payload_bytes"] == 0
    assert summary["verdict"] == "tls13_only"


def test_retransmitted_segment_does_not_shift_the_stream(tmp_path: Path) -> None:
    """A duplicate segment is a loopback artefact, not a plaintext violation.

    A capture taken while three enclaves are running does contain
    retransmissions; appending one twice would misalign every record after it
    and make ciphertext look like a plaintext leak.
    """
    packets = _handshake_packets()
    client_payload, _, _ = _payloads()
    packets.insert(
        1,
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=client_payload,
            sequence=1,
        ),
    )
    capture = tmp_path / "retransmit.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["retransmitted_packets"] == 1
    assert summary["unreassembled_bytes"] == 0
    assert summary["non_tls_payload_bytes"] == 0
    assert summary["verdict"] == "tls13_only"


def test_out_of_order_segment_is_reordered(tmp_path: Path) -> None:
    """A capture that reorders two segments still reassembles in order."""
    client_payload, server_payload, data_payload = _payloads()
    packets = [
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=b"",
            sequence=0,
            flags=0x02,
        ),
        # The application-data segment arrives before the hello that precedes
        # it, so the analyser has to hold it and place it after.
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=data_payload,
            sequence=1 + len(client_payload),
        ),
        _ethernet_ipv4_tcp(
            source="10.0.0.2",
            source_port=47101,
            destination="10.0.0.1",
            destination_port=47100,
            payload=server_payload,
            sequence=1,
        ),
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=client_payload,
            sequence=1,
        ),
    ]
    capture = tmp_path / "reordered.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["out_of_order_packets"] == 1
    assert summary["unreassembled_bytes"] == 0
    assert summary["non_tls_payload_bytes"] == 0
    assert summary["verdict"] == "tls13_only"


def test_plaintext_payload_fails_the_capture(tmp_path: Path) -> None:
    packets = _handshake_packets()
    packets.append(
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=47100,
            destination="10.0.0.2",
            destination_port=47101,
            payload=b"GET /status HTTP/1.1\r\n\r\n",
            sequence=_client_next_sequence(),
        )
    )
    capture = tmp_path / "mixed.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["tls_only"] is False
    assert summary["non_tls_payload_bytes"] > 0
    assert summary["verdict"] == "tls_or_plaintext_violation"


def test_tls12_only_client_hello_fails_the_capture(tmp_path: Path) -> None:
    capture = tmp_path / "tls12.pcap"
    capture.write_bytes(
        _pcap(_handshake_packets(client_versions=(0x0303, 0x0302), server_version=0x0303))
    )
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["tls12_or_lower_flows"] == 1
    assert summary["tls13_flows"] == 0
    assert summary["verdict"] == "tls_or_plaintext_violation"


def test_capture_outside_the_expected_ports_is_ignored(tmp_path: Path) -> None:
    packets = [
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=49999,
            destination="10.0.0.2",
            destination_port=50000,
            payload=b"unrelated traffic",
        )
    ]
    capture = tmp_path / "other.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(capture, expected_ports=PCAP_PORTS)
    assert summary["packets_on_expected_ports"] == 0
    assert summary["flows"] == []
    assert summary["verdict"] == "tls_or_plaintext_violation"


def test_deliberate_plaintext_probe_is_attributed_not_flagged(tmp_path: Path) -> None:
    """The refused probe is expected bytes, not evidence of a plaintext leak."""
    marker = b"A1-22-PLAINTEXT-PROBE\r\n"
    packets = _handshake_packets()
    packets.append(
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=50001,
            destination="10.0.0.2",
            destination_port=47101,
            payload=marker,
        )
    )
    capture = tmp_path / "probe.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(
        capture,
        expected_ports=PCAP_PORTS,
        expected_probe_endpoints=[("10.0.0.2", 47101)],
        probe_marker=marker,
    )
    assert summary["expected_probe_bytes"] == len(marker)
    assert summary["non_tls_payload_bytes"] == 0
    assert summary["tls_only"] is True
    assert summary["verdict"] == "tls13_only"
    assert "expected probe bytes" in render_summary(summary)


def test_plaintext_that_is_not_the_probe_still_fails(tmp_path: Path) -> None:
    packets = _handshake_packets()
    packets.append(
        _ethernet_ipv4_tcp(
            source="10.0.0.1",
            source_port=50002,
            destination="10.0.0.2",
            destination_port=47101,
            payload=b"GET /status HTTP/1.1\r\n\r\n",
        )
    )
    capture = tmp_path / "smuggled.pcap"
    capture.write_bytes(_pcap(packets))
    summary = analyse_capture(
        capture,
        expected_ports=PCAP_PORTS,
        expected_probe_endpoints=[("10.0.0.2", 47101)],
        probe_marker=b"A1-22-PLAINTEXT-PROBE\r\n",
    )
    assert summary["expected_probe_bytes"] == 0
    assert summary["non_tls_payload_bytes"] > 0
    assert summary["verdict"] == "tls_or_plaintext_violation"


def test_bad_magic_is_rejected(tmp_path: Path) -> None:
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 20)
    with pytest.raises(PcapError):
        analyse_capture(capture, expected_ports=PCAP_PORTS)

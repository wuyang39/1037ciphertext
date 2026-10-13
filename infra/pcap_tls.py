"""Minimal classic-pcap reader that summarises the D4 transport.

The D4 acceptance has to show that the protocol traffic between the three
enclaves carries TLS records and nothing else. Rather than adding a tshark
dependency, this module parses the classic libpcap format directly, reassembles
each TCP flow by sequence number, walks the TLS record layer, and reports:

* the flows and their packet/byte counts,
* the TLS record types and handshake messages seen per flow,
* the versions offered and negotiated in the hello messages, and
* any TCP payload that is not a well-formed TLS record.

Reassembly follows the sequence number instead of the capture order: a loopback
capture under enclave load does contain retransmitted segments, and appending
one twice shifts the stream so that ciphertext starts looking like plaintext.
Retransmissions, out-of-order segments and unfilled holes are counted per flow,
and a hole that never got filled is reported as unreassembled bytes instead of
being silently dropped.

The D4 run deliberately fires a plaintext probe at each listener to show it is
refused, so the capture always contains a few bytes that are not TLS. The
analyser is told which endpoints were probed and what marker the probe sends;
those bytes are attributed separately as ``expected_probe_bytes``, and only
*unexplained* non-TLS payload fails the verdict.

Only the summary leaves the runner; the capture itself stays in the evidence
directory as the raw artifact.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence


PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

TLS_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}
TLS_HANDSHAKE_TYPES = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    8: "encrypted_extensions",
    11: "certificate",
    13: "certificate_request",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}
TLS13_VERSION = 0x0304

# The six protocol ports a D4 run uses: BRPC 47100-47102 and the share
# channels 47200-47202. ``--d4-ports`` covers the runs that use the defaults.
D4_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)
TLS_LEGACY_VERSION = 0x0303

# Sequence arithmetic happens modulo 2**32; a delta below half the space is
# "ahead of the stream", anything else is "behind it".
SEQUENCE_MASK = 0xFFFFFFFF
SEQUENCE_HALF = 1 << 31
# Out-of-order segments are held until the hole in front of them is filled.
# A capture that needs more than this is not waiting on TCP, it is losing
# packets, and the missing bytes are reported instead.
MAX_PENDING_SEGMENTS = 64


class PcapError(ValueError):
    """The capture file or its summary could not be produced."""


@dataclass
class TlsFlow:
    """One direction of one TCP flow, reassembled in capture order."""

    key: tuple[str, int, str, int]
    packets: int = 0
    bytes_total: int = 0
    record_types: dict[str, int] = field(default_factory=dict)
    handshake_types: dict[str, int] = field(default_factory=dict)
    offered_versions: list[int] = field(default_factory=list)
    negotiated_version: int | None = None
    malformed_bytes: int = 0
    payload_bytes: int = 0
    alerts: list[int] = field(default_factory=list)
    malformed_prefix: bytes = b""
    connections: int = 0
    retransmitted_packets: int = 0
    retransmitted_bytes: int = 0
    out_of_order_packets: int = 0
    gap_packets: int = 0
    unreassembled_bytes: int = 0
    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _next_seq: int | None = None
    _pending: dict[int, bytes] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow": {
                "src": self.key[0],
                "sport": self.key[1],
                "dst": self.key[2],
                "dport": self.key[3],
            },
            "packets": self.packets,
            "bytes": self.bytes_total,
            "payload_bytes": self.payload_bytes,
            "record_types": dict(sorted(self.record_types.items())),
            "handshake_types": dict(sorted(self.handshake_types.items())),
            "offered_versions": [f"0x{value:04x}" for value in self.offered_versions],
            "negotiated_version": (
                f"0x{self.negotiated_version:04x}"
                if self.negotiated_version is not None
                else None
            ),
            "alerts": self.alerts,
            "malformed_bytes": self.malformed_bytes,
            "malformed_prefix": self.malformed_prefix.hex(),
            "connections": self.connections,
            "retransmitted_packets": self.retransmitted_packets,
            "retransmitted_bytes": self.retransmitted_bytes,
            "out_of_order_packets": self.out_of_order_packets,
            "gap_packets": self.gap_packets,
            "unreassembled_bytes": self.unreassembled_bytes,
        }


def _read_global_header(handle: Any) -> tuple[str, int]:
    header = handle.read(24)
    if len(header) != 24:
        raise PcapError("the capture is shorter than a pcap global header")
    magic = struct.unpack("<I", header[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise PcapError(f"unsupported pcap magic: 0x{magic:08x}")
    linktype = struct.unpack(f"{endian}I", header[20:24])[0]
    return endian, linktype


def _iter_packets(path: Path) -> Iterable[bytes]:
    with Path(path).open("rb") as handle:
        endian, host = _read_global_header(handle)
        while True:
            header = handle.read(16)
            if not header:
                return
            if len(header) != 16:
                raise PcapError("the capture ends inside a packet header")
            _, _, included, _ = struct.unpack(f"{endian}IIII", header)
            payload = handle.read(included)
            if len(payload) != included:
                raise PcapError("the capture ends inside a packet payload")
            if host == LINKTYPE_ETHERNET:
                if len(payload) < 14:
                    continue
                ethertype = struct.unpack("!H", payload[12:14])[0]
                if ethertype != 0x0800:
                    continue
                yield payload[14:]
            elif host == LINKTYPE_RAW:
                yield payload
            elif host == LINKTYPE_LINUX_SLL:
                if len(payload) < 16:
                    continue
                yield payload[16:]
            elif host == LINKTYPE_LINUX_SLL2:
                # "any" device captures on modern Linux use the cooked v2
                # header: a 20-byte preamble in front of the IPv4 packet.
                if len(payload) < 20:
                    continue
                protocol = struct.unpack("!H", payload[:2])[0]
                if protocol != 0x0800:
                    continue
                yield payload[20:]
            else:
                raise PcapError(f"unsupported pcap link type: {host}")


def _parse_tcp(
    packet: bytes,
) -> tuple[str, int, str, int, int, int, bytes] | None:
    """Return (src, sport, dst, dport, sequence, flags, payload)."""
    if len(packet) < 20:
        return None
    version_ihl = packet[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(packet) < ihl + 20 or packet[9] != 6:
        return None
    total_length = struct.unpack("!H", packet[2:4])[0]
    fragment_offset = struct.unpack("!H", packet[6:8])[0] & 0x1FFF
    if fragment_offset:
        return None
    source = ".".join(str(byte) for byte in packet[12:16])
    destination = ".".join(str(byte) for byte in packet[16:20])
    tcp = packet[ihl:]
    source_port, destination_port = struct.unpack("!HH", tcp[:4])
    sequence = struct.unpack("!I", tcp[4:8])[0]
    flags = tcp[13]
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or len(tcp) < offset:
        return None
    payload = tcp[offset:]
    if total_length and ihl + len(tcp) > total_length:
        payload = payload[: max(total_length - ihl - offset, 0)]
    return source, source_port, destination, destination_port, sequence, flags, bytes(payload)


def _deliver(flow: TlsFlow, payload: bytes) -> None:
    """Append in-order bytes to the stream and parse whatever completed."""
    flow._buffer.extend(payload)
    flow._next_seq = (flow._next_seq + len(payload)) & SEQUENCE_MASK  # type: ignore[operator]
    _parse_tls_records(flow)


def _drain_pending(flow: TlsFlow) -> None:
    """Deliver the segments that were waiting behind the hole just filled."""
    while True:
        payload = flow._pending.pop(flow._next_seq, None)  # type: ignore[arg-type]
        if payload is None:
            return
        _deliver(flow, payload)


def _feed_segment(flow: TlsFlow, sequence: int, flags: int, payload: bytes) -> None:
    """Place one TCP segment in the stream, deduplicating retransmissions.

    The flow is one direction of one 4-tuple, and ports do get reused: a SYN
    opens a fresh stream (which is how a second client_hello lands in the same
    key), a FIN after the last byte closes it, and a capture that starts
    mid-connection simply adopts the first sequence number it sees.
    """
    syn = bool(flags & 0x02)
    fin = bool(flags & 0x01)
    if syn:
        flow.connections += 1
        flow._next_seq = (sequence + 1) & SEQUENCE_MASK
        flow._pending.clear()
    if not payload:
        if fin and flow._pending:
            flow.unreassembled_bytes += sum(len(part) for part in flow._pending.values())
            flow._pending.clear()
        if fin:
            flow._next_seq = None
        return
    if flow._next_seq is None:
        flow._next_seq = sequence
    delta = (sequence - flow._next_seq) & SEQUENCE_MASK
    if delta == 0:
        _deliver(flow, payload)
        _drain_pending(flow)
        return
    if delta < SEQUENCE_HALF:
        # Ahead of the stream: the capture is missing the bytes in between.
        flow.out_of_order_packets += 1
        flow.gap_packets += 1
        if len(flow._pending) < MAX_PENDING_SEGMENTS:
            flow._pending[sequence] = payload
        else:
            flow.unreassembled_bytes += len(payload)
        return
    # Behind the stream: a retransmission, possibly carrying new tail bytes.
    flow.retransmitted_packets += 1
    flow.retransmitted_bytes += len(payload)
    overlap = (flow._next_seq - sequence) & SEQUENCE_MASK
    if overlap < len(payload):
        _deliver(flow, payload[overlap:])
        _drain_pending(flow)


def _parse_tls_records(flow: TlsFlow) -> None:
    buffer = flow._buffer
    while len(buffer) >= 5:
        content_type, version, length = struct.unpack("!BHH", bytes(buffer[:5]))
        if content_type not in TLS_CONTENT_TYPES:
            if not flow.malformed_prefix:
                flow.malformed_prefix = bytes(buffer[:64])
            flow.malformed_bytes += len(buffer)
            buffer.clear()
            return
        if len(buffer) < 5 + length:
            return
        record = bytes(buffer[5 : 5 + length])
        del buffer[: 5 + length]
        flow.record_types[TLS_CONTENT_TYPES[content_type]] = (
            flow.record_types.get(TLS_CONTENT_TYPES[content_type], 0) + 1
        )
        if content_type == 22:
            _parse_handshake(flow, record)
        elif content_type == 21 and record:
            level = record[0]
            description = record[1] if len(record) > 1 else -1
            flow.alerts.append((level << 8) | description)
        elif content_type == 23 and version != TLS_LEGACY_VERSION and version != 0x0301:
            # Application data records keep the legacy version on the wire.
            flow.malformed_bytes += 1


def _parse_handshake(flow: TlsFlow, body: bytes) -> None:
    offset = 0
    while offset + 4 <= len(body):
        message_type = body[offset]
        length = int.from_bytes(body[offset + 1 : offset + 4], "big")
        message = body[offset + 4 : offset + 4 + length]
        if len(message) != length:
            return
        offset += 4 + length
        name = TLS_HANDSHAKE_TYPES.get(message_type, f"type_{message_type}")
        flow.handshake_types[name] = flow.handshake_types.get(name, 0) + 1
        if message_type == 1:
            _parse_client_hello(flow, message)
        elif message_type == 2:
            _parse_server_hello(flow, message)


def _parse_client_hello(flow: TlsFlow, message: bytes) -> None:
    if len(message) < 34:
        return
    session_length = message[34]
    offset = 35 + session_length
    if offset + 2 > len(message):
        return
    cipher_length = struct.unpack("!H", message[offset : offset + 2])[0]
    offset += 2 + cipher_length
    if offset >= len(message):
        return
    compression_length = message[offset]
    offset += 1 + compression_length
    if offset + 2 > len(message):
        return
    extensions_length = struct.unpack("!H", message[offset : offset + 2])[0]
    offset += 2
    end = min(offset + extensions_length, len(message))
    while offset + 4 <= end:
        extension_type, extension_length = struct.unpack(
            "!HH", message[offset : offset + 4]
        )
        data = message[offset + 4 : offset + 4 + extension_length]
        offset += 4 + extension_length
        if extension_type == 43 and len(data) >= 1:
            versions = data[1:]
            for index in range(0, len(versions) - 1, 2):
                flow.offered_versions.append(
                    struct.unpack("!H", versions[index : index + 2])[0]
                )


def _parse_server_hello(flow: TlsFlow, message: bytes) -> None:
    if len(message) < 38:
        return
    session_length = message[34]
    offset = 35 + session_length
    if offset + 2 > len(message):
        return
    offset += 2  # cipher suite
    if offset >= len(message):
        return
    offset += 1  # compression method
    if offset + 2 > len(message):
        flow.negotiated_version = struct.unpack("!H", message[0:2])[0]
        return
    extensions_length = struct.unpack("!H", message[offset : offset + 2])[0]
    offset += 2
    end = min(offset + extensions_length, len(message))
    legacy_version = struct.unpack("!H", message[0:2])[0]
    flow.negotiated_version = legacy_version
    while offset + 4 <= end:
        extension_type, extension_length = struct.unpack(
            "!HH", message[offset : offset + 4]
        )
        data = message[offset + 4 : offset + 4 + extension_length]
        offset += 4 + extension_length
        if extension_type == 43 and len(data) >= 2:
            flow.negotiated_version = struct.unpack("!H", data[:2])[0]


def _is_expected_probe(
    key: tuple[str, int, str, int],
    flow: TlsFlow,
    endpoints: frozenset[tuple[str, int]],
    marker: bytes,
) -> bool:
    """Say whether a flow's non-TLS bytes are the deliberate plaintext probe."""
    if not marker or not endpoints or not flow.malformed_prefix:
        return False
    if (key[2], key[3]) not in endpoints:
        return False
    # The probe may be split across segments, so accept a leading fragment of
    # the marker rather than requiring the whole thing in one record.
    return marker.startswith(flow.malformed_prefix)


def analyse_capture(
    path: Path,
    *,
    expected_ports: Sequence[int],
    expected_probe_endpoints: Sequence[tuple[str, int]] = (),
    probe_marker: bytes = b"",
) -> dict[str, Any]:
    """Summarise a capture, restricted to the expected TCP ports.

    ``expected_probe_endpoints`` names the ``(host, port)`` listeners the run
    deliberately probed with ``probe_marker``. Non-TLS bytes on those flows
    that are a leading fragment of the marker are reported as
    ``expected_probe_bytes``; everything else counts as an unexplained
    plaintext violation.
    """
    wanted = set(int(port) for port in expected_ports)
    endpoints = frozenset(
        (str(host), int(port)) for host, port in expected_probe_endpoints
    )
    flows: dict[tuple[str, int, str, int], TlsFlow] = {}
    packet_count = 0
    for packet in _iter_packets(Path(path)):
        parsed = _parse_tcp(packet)
        if parsed is None:
            continue
        (
            source,
            source_port,
            destination,
            destination_port,
            sequence,
            flags,
            payload,
        ) = parsed
        if source_port not in wanted and destination_port not in wanted:
            continue
        packet_count += 1
        key = (source, source_port, destination, destination_port)
        flow = flows.get(key)
        if flow is None:
            flow = TlsFlow(key=key)
            flows[key] = flow
        flow.packets += 1
        flow.bytes_total += len(payload)
        if not payload:
            _feed_segment(flow, sequence, flags, b"")
            continue
        flow.payload_bytes += len(payload)
        _feed_segment(flow, sequence, flags, payload)

    # A hole that never got filled leaves bytes we never looked at; a capture
    # that cannot be reassembled cannot certify the stream either.
    for flow in flows.values():
        flow.unreassembled_bytes += sum(
            len(part) for part in flow._pending.values()
        )
        flow._pending.clear()

    flow_documents = [flow.to_dict() for flow in flows.values()]
    sessions = _session_summary(flows)
    tls13 = sessions["tls13_sessions"]
    tls12_only = sessions["tls12_or_lower_sessions"]
    malformed = sum(flow.malformed_bytes for flow in flows.values())
    expected_probe_bytes = sum(
        flow.malformed_bytes
        for key, flow in flows.items()
        if _is_expected_probe(key, flow, endpoints, probe_marker)
    )
    unexplained = malformed - expected_probe_bytes
    application_records = sum(
        flow.record_types.get("application_data", 0) for flow in flows.values()
    )
    retransmitted = sum(flow.retransmitted_packets for flow in flows.values())
    retransmitted_bytes = sum(flow.retransmitted_bytes for flow in flows.values())
    out_of_order = sum(flow.out_of_order_packets for flow in flows.values())
    gap_packets = sum(flow.gap_packets for flow in flows.values())
    unreassembled = sum(flow.unreassembled_bytes for flow in flows.values())
    handshakes = sum(
        sum(flow.handshake_types.values()) for flow in flows.values()
    )
    summary = {
        "capture": Path(path).name,
        "expected_ports": sorted(wanted),
        "packets_on_expected_ports": packet_count,
        "flows": flow_documents,
        "tls13_flows": tls13,
        "tls12_or_lower_flows": tls12_only,
        "handshake_messages": handshakes,
        "application_data_records": application_records,
        "non_tls_payload_bytes": unexplained,
        "expected_probe_bytes": expected_probe_bytes,
        "retransmitted_packets": retransmitted,
        "retransmitted_bytes": retransmitted_bytes,
        "out_of_order_packets": out_of_order,
        "gap_packets": gap_packets,
        "unreassembled_bytes": unreassembled,
        "probe_marker": probe_marker.hex() if probe_marker else None,
        "probe_endpoints": sorted(f"{host}:{port}" for host, port in endpoints),
        "sessions": sessions,
        "capture_complete": unreassembled == 0,
        "tls_only": bool(flows) and unexplained == 0 and unreassembled == 0,
        "ciphertext_only": bool(flows) and unexplained == 0 and unreassembled == 0,
    }
    summary["verdict"] = (
        "tls13_only"
        if summary["tls_only"] and tls13 > 0 and tls12_only == 0
        else "tls_or_plaintext_violation"
    )
    return summary


def _session_summary(flows: dict[tuple[str, int, str, int], TlsFlow]) -> dict[str, Any]:
    """Group the two flow directions of a connection into one TLS session."""
    seen: set[tuple[tuple[str, int, str, int], ...]] = set()
    documents: list[dict[str, Any]] = []
    tls13 = 0
    lower = 0
    for key, flow in flows.items():
        reverse = (key[2], key[3], key[0], key[1])
        pair = tuple(sorted((key, reverse)))
        if pair in seen:
            continue
        seen.add(pair)
        other = flows.get(reverse)
        offered = sorted(set(flow.offered_versions) | set(
            other.offered_versions if other else []
        ))
        negotiated = [
            candidate.negotiated_version
            for candidate in (flow, other)
            if candidate is not None and candidate.negotiated_version is not None
        ]
        handshakes = sorted(
            set(flow.handshake_types) | set(other.handshake_types if other else [])
        )
        if TLS13_VERSION in negotiated:
            verdict = "tls13"
            tls13 += 1
        elif offered and TLS13_VERSION not in offered:
            verdict = "tls12_or_lower"
            lower += 1
        else:
            verdict = "unclassified"
        documents.append(
            {
                "endpoints": [list(pair[0]), list(pair[1])],
                "offered_versions": [f"0x{value:04x}" for value in offered],
                "negotiated_versions": [
                    f"0x{value:04x}" for value in negotiated
                ],
                "handshake_types": handshakes,
                "verdict": verdict,
            }
        )
    return {
        "count": len(documents),
        "tls13_sessions": tls13,
        "tls12_or_lower_sessions": lower,
        "sessions": documents,
    }


def render_summary(summary: dict[str, Any]) -> str:
    """Render the capture summary as the evidence text file."""
    lines = [
        "# A1-22 D4 TLS capture summary",
        f"capture: {summary['capture']}",
        f"expected ports: {summary['expected_ports']}",
        f"packets on expected ports: {summary['packets_on_expected_ports']}",
        f"TLS 1.3 flows: {summary['tls13_flows']}",
        f"TLS 1.2-or-lower flows: {summary['tls12_or_lower_flows']}",
        f"handshake messages: {summary['handshake_messages']}",
        f"application-data records: {summary['application_data_records']}",
        f"non-TLS payload bytes: {summary['non_tls_payload_bytes']}",
        f"TCP retransmissions: {summary.get('retransmitted_packets', 0)} "
        f"({summary.get('retransmitted_bytes', 0)} bytes, deduplicated)",
        f"capture gaps: {summary.get('gap_packets', 0)} "
        f"(unreassembled bytes: {summary.get('unreassembled_bytes', 0)})",
        f"verdict: {summary['verdict']}",
        "",
        "# deliberate plaintext probes",
        f"probe endpoints: {summary.get('probe_endpoints') or []}",
        f"probe marker: {summary.get('probe_marker')}",
        f"expected probe bytes: {summary.get('expected_probe_bytes', 0)}",
        "those bytes are the refused probe itself and are not a protocol leak",
        "",
        "# flows",
    ]
    for flow in summary["flows"]:
        endpoint = flow["flow"]
        lines.append(
            f"{endpoint['src']}:{endpoint['sport']} -> "
            f"{endpoint['dst']}:{endpoint['dport']} "
            f"packets={flow['packets']} bytes={flow['bytes']} "
            f"records={flow['record_types']} "
            f"handshakes={flow['handshake_types']} "
            f"offered={flow['offered_versions']} "
            f"negotiated={flow['negotiated_version']} "
            f"alerts={flow['alerts']} "
            f"non_tls={flow['malformed_bytes']} "
            f"retransmits={flow.get('retransmitted_packets', 0)} "
            f"non_tls_prefix={flow['malformed_prefix']}"
        )
    lines.append("")
    lines.append("# sessions")
    for session in summary["sessions"]["sessions"]:
        lines.append(
            f"{session['endpoints'][0]} <-> {session['endpoints'][1]} "
            f"offered={session['offered_versions']} "
            f"negotiated={session['negotiated_versions']} "
            f"handshakes={session['handshake_types']} "
            f"verdict={session['verdict']}"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Render one capture's summary, so a host can describe its own traffic."""
    parser = argparse.ArgumentParser(
        description="Summarise the TLS traffic in a D4 capture"
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        default=[],
        help="a port the run used; repeat for each one",
    )
    parser.add_argument(
        "--d4-ports",
        action="store_true",
        help="use the six default D4 ports (47100-47102, 47200-47202)",
    )
    parser.add_argument(
        "--probe-endpoint",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="a listener the run deliberately probed in plaintext",
    )
    parser.add_argument("--probe-marker", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    ports = list(args.port)
    if args.d4_ports:
        ports.extend(D4_PORTS)
    if not ports:
        parser.error("give at least one --port, or pass --d4-ports")
    endpoints: list[tuple[str, int]] = []
    for item in args.probe_endpoint:
        host, _, raw_port = item.rpartition(":")
        if not host or not raw_port.isdigit():
            parser.error(f"--probe-endpoint wants HOST:PORT, got {item!r}")
        endpoints.append((host, int(raw_port)))
    try:
        document = analyse_capture(
            args.capture,
            expected_ports=ports,
            expected_probe_endpoints=endpoints,
            probe_marker=args.probe_marker.encode("utf-8"),
        )
    except (OSError, PcapError) as exc:
        print(f"capture analysis failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    print(render_summary(document), end="")
    return 0


__all__ = [
    "D4_PORTS",
    "PcapError",
    "TLS13_VERSION",
    "TlsFlow",
    "analyse_capture",
    "main",
    "render_summary",
]


if __name__ == "__main__":
    raise SystemExit(main())

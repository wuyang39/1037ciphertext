from __future__ import annotations

import hashlib
from pathlib import Path

from infra.d3_encfs_evidence import parse_probe
from infra.d3_host_scan import scan_roots


def test_parse_probe_reads_counts_and_prefix_hash() -> None:
    text = "\n".join(
        [
            "A1_22_ENCFS_BEGIN",
            "key_name=a122_disk",
            "key_installed=1",
            "key_status=0",
            "read_ok=1",
            "content_len=46080",
            "content_prefix_len=4",
            "content_hex=deadbeef",
            "A1_22_ENCFS_END",
            "",
        ]
    )

    fields = parse_probe(text)

    assert fields["key_installed"] == 1
    assert fields["read_ok"] == 1
    assert fields["content_len"] == 46080
    assert fields["content_prefix_bytes"] == 4
    assert fields["content_prefix_sha256"] == hashlib.sha256(
        bytes.fromhex("deadbeef")
    ).hexdigest()
    assert fields["marker_complete"] is True


def test_parse_probe_handles_a_refusal_without_a_prefix() -> None:
    fields = parse_probe(
        "A1_22_ENCFS_BEGIN\nkey_installed=0\nread_ok=0\nread_errno=13\n"
        "A1_22_ENCFS_END\n"
    )

    assert fields["read_ok"] == 0
    assert fields["read_errno"] == 13
    assert "content_prefix_sha256" not in fields
    assert fields["marker_complete"] is True


def test_host_scan_reports_the_file_that_contains_the_share(tmp_path: Path) -> None:
    needle = bytes(range(256)) * 4
    (tmp_path / "store.bin").write_bytes(b"\x00" * 64)
    (tmp_path / "leak.bin").write_bytes(b"prefix" + needle + b"suffix")

    hits = scan_roots({"full_share": needle}, [tmp_path])

    assert [hit["needle"] for hit in hits] == ["full_share"]
    assert str(hits[0]["path"]).endswith("leak.bin")


def test_host_scan_honours_skip_paths(tmp_path: Path) -> None:
    needle = b"a122" * 16
    leak = tmp_path / "needle.bin"
    leak.write_bytes(needle)

    assert scan_roots({"full_share": needle}, [tmp_path], skip={leak}) == []

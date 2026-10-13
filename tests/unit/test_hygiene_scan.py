"""The post-close search has to fail on a leak and pass on a clean instance."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from infra.hygiene_scan import (
    main,
    scan,
    scan_files,
    scan_journal,
    scan_processes,
)


PROBE = "Q2FycnlUaGlzUHJvYmVEb2VzTm90TWF0dGVy"


def _needles() -> dict[str, bytes]:
    return {"probe[0]": PROBE.encode("utf-8")}


def test_a_file_that_carries_a_probe_is_a_hit(tmp_path: Path) -> None:
    (tmp_path / "spill").mkdir()
    (tmp_path / "spill" / "step-0001.share").write_text(
        f'{{"meta":"x","chunks":["{PROBE}"]}}', encoding="utf-8"
    )
    hits, present = scan_files(_needles(), [tmp_path])
    assert [hit["path"] for hit in hits] == [
        str(tmp_path / "spill" / "step-0001.share")
    ]
    assert present == [str(tmp_path)]


def test_a_skipped_evidence_file_is_not_a_hit(tmp_path: Path) -> None:
    result = tmp_path / "client-result.json"
    result.write_text(json.dumps({"share_probes": [PROBE]}), encoding="utf-8")
    hits, _present = scan_files(_needles(), [tmp_path], skip=[result])
    assert hits == []
    report = scan(
        probes=[PROBE],
        roots=[tmp_path],
        skip=[result],
        with_journal=False,
        with_processes=False,
    )
    assert report["verdict"] == "clean"
    assert report["findings"] == []


def test_a_process_command_line_is_part_of_the_search(
    tmp_path: Path,
) -> None:
    proc = tmp_path / "proc"
    (proc / "4321").mkdir(parents=True)
    (proc / "4321" / "cmdline").write_bytes(b"python\0--probe\0" + PROBE.encode())
    (proc / "4321" / "environ").write_bytes(b"HOME=/root")
    (proc / "self").mkdir()
    (proc / "self" / "cmdline").write_bytes(b"scan")
    hits = scan_processes(_needles(), proc=proc)
    assert [hit["path"] for hit in hits] == [str(proc / "4321" / "cmdline")]


def test_a_probe_in_the_journal_is_a_hit() -> None:
    def runner(command, **kwargs):  # noqa: ANN001, ANN003 - matches subprocess.run
        return SimpleNamespace(
            returncode=0,
            stdout=f"Oct 13 host node: {PROBE}\n".encode(),
            stderr=b"",
        )

    available = scan_journal(_needles(), since="@1", runner=runner)
    assert available["available"] is True
    assert [hit["probe"] for hit in available["hits"]] == ["probe[0]"]


def test_a_missing_journal_is_reported_not_faked() -> None:
    def runner(command, **kwargs):  # noqa: ANN001, ANN003 - matches subprocess.run
        raise FileNotFoundError("journalctl")

    report = scan_journal(_needles(), runner=runner)
    assert report["available"] is False
    assert "FileNotFoundError" in report["reason"]


def test_cleanup_is_checked_from_the_filesystem(tmp_path: Path) -> None:
    session = tmp_path / "run" / "P0"
    session.mkdir(parents=True)
    (session / "step-0001.share").write_text(PROBE, encoding="utf-8")
    dirty = scan(
        probes=[PROBE],
        roots=[tmp_path],
        expect_absent=[session],
        expect_empty=[tmp_path / "run"],
        with_journal=False,
        with_processes=False,
    )
    assert dirty["verdict"] == "session-state-found"
    assert dirty["still_present"] == [str(session)]
    assert dirty["not_empty"] == [
        {"path": str(tmp_path / "run"), "entries": ["P0"]}
    ]
    (session / "step-0001.share").unlink()
    session.rmdir()
    clean = scan(
        probes=[PROBE],
        roots=[tmp_path],
        expect_absent=[session],
        expect_empty=[tmp_path / "run"],
        with_journal=False,
        with_processes=False,
    )
    assert clean["verdict"] == "clean"
    assert clean["roots_that_exist"] == [str(tmp_path)]


def test_the_command_line_exits_non_zero_on_a_finding(tmp_path: Path) -> None:
    probes = tmp_path / "probes.json"
    probes.write_text(json.dumps({"probes": [PROBE]}), encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    output = tmp_path / "report.json"
    clean_status = main(
        [
            "--probes-file",
            str(probes),
            "--root",
            str(root),
            "--no-journal",
            "--output",
            str(output),
        ]
    )
    assert clean_status == 0
    assert json.loads(output.read_text(encoding="utf-8"))["verdict"] == "clean"
    (root / "leak.bin").write_text(f"prefix {PROBE} suffix", encoding="utf-8")
    dirty_status = main(
        [
            "--probes-file",
            str(probes),
            "--root",
            str(root),
            "--no-journal",
            "--output",
            str(output),
        ]
    )
    assert dirty_status == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["findings"][0]["path"] == str(root / "leak.bin")
    assert report["findings"][0]["probe"] == "probe[0]"

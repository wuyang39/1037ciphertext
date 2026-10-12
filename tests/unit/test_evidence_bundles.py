from __future__ import annotations

from pathlib import Path

import pytest

from infra.evidence import (
    EvidenceError,
    exclusions_path,
    load_exclusions,
    seal_directory,
    verify_directory,
    write_exclusions,
    write_json,
)


EVIDENCE_ROOT = Path(__file__).resolve().parents[2] / "docs" / "evidence"


def _small_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "run"
    bundle.mkdir()
    (bundle / "summary.json").write_text("{}\n", encoding="utf-8")
    return bundle


def _bundles() -> list[Path]:
    if not EVIDENCE_ROOT.is_dir():
        return []
    return sorted(path for path in EVIDENCE_ROOT.iterdir() if path.is_dir())


def test_committed_evidence_bundles_verify() -> None:
    bundles = _bundles()
    if not bundles:
        pytest.skip("no committed evidence bundles yet")
    for bundle in bundles:
        exclusions = load_exclusions(bundle)
        index = verify_directory(bundle, exclusions=exclusions)
        assert index["file_count"] > 0
        # The only files a bundle may leave out are the ones it names, and it
        # must name exactly the ones that are really gone.
        assert index["excluded"] == sorted(
            entry["path"]
            for entry in exclusions
            if not (bundle / str(entry["path"])).is_file()
        )


def test_seal_directory_records_artifacts_that_stay_on_the_instance(
    tmp_path: Path,
) -> None:
    """A cross-host bundle names its captures without shipping them."""
    bundle = _small_bundle(tmp_path)
    (bundle / "summary.json").write_text('{"ok": true}\n', encoding="utf-8")
    external = [
        {
            "path": "d4-three-P0.pcap",
            "bytes": 144791448,
            "sha256": "a" * 64,
            "reason": "too large to commit",
        }
    ]
    index = seal_directory(bundle, external=external)
    assert [entry["path"] for entry in index["files"]] == [
        "summary.json",
        "d4-three-P0.pcap",
    ]
    assert index["files"][-1]["external"] is True
    assert verify_directory(bundle, exclusions=external)["excluded"] == [
        "d4-three-P0.pcap"
    ]
    write_exclusions(bundle, external, run_id="d4-3host-test")
    assert load_exclusions(bundle) == external
    # A digest that disagrees with the index is refused, so an exclusion can
    # never excuse a substituted capture.
    with pytest.raises(EvidenceError, match="disagrees with the index"):
        verify_directory(
            bundle,
            exclusions=[
                {"path": "d4-three-P0.pcap", "bytes": 144791448, "sha256": "b" * 64}
            ],
        )


def test_seal_directory_rejects_a_malformed_external_artifact(tmp_path: Path) -> None:
    bundle = _small_bundle(tmp_path)
    (bundle / "summary.json").write_text("{}\n", encoding="utf-8")
    for entry in (
        {"path": "../escape.pcap", "bytes": 1, "sha256": "a" * 64},
        {"path": "summary.json", "bytes": 1, "sha256": "a" * 64},
        {"path": "capture.pcap", "bytes": 1, "sha256": "not-a-digest"},
        {"path": "capture.pcap", "sha256": "a" * 64},
    ):
        with pytest.raises(EvidenceError):
            seal_directory(bundle, external=[entry])


def test_verify_directory_honours_an_exclusion_list(tmp_path: Path) -> None:
    bundle = _small_bundle(tmp_path)
    (bundle / "raw.pcap").write_bytes(b"capture" * 4)
    index = seal_directory(bundle)
    capture = next(entry for entry in index["files"] if entry["path"] == "raw.pcap")
    (bundle / "raw.pcap").unlink()

    with pytest.raises(EvidenceError, match="evidence file is missing"):
        verify_directory(bundle)

    exclusions = [
        {
            "path": "raw.pcap",
            "bytes": capture["bytes"],
            "sha256": capture["sha256"],
            "reason": "too large to commit",
        }
    ]
    verify_directory(bundle, exclusions=exclusions)
    write_json(exclusions_path(bundle), {"excluded": exclusions})
    assert load_exclusions(bundle) == exclusions
    assert verify_directory(
        bundle, exclusions=load_exclusions(bundle)
    )["excluded"] == ["raw.pcap"]


def test_verify_directory_rejects_a_stale_exclusion(tmp_path: Path) -> None:
    bundle = _small_bundle(tmp_path)
    (bundle / "raw.pcap").write_bytes(b"capture" * 4)
    seal_directory(bundle)
    (bundle / "raw.pcap").unlink()
    for entry, match in (
        ({"path": "raw.pcap", "sha256": "0" * 64}, "disagrees with the index"),
        ({"path": "not-indexed.pcap"}, "not indexed"),
    ):
        with pytest.raises(EvidenceError, match=match):
            verify_directory(bundle, exclusions=[entry])


def test_committed_evidence_contains_no_private_key_material() -> None:
    marker = b"PRIVATE KEY-----"
    for bundle in _bundles():
        for path in bundle.rglob("*"):
            if path.is_file():
                assert marker not in path.read_bytes(), path

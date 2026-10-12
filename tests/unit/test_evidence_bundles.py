from __future__ import annotations

from pathlib import Path

import pytest

from infra.evidence import verify_directory


EVIDENCE_ROOT = Path(__file__).resolve().parents[2] / "docs" / "evidence"


def _bundles() -> list[Path]:
    if not EVIDENCE_ROOT.is_dir():
        return []
    return sorted(path for path in EVIDENCE_ROOT.iterdir() if path.is_dir())


def test_committed_evidence_bundles_verify() -> None:
    bundles = _bundles()
    if not bundles:
        pytest.skip("no committed evidence bundles yet")
    for bundle in bundles:
        index = verify_directory(bundle)
        assert index["file_count"] > 0


def test_committed_evidence_contains_no_private_key_material() -> None:
    marker = b"PRIVATE KEY-----"
    for bundle in _bundles():
        for path in bundle.rglob("*"):
            if path.is_file():
                assert marker not in path.read_bytes(), path

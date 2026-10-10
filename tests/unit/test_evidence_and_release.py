from __future__ import annotations

import json
from pathlib import Path

import pytest

from infra.build_release import build
from infra.evidence import (
    EvidenceError,
    build_record,
    seal_directory,
    verify_directory,
    write_json,
)
from infra.validate_release import ReleaseValidationError, validate_archive


def test_evidence_directory_is_sealed_and_tamper_evident(tmp_path: Path) -> None:
    write_json(tmp_path / "result.json", {"ok": True})
    index = seal_directory(tmp_path)
    assert index["file_count"] == 1
    assert verify_directory(tmp_path)["file_count"] == 1
    (tmp_path / "result.json").write_text('{"ok": false}\n', encoding="utf-8")
    with pytest.raises(EvidenceError, match="mismatch"):
        verify_directory(tmp_path)


def test_evidence_record_rejects_sensitive_material(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="private"):
        build_record(
            run_id="test",
            phase="test",
            outcome="failed",
            command="test",
            stdout=b"-----BEGIN " + b"PRIVATE KEY-----",
        )


def test_release_archive_manifest_is_verified(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("release\n", encoding="utf-8")
    archive = tmp_path / "release.zip"
    manifest = build(source, archive, "test-release")
    result = validate_archive(archive, external_manifest_path=archive.with_suffix(".manifest.json"))
    assert result["valid"] is True
    assert result["file_count"] == manifest["file_count"]

    import zipfile

    with zipfile.ZipFile(archive, "a") as handle:
        handle.writestr("extra.txt", "tampered\n")
    with pytest.raises(ReleaseValidationError):
        validate_archive(archive)

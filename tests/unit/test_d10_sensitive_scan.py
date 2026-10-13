"""The release-sensitive scan must excuse reviewed source, not all source."""

from __future__ import annotations

import pytest

from infra.build_release import build
from infra.evidence import scan_sensitive_markers
from infra.validate_release import ReleaseValidationError, validate_archive


# Needles are assembled from parts so this file does not itself match.
PEM_NEEDLE = "-----BEGIN " + "PRIVATE KEY-----\n"
SESSION_NEEDLE = '{"' + "session_key" + '": "abc"}\n'
STORAGE_NEEDLE = "bundle = {" + '"' + "storage_key" + '": storage_key}\n'


def test_reviewed_source_marker_is_excused_not_hidden():
    text = STORAGE_NEEDLE
    unreviewed, reviewed = scan_sensitive_markers(text, path="crypto/enclave_key.py")
    assert unreviewed == []
    assert reviewed == ["session_key_field"]


def test_unreviewed_source_marker_still_fails():
    text = STORAGE_NEEDLE
    unreviewed, reviewed = scan_sensitive_markers(text, path="crypto/somewhere_else.py")
    assert unreviewed == ["session_key_field"]
    assert reviewed == []


def test_a_data_path_is_never_excused():
    unreviewed, reviewed = scan_sensitive_markers(SESSION_NEEDLE, path="docs/notes.json")
    assert unreviewed == ["session_key_field"]
    assert reviewed == []


def test_the_exemption_is_per_marker_not_per_file():
    # A real PEM pasted into a reviewed file is a different marker, so it fails.
    unreviewed, reviewed = scan_sensitive_markers(
        PEM_NEEDLE, path="crypto/enclave_key.py"
    )
    assert unreviewed == ["private_key"]
    assert reviewed == []


def test_a_pem_header_in_an_unreviewed_file_fails():
    unreviewed, _reviewed = scan_sensitive_markers(
        PEM_NEEDLE, path="docs/notes.md"
    )
    assert unreviewed == ["private_key"]


def test_release_scan_accepts_a_reviewed_source_hit(tmp_path):
    source = tmp_path / "source"
    (source / "crypto").mkdir(parents=True)
    (source / "crypto" / "enclave_key.py").write_text(
        STORAGE_NEEDLE, encoding="utf-8"
    )
    archive = tmp_path / "release.zip"
    build(source, archive, "test-release")
    assert validate_archive(archive, scan_sensitive=True)["valid"] is True


def test_release_scan_rejects_a_key_in_a_new_source_file(tmp_path):
    source = tmp_path / "source"
    (source / "crypto").mkdir(parents=True)
    (source / "crypto" / "leak.py").write_text(PEM_NEEDLE, encoding="utf-8")
    archive = tmp_path / "release.zip"
    build(source, archive, "test-release")
    with pytest.raises(ReleaseValidationError, match="sensitive"):
        validate_archive(archive, scan_sensitive=True)

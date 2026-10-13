"""The clean-dir rehearsal must fail on anything short of a runnable package."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from infra import d10_rehearsal
from infra.build_release import build


# Assembled from parts so this test does not itself carry a scanner needle.
FAKE_PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\n"


def _make_source(tmp_path: Path, *, sensitive: bool = False) -> Path:
    source = tmp_path / "source"
    (source / "docs").mkdir(parents=True)
    (source / "deploy").mkdir(parents=True)
    for package in d10_rehearsal.PACKAGES:
        (source / package).mkdir(parents=True)
        (source / package / "__init__.py").write_text("", encoding="utf-8")
    (source / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (source / "README.md").write_text("release\n", encoding="utf-8")
    (source / "docs" / "installation.md").write_text("install\n", encoding="utf-8")
    (source / "docs" / "reproducibility.md").write_text("reproduce\n", encoding="utf-8")
    (source / "deploy" / "run_local_checks.ps1").write_text("# ps1\n", encoding="utf-8")
    (source / "deploy" / "run_local_checks.sh").write_text("# sh\n", encoding="utf-8")
    body = "value = 1\n"
    if sensitive:
        body = FAKE_PEM
    (source / "client" / "__init__.py").write_text(body, encoding="utf-8")
    return source


def _runner(*, compile_rc: int = 0, test_rc: int = 0, summary: str = "7 passed, 1 skipped in 1.0s"):
    seen: dict = {}

    class _Runner:
        def __call__(self, command, **_kwargs):
            seen["env"] = _kwargs.get("env", {})
            seen["cwd"] = _kwargs.get("cwd")
            if "compileall" in command:
                return SimpleNamespace(returncode=compile_rc, stdout=b"", stderr=b"")
            return SimpleNamespace(
                returncode=test_rc, stdout=summary.encode("utf-8"), stderr=b""
            )

    return _Runner(), seen


def test_clean_rehearsal_reports_a_runnable_package(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path), archive, "test-release")
    runner, seen = _runner()
    report, log = d10_rehearsal.run_rehearsal(
        archive, workdir=tmp_path / "empty", runner=runner
    )
    assert report["verdict"] == "runs-without-patching"
    assert report["tests"]["passed"] == 7
    assert report["tests"]["skipped"] == 1
    assert all(report["required_files"].values())
    assert any(line.startswith("$ ") for line in log)
    # The child must run from the extracted copy, with it on the import path and
    # with the full environment kept (Windows needs SystemRoot for Winsock).
    assert seen["cwd"] == str(tmp_path / "empty")
    assert seen["env"]["PYTHONPATH"] == str(tmp_path / "empty")
    assert "PATH" in seen["env"]


def test_rehearsal_refuses_a_directory_that_is_not_empty(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path), archive, "test-release")
    destination = tmp_path / "occupied"
    destination.mkdir()
    (destination / "leftover.txt").write_text("x", encoding="utf-8")
    runner, _seen = _runner()
    with pytest.raises(d10_rehearsal.RehearsalError, match="not empty"):
        d10_rehearsal.run_rehearsal(archive, workdir=destination, runner=runner)


def test_rehearsal_reports_a_missing_install_file(tmp_path):
    source = _make_source(tmp_path)
    (source / "docs" / "installation.md").unlink()
    archive = tmp_path / "release.zip"
    build(source, archive, "test-release")
    runner, _seen = _runner()
    with pytest.raises(d10_rehearsal.RehearsalError, match="install-manual"):
        d10_rehearsal.run_rehearsal(archive, workdir=tmp_path / "empty", runner=runner)


def test_rehearsal_reports_a_compile_failure(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path), archive, "test-release")
    runner, _seen = _runner(compile_rc=1)
    report, _log = d10_rehearsal.run_rehearsal(
        archive, workdir=tmp_path / "empty", runner=runner
    )
    assert report["verdict"] == "compile-failed"


def test_rehearsal_reports_a_test_failure(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path), archive, "test-release")
    runner, _seen = _runner(test_rc=1)
    report, _log = d10_rehearsal.run_rehearsal(
        archive, workdir=tmp_path / "empty", runner=runner
    )
    assert report["verdict"] == "tests-failed"


def test_rehearsal_scans_the_archive_for_sensitive_material(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path, sensitive=True), archive, "test-release")
    runner, _seen = _runner()
    with pytest.raises(ValueError, match="sensitive"):
        d10_rehearsal.run_rehearsal(archive, workdir=tmp_path / "empty", runner=runner)


def test_main_writes_the_report_and_log(tmp_path):
    archive = tmp_path / "release.zip"
    build(_make_source(tmp_path), archive, "test-release")
    out = tmp_path / "rehearsal.json"
    log = tmp_path / "rehearsal.log"
    assert (
        d10_rehearsal.main(
            [
                "--archive", str(archive),
                "--out", str(out),
                "--log", str(log),
                "--workdir", str(tmp_path / "empty"),
                "--skip-tests",
            ]
        )
        == 0
    )
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["verdict"] == "runs-without-patching"
    assert report["compileall"]["returncode"] == 0
    assert "compileall" in log.read_text(encoding="utf-8")
    # The bundle is sealed over bytes and pinned to LF by .gitattributes.
    assert b"\r\n" not in log.read_bytes()


def test_tracked_only_packaging_skips_untracked_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "tracked.txt").write_text("keep\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    (repo / "scratch.txt").write_text("drop\n", encoding="utf-8")
    archive = tmp_path / "tracked.zip"
    manifest = build(repo, archive, "test-release", tracked_only=True)
    names = {entry["path"] for entry in manifest["files"]}
    assert names == {"tracked.txt"}

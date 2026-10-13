"""Run the D10 "clean machine" rehearsal on the release archive.

The acceptance gate is explicit: the delivered package must unpack and run per
the install manual with no hand patching. This module turns that sentence into a
measurement:

1. verify the archive against its embedded manifest, and scan it for the
   sensitive markers the release must not carry;
2. extract it into a directory that starts empty;
3. confirm the files the install manual needs are actually there;
4. byte-compile every package from the extracted copy;
5. run the test suite from the extracted copy, with the extracted copy on the
   import path and as the working directory, so nothing can quietly fall back to
   the developer's checkout.

The frozen GPT-2 weights are excluded from the archive on purpose, so the D7
model tests are expected to skip here; a skip is recorded, not hidden.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Sequence

from infra.evidence import sha256_file, write_json
from infra.validate_release import validate_archive


PACKAGES = ("benchmark", "client", "contracts", "crypto", "infra", "kas", "model", "mpc", "tee")
REQUIRED_FILES = (
    "pyproject.toml",
    "README.md",
    "docs/installation.md",
    "docs/reproducibility.md",
    "deploy/run_local_checks.ps1",
    "deploy/run_local_checks.sh",
)
SUMMARY_PATTERN = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")


class RehearsalError(ValueError):
    """The rehearsal could not be completed."""


def extract_archive(archive: Path, destination: Path) -> Path:
    """Extract into an empty directory and return it."""
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise RehearsalError(f"the rehearsal directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "r") as handle:
        handle.extractall(destination)
    return destination


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: list[str],
    runner: Callable[..., Any] | None = None,
    timeout: float = 1800,
) -> dict[str, Any]:
    runner = runner or subprocess.run
    log.append(f"$ {' '.join(command)}")
    try:
        completed = runner(
            list(command),
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.append(f"! {type(exc).__name__}: {exc}")
        return {"returncode": None, "error": f"{type(exc).__name__}: {exc}"}
    # Child output is CRLF on Windows; the bundle is sealed over bytes and
    # ``.gitattributes`` pins ``docs/evidence/**`` to LF, so normalise here.
    stdout = (completed.stdout or b"").decode("utf-8", "replace").replace("\r\n", "\n")
    stderr = (completed.stderr or b"").decode("utf-8", "replace").replace("\r\n", "\n")
    log.append(stdout.rstrip())
    if stderr.strip():
        log.append(stderr.rstrip())
    return {
        "returncode": int(completed.returncode),
        "stdout_tail": stdout.strip().splitlines()[-1] if stdout.strip() else "",
    }


def run_rehearsal(
    archive: Path,
    *,
    workdir: Path | None = None,
    python: str = sys.executable,
    runner: Callable[..., Any] | None = None,
    run_tests: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    """Extract, verify and exercise the release archive; return report and log."""
    archive = Path(archive).resolve()
    if not archive.is_file():
        raise RehearsalError(f"release archive does not exist: {archive}")
    log: list[str] = [f"archive: {archive.name}", f"sha256: {sha256_file(archive)}"]
    validated = validate_archive(archive, scan_sensitive=True)
    log.append(f"manifest: valid, {validated['file_count']} files")

    temporary = None
    if workdir is None:
        temporary = Path(tempfile.mkdtemp(prefix="a122-d10-rehearsal-"))
        workdir = temporary
    workdir = Path(workdir)
    extract_archive(archive, workdir)

    required = {name: (workdir / name).is_file() for name in REQUIRED_FILES}
    missing = sorted(name for name, present in required.items() if not present)
    if missing:
        raise RehearsalError("the archive is missing install-manual files: " + ", ".join(missing))

    # Keep the full environment: on Windows a stripped one loses SystemRoot and
    # the child cannot initialise Winsock, which reads as a package failure.
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(workdir),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    compile_result = _run(
        [python, "-m", "compileall", "-q", *PACKAGES],
        cwd=workdir,
        env=env,
        log=log,
        runner=runner,
    )
    tests: dict[str, Any] = {"ran": False}
    if run_tests:
        tests = _run(
            [python, "-m", "pytest", "tests", "-p", "no:cacheprovider", "--tb=short"],
            cwd=workdir,
            env=env,
            log=log,
            runner=runner,
        )
        tests["ran"] = True
        match = SUMMARY_PATTERN.search("\n".join(log))
        if match:
            tests["passed"] = int(match.group(1))
            tests["skipped"] = int(match.group(2) or 0)

    verdict = "runs-without-patching"
    if compile_result.get("returncode") != 0:
        verdict = "compile-failed"
    elif run_tests and tests.get("returncode") != 0:
        verdict = "tests-failed"
    report: dict[str, Any] = {
        "rehearsal": "from-empty-dir",
        "archive": {
            "name": archive.name,
            "sha256": sha256_file(archive),
            "bytes": archive.stat().st_size,
        },
        "manifest": {
            "release_version": validated.get("release_version"),
            "file_count": validated["file_count"],
            "uncompressed_bytes": validated["uncompressed_bytes"],
        },
        "required_files": required,
        "compileall": compile_result,
        "tests": tests,
        "verdict": verdict,
    }
    if temporary is not None:
        shutil.rmtree(temporary, ignore_errors=True)
    return report, log


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D10 clean-dir rehearsal")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args(argv)
    try:
        report, log = run_rehearsal(
            args.archive, workdir=args.workdir, run_tests=not args.skip_tests
        )
    except (OSError, ValueError) as exc:
        print(f"the rehearsal could not be run: {exc}", file=sys.stderr)
        return 2
    write_json(args.out, report)
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text("\n".join(log) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: report[k] for k in ("verdict", "manifest", "compileall")}, ensure_ascii=True, sort_keys=True))
    return 0 if report["verdict"] == "runs-without-patching" else 1


__all__ = [
    "PACKAGES",
    "REQUIRED_FILES",
    "RehearsalError",
    "extract_archive",
    "main",
    "run_rehearsal",
]


if __name__ == "__main__":
    raise SystemExit(main())

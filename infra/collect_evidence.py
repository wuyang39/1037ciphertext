"""Collect redacted local evidence without reading protected plaintext."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from infra.evidence import build_record, write_json


FORBIDDEN_PATTERNS = {
    "private_key": "BEGIN PRIVATE KEY",
    "encrypted_private_key": "BEGIN ENCRYPTED PRIVATE KEY",
    "debug_enclave": "sgx.debug = true",
    "production_reveal": "reveal(",
}
EXCLUDED_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    "artifacts",
}
SELF_EXCLUDES = {
    "infra/collect_evidence.py",
    "infra/security_negative.py",
}
SCANNED_SUFFIXES = {
    ".py",
    ".ps1",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".template",
}


def _git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return completed.stdout.strip()


def _iter_files(root: Path) -> Iterable[Path]:
    for current, directories, files in os.walk(root):
        directories[:] = [
            name
            for name in directories
            if name not in EXCLUDED_NAMES and not name.endswith(".egg-info")
        ]
        current_path = Path(current)
        for filename in files:
            yield current_path / filename


def _scan_patterns(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in _iter_files(root):
        relative = str(path.relative_to(root)).replace("\\", "/")
        if relative in SELF_EXCLUDES or path.suffix not in SCANNED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, pattern in FORBIDDEN_PATTERNS.items():
            if name == "production_reveal" and (
                path.suffix != ".py" or relative.startswith("tests/")
            ):
                continue
            if pattern in text:
                findings.append(
                    {
                        "pattern": name,
                        "path": relative,
                    }
                )
    return sorted(findings, key=lambda item: (item["path"], item["pattern"]))


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(root: Path) -> dict[str, object]:
    root = Path(root).resolve()
    key_paths = [
        root / "pyproject.toml",
        root / "requirements.lock",
        root / "README.md",
        root / "docs" / "protocol-baseline.md",
        root / "tee" / "gramine" / "a122.manifest.template",
    ]
    hashes = {
        str(path.relative_to(root)).replace("\\", "/"): _hash_file(path)
        for path in key_paths
        if path.is_file()
    }
    return {
        "evidence_version": "a122-local-evidence-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "git_commit": _git_commit(root),
        "root": str(root),
        "key_file_hashes": hashes,
        "forbidden_pattern_findings": _scan_patterns(root),
        "claim_boundary": {
            "local_mock_only": True,
            "sgx_acceptance": False,
            "three_node_acceptance": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="return non-zero if a forbidden plaintext marker is found",
    )
    args = parser.parse_args()
    document = collect(args.root)
    record = build_record(
        run_id="local-evidence-collection",
        phase="D0-D10",
        outcome=(
            "failed_sensitive_markers"
            if document["forbidden_pattern_findings"]
            else "passed_redacted_local_scan"
        ),
        command="python infra/collect_evidence.py",
        details=document,
    )
    write_json(args.output, record)
    if args.fail_on_findings and document["forbidden_pattern_findings"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

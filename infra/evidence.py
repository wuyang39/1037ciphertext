"""Canonical evidence helpers for local and server-side verification runs."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping


EVIDENCE_VERSION = "a122-evidence-v1"
INDEX_NAME = "evidence-index.json"
SEAL_NAME = "evidence.sha256"
SENSITIVE_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----"),
    "session_key_field": re.compile(r'"(?:session_key|storage_key|disk_key)"\s*:'),
    "raw_ticket_signature": re.compile(r'"ticket_signature"\s*:\s*"[0-9a-f]{64,}"'),
}


class EvidenceError(ValueError):
    """Evidence is malformed, missing, or fails an integrity check."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    """Atomically write deterministic JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def build_record(
    *,
    run_id: str,
    phase: str,
    outcome: str,
    command: str,
    instance_id: str = "local",
    cloud_region: str = "local",
    image_id: str = "local",
    release_id: str = "local-checkpoint",
    stdout: bytes = b"",
    stderr: bytes = b"",
    audit_event_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one redacted evidence record with deterministic hashes."""
    if not run_id or not phase or not command:
        raise EvidenceError("run_id, phase, and command are required")
    for stream in (stdout, stderr):
        try:
            assert_no_sensitive_text(stream.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    record = {
        "evidence_version": EVIDENCE_VERSION,
        "run_id": run_id,
        "phase": phase,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "cloud_region": cloud_region,
        "instance_id": instance_id,
        "image_id": image_id,
        "release_id": release_id,
        "command": command,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "outcome": outcome,
        "audit_event_id": audit_event_id,
        "details": dict(details or {}),
    }
    assert_redacted(record)
    return record


def assert_no_sensitive_text(text: str) -> None:
    findings = [
        name for name, pattern in SENSITIVE_PATTERNS.items() if pattern.search(text)
    ]
    if findings:
        raise EvidenceError(
            "evidence contains forbidden sensitive markers: " + ", ".join(findings)
        )


def assert_redacted(value: Any) -> None:
    if isinstance(value, str):
        assert_no_sensitive_text(value)
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            assert_redacted(str(key))
            assert_redacted(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            assert_redacted(child)


def iter_evidence_files(root: Path) -> Iterable[Path]:
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {INDEX_NAME, SEAL_NAME}:
            continue
        yield path


def seal_directory(root: Path) -> dict[str, Any]:
    """Create an evidence index and a detached SHA-256 seal."""
    root = Path(root)
    if not root.is_dir():
        raise EvidenceError(f"evidence directory does not exist: {root}")
    entries = []
    for path in iter_evidence_files(root):
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    index = {
        "evidence_version": EVIDENCE_VERSION,
        "root": root.name,
        "file_count": len(entries),
        "files": entries,
    }
    write_json(root / INDEX_NAME, index)
    index_hash = sha256_file(root / INDEX_NAME)
    (root / SEAL_NAME).write_text(f"{index_hash}  {INDEX_NAME}\n", encoding="ascii")
    return index


def verify_directory(root: Path, *, require_seal: bool = True) -> dict[str, Any]:
    """Verify every indexed file and, by default, the detached seal."""
    root = Path(root)
    index_path = root / INDEX_NAME
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence index is missing or invalid") from exc
    if index.get("evidence_version") != EVIDENCE_VERSION:
        raise EvidenceError("evidence index version mismatch")
    files = index.get("files")
    if not isinstance(files, list):
        raise EvidenceError("evidence index files field is invalid")
    expected_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, Mapping):
            raise EvidenceError("evidence index entry is invalid")
        relative = str(entry.get("path", ""))
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise EvidenceError("evidence index contains an unsafe path")
        path = root / relative
        if not path.is_file():
            raise EvidenceError(f"evidence file is missing: {relative}")
        if path.stat().st_size != int(entry.get("bytes", -1)):
            raise EvidenceError(f"evidence size mismatch: {relative}")
        if sha256_file(path) != entry.get("sha256"):
            raise EvidenceError(f"evidence hash mismatch: {relative}")
        expected_paths.add(relative)
    actual_paths = {
        path.relative_to(root).as_posix() for path in iter_evidence_files(root)
    }
    if actual_paths != expected_paths:
        raise EvidenceError("evidence directory contains unindexed or removed files")
    if int(index.get("file_count", -1)) != len(files):
        raise EvidenceError("evidence file count mismatch")
    if require_seal:
        seal_path = root / SEAL_NAME
        try:
            seal = seal_path.read_text(encoding="ascii").strip().split()
        except OSError as exc:
            raise EvidenceError("evidence seal is missing") from exc
        if len(seal) != 2 or seal[1] != INDEX_NAME:
            raise EvidenceError("evidence seal format is invalid")
        if seal[0] != sha256_file(index_path):
            raise EvidenceError("evidence seal does not match the index")
    return index


__all__ = [
    "EVIDENCE_VERSION",
    "INDEX_NAME",
    "SEAL_NAME",
    "EvidenceError",
    "assert_no_sensitive_text",
    "assert_redacted",
    "build_record",
    "iter_evidence_files",
    "seal_directory",
    "sha256_bytes",
    "sha256_file",
    "verify_directory",
    "write_json",
]

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
EXCLUSIONS_SUFFIX = ".exclusions.json"
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


def seal_directory(
    root: Path,
    *,
    external: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Create an evidence index and a detached SHA-256 seal.

    ``external`` names artifacts the run produced that stay outside the
    repository on purpose, such as the raw capture of a three-instance run that
    would blow past the host file limit. They are recorded in the index so the
    bundle's exclusions file can name them, and an absent one is only excused
    when its digest and size still agree with the index. A small bundle passes
    nothing here and keeps the default layout.
    """
    root = Path(root)
    if not root.is_dir():
        raise EvidenceError(f"evidence directory does not exist: {root}")
    entries: list[dict[str, Any]] = []
    for path in iter_evidence_files(root):
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    bundled = {entry["path"] for entry in entries}
    for record in external:
        relative = str(record.get("path", ""))
        if (
            not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise EvidenceError(f"external artifact has an unsafe path: {relative!r}")
        if relative in bundled:
            raise EvidenceError(
                f"external artifact collides with a bundled file: {relative}"
            )
        digest = str(record.get("sha256", ""))
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise EvidenceError(
                f"external artifact has a malformed sha256: {relative}"
            )
        try:
            size = int(record["bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(
                f"external artifact has no usable size: {relative}"
            ) from exc
        entries.append(
            {
                "path": relative,
                "bytes": size,
                "sha256": digest,
                "external": True,
            }
        )
        bundled.add(relative)
    index = {
        "evidence_version": EVIDENCE_VERSION,
        "root": root.name,
        "file_count": len(entries),
        "files": entries,
    }
    write_json(root / INDEX_NAME, index)
    index_hash = sha256_file(root / INDEX_NAME)
    (root / SEAL_NAME).write_text(
        f"{index_hash}  {INDEX_NAME}\n", encoding="ascii", newline="\n"
    )
    return index


def exclusions_path(root: Path) -> Path:
    """Where a bundle records the artifacts it deliberately leaves out."""
    root = Path(root)
    return root.with_name(root.name + EXCLUSIONS_SUFFIX)


DEFAULT_EXCLUSION_NOTE = (
    "Raw artifacts too large to commit are named here. Every excluded file "
    "still has to match the sealed index if it is present, so restoring the "
    "original capture tightens the check instead of bypassing it."
)


def write_exclusions(
    root: Path,
    entries: Iterable[Mapping[str, Any]],
    *,
    run_id: str | None = None,
    note: str | None = None,
) -> Path:
    """Record the artifacts a bundle deliberately leaves out of the repository."""
    root = Path(root)
    document = {
        "evidence_version": EVIDENCE_VERSION,
        "run_id": run_id or root.name,
        "note": note or DEFAULT_EXCLUSION_NOTE,
        "excluded": [dict(entry) for entry in entries],
    }
    path = exclusions_path(root)
    write_json(path, document)
    return path


def load_exclusions(root: Path) -> list[dict[str, Any]]:
    """Read the exclusion list for a bundle, or return an empty one.

    A bundle whose raw artifacts are too large to commit (a pcap, a disk
    image) names them in ``<bundle>.exclusions.json`` next to the directory.
    The list stays next to the bundle rather than inside it so the sealed
    directory is still exactly the set of files the index describes.
    """
    path = exclusions_path(Path(root))
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"evidence exclusions are invalid: {path}") from exc
    entries = document.get("excluded")
    if not isinstance(entries, list):
        raise EvidenceError(f"evidence exclusions lack an 'excluded' list: {path}")
    for entry in entries:
        if not isinstance(entry, Mapping) or not str(entry.get("path", "")):
            raise EvidenceError(f"evidence exclusion entry is invalid: {path}")
    return entries


def verify_directory(
    root: Path,
    *,
    require_seal: bool = True,
    exclusions: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify every indexed file and, by default, the detached seal.

    ``exclusions`` names indexed artifacts the caller expects to be absent
    (see :func:`load_exclusions`). An excluded file that is present is still
    verified, so restoring a raw capture only ever tightens the check.
    """
    root = Path(root)
    excluded = {
        str(entry["path"]): entry for entry in (exclusions or [])
    }
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
    # Validate the exclusion list before trusting it to excuse a missing file.
    indexed_by_path = {str(entry.get("path")): entry for entry in files
                       if isinstance(entry, Mapping)}
    unknown = set(excluded) - set(indexed_by_path)
    if unknown:
        raise EvidenceError(
            "evidence exclusions name files that are not indexed: "
            + ", ".join(sorted(unknown))
        )
    for relative, entry in excluded.items():
        for field in ("bytes", "sha256"):
            if field in entry and entry[field] != indexed_by_path[relative].get(field):
                raise EvidenceError(
                    f"evidence exclusion disagrees with the index on {field}: {relative}"
                )
    expected_paths: set[str] = set()
    skipped: set[str] = set()
    for entry in files:
        if not isinstance(entry, Mapping):
            raise EvidenceError("evidence index entry is invalid")
        relative = str(entry.get("path", ""))
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise EvidenceError("evidence index contains an unsafe path")
        path = root / relative
        if not path.is_file():
            if relative in excluded:
                skipped.add(relative)
                continue
            raise EvidenceError(f"evidence file is missing: {relative}")
        if path.stat().st_size != int(entry.get("bytes", -1)):
            raise EvidenceError(f"evidence size mismatch: {relative}")
        if sha256_file(path) != entry.get("sha256"):
            raise EvidenceError(f"evidence hash mismatch: {relative}")
        expected_paths.add(relative)
    expected_paths -= skipped
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
    return {**index, "excluded": sorted(skipped)}


__all__ = [
    "EVIDENCE_VERSION",
    "EXCLUSIONS_SUFFIX",
    "INDEX_NAME",
    "SEAL_NAME",
    "EvidenceError",
    "assert_no_sensitive_text",
    "assert_redacted",
    "build_record",
    "exclusions_path",
    "iter_evidence_files",
    "load_exclusions",
    "seal_directory",
    "sha256_bytes",
    "sha256_file",
    "verify_directory",
    "write_exclusions",
    "write_json",
]

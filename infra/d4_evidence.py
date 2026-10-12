"""Assemble and seal the D4 acceptance evidence directory.

The layout follows the plan:

    artifacts/server/<run-id>/d4/
    ├── p0-cert.pem, p1-cert.pem, p2-cert.pem
    ├── tls-pcap.pcap, tls-summary.txt
    ├── rss-vectors.json, communication-trace.json
    ├── deny-plaintext.txt, deny-wrong-ca.txt, deny-wrong-san.txt,
    │   deny-no-client-cert.txt, deny-tls-disabled.txt
    └── material-ledger.json

Only public material lands here: node certificates, byte counts, verdicts, and
refusal text. Shares, private keys, and session material are checked for before
anything is written.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping

from infra.evidence import (
    assert_redacted,
    seal_directory,
    sha256_file,
    verify_directory,
    write_json,
)


EVIDENCE_SUBDIR = "d4"
REQUIRED_FILES: tuple[str, ...] = (
    "p0-cert.pem",
    "p1-cert.pem",
    "p2-cert.pem",
    "tls-pcap.pcap",
    "tls-summary.txt",
    "rss-vectors.json",
    "communication-trace.json",
    "deny-plaintext.txt",
    "deny-wrong-ca.txt",
    "deny-wrong-san.txt",
    "deny-no-client-cert.txt",
    "deny-tls-disabled.txt",
    "material-ledger.json",
)


class D4EvidenceError(ValueError):
    """The evidence directory is incomplete or contains forbidden material."""


def write_text(path: Path, text: str) -> None:
    assert_redacted(text)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text = text + "\n"
    path.write_text(text, encoding="utf-8")


def write_document(path: Path, document: Mapping[str, Any]) -> None:
    assert_redacted(dict(document))
    write_json(Path(path), document)


def copy_certificates(
    workspace_root: Path,
    out_dir: Path,
    roles: Iterable[str] = ("P0", "P1", "P2"),
) -> dict[str, str]:
    """Copy the three public node certificates and return their digests."""
    digests: dict[str, str] = {}
    for role in roles:
        source = Path(workspace_root) / "pki" / "nodes" / role / f"{role}-cert.pem"
        if not source.is_file():
            raise D4EvidenceError(f"the {role} certificate is missing: {source}")
        target = Path(out_dir) / f"{role.lower()}-cert.pem"
        shutil.copyfile(source, target)
        digests[role] = sha256_file(target)
    return digests


def copy_pcap(source: Path, out_dir: Path) -> str:
    source = Path(source)
    if not source.is_file():
        raise D4EvidenceError(f"the capture is missing: {source}")
    target = Path(out_dir) / "tls-pcap.pcap"
    shutil.copyfile(source, target)
    return sha256_file(target)


def missing_required(out_dir: Path) -> list[str]:
    return [name for name in REQUIRED_FILES if not (Path(out_dir) / name).is_file()]


def finalise(
    out_dir: Path,
    *,
    run_id: str,
    instance_id: str,
    cloud_region: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    """Write the run summary, then index and seal the directory."""
    out_dir = Path(out_dir)
    missing = missing_required(out_dir)
    summary = {
        "run_id": run_id,
        "phase": "D4",
        "instance_id": instance_id,
        "cloud_region": cloud_region,
        "required_files": list(REQUIRED_FILES),
        "missing_files": missing,
        "evidence_complete": not missing,
        **dict(details),
    }
    write_document(out_dir / "d4-summary.json", summary)
    index = seal_directory(out_dir)
    verify_directory(out_dir)
    return {"summary": summary, "index": index}


__all__ = [
    "D4EvidenceError",
    "EVIDENCE_SUBDIR",
    "REQUIRED_FILES",
    "copy_certificates",
    "copy_pcap",
    "finalise",
    "missing_required",
    "write_document",
    "write_text",
]

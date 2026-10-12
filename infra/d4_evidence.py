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

import json
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping

from infra.evidence import (
    assert_redacted,
    seal_directory,
    sha256_file,
    verify_directory,
    write_exclusions,
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

# The three-instance run keeps the same per-role artifacts but they are
# collected from three hosts, so the file names carry the role and the raw
# captures stay on the instances that produced them.
CROSS_HOST_ROLES: tuple[str, ...] = ("P0", "P1", "P2")
CROSS_HOST_REQUIRED_FILES: tuple[str, ...] = (
    "d4-three-P0-tls-summary.txt",
    "d4-three-P1-tls-summary.txt",
    "d4-three-P2-tls-summary.txt",
    "d4-three-p0-node-status.json",
    "d4-three-p1-node-status.json",
    "d4-three-p2-node-status.json",
    "d4-three-p0-node.log",
    "d4-three-p1-node.log",
    "d4-three-p2-node.log",
    "d4-three-rss-vectors.json",
    "d4-three-communication-trace.json",
)

# Lines the capture summary carries; the cross-host bundle restates them in
# machine-readable form so a reader does not have to parse prose.
CAPTURE_FACT_LINES: dict[str, str] = {
    "packets on expected ports": "packets",
    "TLS 1.3 flows": "tls13_flows",
    "TLS 1.2-or-lower flows": "lower_flows",
    "handshake messages": "handshake_messages",
    "application-data records": "application_data_records",
    "non-TLS payload bytes": "non_tls_payload_bytes",
    "verdict": "verdict",
}


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
    # A live capture already writes into the evidence directory, so the source
    # and the target are often the same file; that is not a copy failure.
    if source.resolve() != target.resolve():
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


def capture_facts(summary_text: str) -> dict[str, Any]:
    """Read the per-host capture verdict back out of its rendered summary."""
    facts: dict[str, Any] = {}
    for line in summary_text.splitlines():
        label, separator, raw = line.partition(": ")
        if not separator:
            continue
        field = CAPTURE_FACT_LINES.get(label.strip())
        if field is None:
            continue
        value = raw.strip()
        facts[field] = int(value) if value.lstrip("-").isdigit() else value
    missing = set(CAPTURE_FACT_LINES.values()) - set(facts)
    if missing:
        raise D4EvidenceError(
            "the capture summary is missing: " + ", ".join(sorted(missing))
        )
    return facts


def finalise_cross_host(
    out_dir: Path,
    *,
    run_id: str,
    roles: Mapping[str, Mapping[str, Any]],
    captures: Mapping[str, Mapping[str, Any]],
    cloud_region: str = "cn-shanghai",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and seal the evidence of a three-instance run.

    ``roles`` names what each instance is (its id and addresses) and
    ``captures`` names the raw capture each instance kept. The captures are
    recorded in the index but stay on the instances, so the bundle ships their
    digests and the summary each host derived, and the exclusions file records
    exactly which digests a restorer has to match.
    """
    out_dir = Path(out_dir)
    missing = [
        name for name in CROSS_HOST_REQUIRED_FILES
        if not (out_dir / name).is_file()
    ]
    if missing:
        raise D4EvidenceError(
            "the cross-host bundle is incomplete, missing: " + ", ".join(missing)
        )
    absent_roles = [role for role in CROSS_HOST_ROLES if role not in roles]
    if absent_roles:
        raise D4EvidenceError(
            "the cross-host bundle does not describe: " + ", ".join(absent_roles)
        )
    absent_captures = [role for role in CROSS_HOST_ROLES if role not in captures]
    if absent_captures:
        raise D4EvidenceError(
            "no capture is recorded for: " + ", ".join(absent_captures)
        )

    summaries = {
        role: capture_facts(
            (out_dir / f"d4-three-{role}-tls-summary.txt").read_text(encoding="utf-8")
        )
        for role in CROSS_HOST_ROLES
    }
    statuses = {
        role: json.loads(
            (out_dir / f"d4-three-{role.lower()}-node-status.json").read_text(
                encoding="utf-8"
            )
        )
        for role in CROSS_HOST_ROLES
    }
    vectors = json.loads(
        (out_dir / "d4-three-rss-vectors.json").read_text(encoding="utf-8")
    )
    trace = json.loads(
        (out_dir / "d4-three-communication-trace.json").read_text(encoding="utf-8")
    )

    # Every role has to agree on its peers' certificates, or the mesh did not
    # authenticate the same identities end to end.
    certificate_mismatches: list[str] = []
    for role in CROSS_HOST_ROLES:
        peers = statuses[role].get("peer_certificates") or {}
        for peer, digest in peers.items():
            if digest != statuses.get(peer, {}).get("identity_sha256"):
                certificate_mismatches.append(f"{role}->{peer}")
    grid_verdicts = {
        role: statuses[role].get("verdicts") for role in CROSS_HOST_ROLES
    }
    summary = {
        "run_id": run_id,
        "phase": "D4",
        "mode": "three-instances",
        "cloud_region": cloud_region,
        "roles": {role: dict(roles[role]) for role in CROSS_HOST_ROLES},
        "required_files": list(CROSS_HOST_REQUIRED_FILES),
        "missing_files": [],
        "evidence_complete": True,
        "grid": {
            "count": vectors.get("count"),
            "batch": vectors.get("batch"),
            "rows": vectors.get("rows"),
            "cols": vectors.get("cols"),
            "operators": vectors.get("operators"),
            "grid_digest": vectors.get("grid_digest"),
            "verdicts": (vectors.get("summary") or {}).get("verdicts"),
            "passed": (vectors.get("summary") or {}).get("passed"),
            "failed": (vectors.get("summary") or {}).get("failed"),
            "per_role": grid_verdicts,
        },
        "runtime": {
            "transport": trace.get("transport"),
            "inside_enclave": trace.get("inside_enclave"),
            "attestation_available": trace.get("attestation_available"),
            "link_seconds": trace.get("link_seconds"),
            "share_bytes": trace.get("share_bytes"),
            "batches": len(trace.get("batches") or []),
        },
        "capture": {
            role: {**summaries[role], **dict(captures[role])}
            for role in CROSS_HOST_ROLES
        },
        "peer_certificates_match": not certificate_mismatches,
        "certificate_mismatches": certificate_mismatches,
        "teardown_finished": {
            role: bool(statuses[role].get("teardown_finished"))
            for role in CROSS_HOST_ROLES
        },
        **dict(details or {}),
    }
    write_document(out_dir / "d4-three-summary.json", summary)
    exclusions = [
        {
            "path": str(captures[role]["path"]),
            "bytes": int(captures[role]["bytes"]),
            "sha256": str(captures[role]["sha256"]),
            "reason": str(captures[role].get("reason", "")),
        }
        for role in CROSS_HOST_ROLES
    ]
    index = seal_directory(out_dir, external=exclusions)
    write_exclusions(out_dir, exclusions, run_id=run_id)
    verify_directory(out_dir, exclusions=exclusions)
    return {"summary": summary, "index": index, "exclusions": exclusions}


__all__ = [
    "CROSS_HOST_REQUIRED_FILES",
    "CROSS_HOST_ROLES",
    "D4EvidenceError",
    "EVIDENCE_SUBDIR",
    "REQUIRED_FILES",
    "capture_facts",
    "copy_certificates",
    "copy_pcap",
    "finalise",
    "finalise_cross_host",
    "missing_required",
    "write_document",
    "write_text",
]

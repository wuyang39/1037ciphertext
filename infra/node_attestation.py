"""Driver-side half of the attested D4 node identity.

The node half lives in :mod:`tee.enclave.attestation`. This module is what the
acceptance driver uses around it:

* read one real quote from the enclave the nodes are about to run under, so the
  release policy pins the measurement and signer the platform actually reports;
* write that policy and start the KAS on the dealer instance;
* collect the certificate each node was issued and publish the three-way peer
  map the nodes pin before they open a link.

Nothing here trusts a laptop's guess at a measurement: the policy is built from
the quote, and the run fails if that quote disagrees with what
``gramine-sgx-sign`` printed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography import x509

from infra.sgx_quote import parse_quote


BOOTSTRAP_DOMAIN = b"A1-22:d4-bootstrap-quote:v1"
BOOTSTRAP_MODULE = "tee.enclave.quote_bootstrap"
DEFAULT_KAS_PORT = 18443
DEFAULT_PEERS_TIMEOUT_SECONDS = 300.0
PEERS_FILE_NAME = "peers.json"
# ``release_manifest`` pins the release id to this alphabet, and the id ends up
# inside every issued certificate, so a run derives it from its own run id.
RELEASE_ID_PATTERN = re.compile(r"[^A-Za-z0-9._-]")
RELEASE_ID_PREFIX = "a122-d4-attested-"


class NodeAttestationError(RuntimeError):
    """The driver could not prepare or collect the attestation material."""


@dataclass(frozen=True)
class EnclaveClaims:
    """What one bootstrap quote says about the enclave that produced it."""

    mrenclave: str
    mrsigner: str
    isvsvn: int
    debug: bool
    quote_sha256: str
    quote_bytes: int

    def to_evidence(self) -> dict[str, Any]:
        return {
            "mrenclave": self.mrenclave,
            "mrsigner": self.mrsigner,
            "isvsvn": self.isvsvn,
            "debug": self.debug,
            "quote_sha256": self.quote_sha256,
            "quote_bytes": self.quote_bytes,
        }


def bootstrap_report_data() -> bytes:
    """A fixed 64-byte REPORTDATA; the bootstrap proves nothing by itself."""
    return hashlib.sha256(BOOTSTRAP_DOMAIN).digest() + b"\x00" * 32


def bootstrap_quote_command(
    *,
    repo: str,
    out: str,
    launcher: Sequence[str],
    module: str = BOOTSTRAP_MODULE,
) -> str:
    """Start the bootstrap inside the signed manifest the node will load."""
    command = " ".join(shlex.quote(token) for token in launcher)
    return (
        f"cd {shlex.quote(repo)} && {command} -m {module} --out {shlex.quote(out)}"
    )


def read_bootstrap_claims(path: Path) -> EnclaveClaims:
    """Parse one bootstrap quote into the claims the policy pins."""
    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        raise NodeAttestationError(f"the bootstrap quote is missing: {exc}") from exc
    try:
        claims = parse_quote(blob)
    except ValueError as exc:
        raise NodeAttestationError(f"the bootstrap quote is malformed: {exc}") from exc
    return EnclaveClaims(
        mrenclave=claims.mr_enclave.hex(),
        mrsigner=claims.mr_signer.hex(),
        isvsvn=claims.isv_svn,
        debug=claims.debug,
        quote_sha256=hashlib.sha256(blob).hexdigest(),
        quote_bytes=len(blob),
    )


def release_policy_document(
    *,
    release_id: str,
    claims: EnclaveClaims,
    spu_build_hash: str,
    model_version: str,
    model_manifest_hash: str,
    precision_plan_hash: str,
    expires_at: dt.datetime,
) -> dict[str, Any]:
    """The one release the KAS will attest, pinned to the bootstrap quote."""
    if claims.debug:
        raise NodeAttestationError(
            "the bootstrap quote is a debug quote; the release cannot be pinned "
            "to it"
        )
    return {
        "releases": [
            {
                "release_id": release_id,
                "mrenclave": claims.mrenclave,
                "mrsigner": claims.mrsigner,
                "min_isvsvn": claims.isvsvn,
                "debug_allowed": False,
                "spu_build_hash": spu_build_hash,
                "model_version": model_version,
                "model_manifest_hash": model_manifest_hash,
                "precision_plan_hash": precision_plan_hash,
                "expires_at": expires_at.astimezone(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        ]
    }


def write_release_policy(path: Path, document: Mapping[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def kas_start_command(
    *,
    repo: str,
    python: str,
    settings: Mapping[str, str],
    log: str,
    secret_files: Mapping[str, str] | None = None,
) -> str:
    """Start the KAS on the instance that owns it, detached.

    ``secret_files`` names settings whose value is read out of a file at start
    time. The storage key master is generated on the instance and never leaves
    it, so the driver has no value to put in the environment itself: the
    remote shell expands ``$(cat ...)`` before ``env`` runs.
    """
    assignments = [
        f"{name}={shlex.quote(str(value))}"
        for name, value in sorted(settings.items())
    ]
    assignments += [
        f'{name}="$(cat {shlex.quote(path)})"'
        for name, path in sorted((secret_files or {}).items())
    ]
    joined = " ".join(assignments)
    return (
        f"cd {shlex.quote(repo)} && "
        f"setsid nohup env {joined} {shlex.quote(python)} -m kas "
        f"> {shlex.quote(log)} 2>&1 < /dev/null & echo started"
    )


def attestation_block(
    *,
    kas_url: str,
    release_id: str,
    shared_dir: str,
    private_dir: str = "/tmp/a122-attest",
    peers_timeout_seconds: float = DEFAULT_PEERS_TIMEOUT_SECONDS,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """The block the driver merges into every node configuration."""
    return {
        "kas_url": kas_url,
        "release_id": release_id,
        "shared_dir": shared_dir,
        "private_dir": private_dir,
        "peers_timeout_seconds": float(peers_timeout_seconds),
        "timeout_seconds": float(timeout_seconds),
    }


def shared_attestation_dir(workspace: str, run_id: str) -> str:
    """One host-visible directory per run, inside the writable out/ tree."""
    safe = RELEASE_ID_PATTERN.sub("-", run_id).strip(".-") or "run"
    return f"{workspace.rstrip('/')}/out/attest-{safe}"


def certificate_path(shared_dir: str, role: str) -> str:
    return f"{shared_dir.rstrip('/')}/{role}-cert.pem"


def peers_path(shared_dir: str) -> str:
    return f"{shared_dir.rstrip('/')}/{PEERS_FILE_NAME}"


def peer_map_document(certificates: Mapping[str, str]) -> dict[str, str]:
    if not certificates:
        raise NodeAttestationError("no node certificates were collected")
    return {str(role): str(pem) for role, pem in sorted(certificates.items())}


def assert_certificates_agree(claims: Mapping[str, EnclaveClaims]) -> EnclaveClaims:
    """Every rank has to report one measurement, or the release means nothing."""
    if not claims:
        raise NodeAttestationError("no bootstrap quotes were collected")
    measurements = {row.mrenclave for row in claims.values()}
    if len(measurements) != 1:
        raise NodeAttestationError(
            "the three enclaves report different measurements: "
            + ", ".join(sorted(measurements))
        )
    signers = {row.mrsigner for row in claims.values()}
    if len(signers) != 1:
        raise NodeAttestationError(
            "the three enclaves report different signers: "
            + ", ".join(sorted(signers))
        )
    isvsvns = {row.isvsvn for row in claims.values()}
    if len(isvsvns) != 1:
        raise NodeAttestationError("the three enclaves report different ISVSVNs")
    return next(iter(claims.values()))


def run_release_id(run_id: str, *, prefix: str = RELEASE_ID_PREFIX) -> str:
    """Derive the one release the KAS registers for a run from its run id."""
    sanitized = RELEASE_ID_PATTERN.sub("-", run_id).strip(".-") or "run"
    release_id = f"{prefix}{sanitized}"
    if len(release_id) > 128:
        release_id = release_id[:128].rstrip(".-")
    if len(release_id) < 3:  # pragma: no cover - the prefix already covers this
        raise NodeAttestationError("the release id derived from the run is too short")
    return release_id


def kas_health_url(host: str, port: int) -> str:
    return f"http://{host}:{int(port)}/healthz"


def certificate_is_for_role(certificate_pem: str, role: str) -> bool:
    """True when a published leaf is a PEM leaf whose SAN names this role."""
    try:
        leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        sans = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
    except (ValueError, x509.ExtensionNotFound, UnicodeEncodeError):
        return False
    return f"spiffe://a122/{role}" in list(sans)


def collect_published_certificates(
    present: Mapping[str, str | None], roles: Sequence[str]
) -> dict[str, str] | None:
    """Return the published leaves once every role has one, else ``None``.

    A node publishes its KAS-issued certificate into a host-visible directory
    as soon as it has one. The driver polls those files, and this decides when
    the three-way peer map can be written back. A leaf that is not a PEM
    identity for its own role is a driver-side error rather than a silent gap:
    relaying it would only move the refusal to the node.
    """
    collected: dict[str, str] = {}
    for role in roles:
        pem = present.get(role)
        if not pem:
            return None
        if not certificate_is_for_role(pem, role):
            raise NodeAttestationError(
                f"the published {role} leaf is not a certificate for that role"
            )
        collected[role] = pem
    return collected


def assert_attested_run(
    statuses: Mapping[str, Mapping[str, Any]],
    *,
    roles: Sequence[str],
    mrenclave: str,
) -> dict[str, Any]:
    """Require every rank to report the KAS identity the release pinned.

    The positive run only counts as attested when each node says its own
    identity came from the KAS, under the one measurement the release
    registered, with a lease of its own. Two ranks sharing a lease, a node
    falling back to the local PKI, or a measurement the release does not carry
    all mean the mesh did not authenticate what the bundle claims it did.
    """
    reported: dict[str, Any] = {}
    leases: set[str] = set()
    quotes: set[str] = set()
    for role in roles:
        block = (statuses.get(role) or {}).get("attestation")
        if not isinstance(block, Mapping):
            raise NodeAttestationError(f"{role} reports no attestation block")
        if block.get("mode") != "kas-attested":
            raise NodeAttestationError(
                f"{role} reports {block.get('mode')!r} instead of a KAS identity"
            )
        if str(block.get("mrenclave", "")).lower() != mrenclave.lower():
            raise NodeAttestationError(
                f"{role} attested under {block.get('mrenclave')!r}, "
                f"not the registered {mrenclave}"
            )
        lease_id = str(block.get("lease_id") or "")
        quote_sha256 = str(block.get("quote_sha256") or "")
        if not lease_id or not quote_sha256:
            raise NodeAttestationError(f"{role} reports no lease or no quote")
        leases.add(lease_id)
        quotes.add(quote_sha256)
        reported[role] = {
            "lease_id": lease_id,
            "expires_at": block.get("expires_at"),
            "mrenclave": block.get("mrenclave"),
            "mrsigner": block.get("mrsigner"),
            "quote_sha256": quote_sha256,
            "quote_bytes": block.get("quote_bytes"),
            "certificate": block.get("certificate"),
        }
    if len(leases) != len(roles):
        raise NodeAttestationError("two ranks report the same lease")
    if len(quotes) != len(roles):
        raise NodeAttestationError("two ranks report the same quote")
    return {
        "roles": reported,
        "distinct_leases": len(leases),
        "distinct_quotes": len(quotes),
        "mrenclave": mrenclave,
    }


__all__ = [
    "BOOTSTRAP_DOMAIN",
    "BOOTSTRAP_MODULE",
    "DEFAULT_KAS_PORT",
    "DEFAULT_PEERS_TIMEOUT_SECONDS",
    "EnclaveClaims",
    "NodeAttestationError",
    "PEERS_FILE_NAME",
    "RELEASE_ID_PREFIX",
    "assert_certificates_agree",
    "assert_attested_run",
    "attestation_block",
    "bootstrap_quote_command",
    "bootstrap_report_data",
    "certificate_is_for_role",
    "certificate_path",
    "collect_published_certificates",
    "kas_start_command",
    "kas_health_url",
    "peer_map_document",
    "peers_path",
    "read_bootstrap_claims",
    "release_policy_document",
    "run_release_id",
    "shared_attestation_dir",
    "write_release_policy",
]

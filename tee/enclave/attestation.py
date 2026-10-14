"""Node identity that the KAS issues from a real Quote, not from the driver.

The D4/D5/D6/D7 acceptance runs took their certificate, key, and CA bundle
from a local PKI the driver generated, so the session's identities proved
nothing about where the node ran. This module closes that gap.

The node generates its own P-256 key inside the enclave, binds that key, its
role and the release into REPORTDATA, has the platform quote it (Gramine
exposes the DCAP quote at ``/dev/attestation/quote``), and asks the KAS to
verify the quote and issue a short-lived certificate and lease. Only an
identity the KAS issued for that quote is accepted: a missing quote, a quote
that does not carry this key's REPORTDATA, an unreachable KAS, or a rejected
attestation all stop the node before it opens the SPU link.

Peer certificates are collected in a second step. Each node publishes the
certificate it was issued into a host-visible directory, the driver writes the
three-way mapping back, and every node pins the peers' leaves against the KAS
CA and the SAN role before the link starts. That keeps the D4 role binding
while letting each node's own key live only inside its enclave.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from infra.sgx_quote import parse_quote
from kas.binding import build_report_data, csr_public_key_der
from mpc.spu_backend.spu_link import NodeIdentity
from tee.enclave.node_common import NodeError


class AttestationError(NodeError):
    """The node could not obtain an attested identity, so it must refuse."""


ATTESTATION_DIR_NAME = "attestation"
PEERS_FILE_NAME = "peers.json"
RELEASE_EXTENSION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
DEFAULT_KAS_TIMEOUT_SECONDS = 30.0
DEFAULT_PEERS_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True)
class AttestationConfig:
    """Everything one node needs to ask the KAS for an attested identity."""

    kas_url: str
    release_id: str
    shared_dir: Path
    timeout_seconds: float = DEFAULT_KAS_TIMEOUT_SECONDS
    peers_timeout_seconds: float = DEFAULT_PEERS_TIMEOUT_SECONDS
    # The private key lives in the enclave-private tmpfs, never in the shared
    # host-visible directory the driver reads the certificates back from.
    private_dir: Path = Path("/tmp/a122-attest")
    report_data_path: Path = Path("/dev/attestation/user_report_data")
    quote_path: Path = Path("/dev/attestation/quote")

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "AttestationConfig":
        try:
            kas_url = str(document["kas_url"])
            release_id = str(document["release_id"])
            shared_dir = Path(document["shared_dir"])
        except KeyError as exc:
            raise AttestationError(
                f"the attestation block is missing {exc.args[0]!r}"
            ) from exc
        if not kas_url.startswith(("http://", "https://")):
            raise AttestationError("the KAS URL must be http(s)")
        if len(release_id) < 3:
            raise AttestationError("the release id is too short")
        timeout = float(document.get("timeout_seconds", DEFAULT_KAS_TIMEOUT_SECONDS))
        peers_timeout = float(
            document.get("peers_timeout_seconds", DEFAULT_PEERS_TIMEOUT_SECONDS)
        )
        if timeout <= 0 or peers_timeout <= 0:
            raise AttestationError("the attestation timeouts must be positive")
        return cls(
            kas_url=kas_url.rstrip("/"),
            release_id=release_id,
            shared_dir=shared_dir,
            timeout_seconds=timeout,
            peers_timeout_seconds=peers_timeout,
            private_dir=Path(document.get("private_dir", "/tmp/a122-attest")),
            report_data_path=Path(
                document.get("report_data_path", "/dev/attestation/user_report_data")
            ),
            quote_path=Path(document.get("quote_path", "/dev/attestation/quote")),
        )


@dataclass(frozen=True)
class AttestedNodeIdentity:
    """The identity the KAS issued, plus what the node measured to get it."""

    identity: NodeIdentity
    lease_id: str
    expires_at: str
    mrenclave: str
    mrsigner: str
    quote_sha256: str
    quote_bytes: int
    report_data_hex: str
    certificate_path: Path

    def to_evidence(self) -> dict[str, Any]:
        return {
            "mode": "kas-attested",
            "lease_id": self.lease_id,
            "expires_at": self.expires_at,
            "mrenclave": self.mrenclave,
            "mrsigner": self.mrsigner,
            "quote_sha256": self.quote_sha256,
            "quote_bytes": self.quote_bytes,
            "report_data_hex": self.report_data_hex,
            "certificate": str(self.certificate_path),
        }


def read_platform_quote(
    report_data: bytes,
    *,
    report_data_path: Path,
    quote_path: Path,
) -> bytes:
    """Write REPORTDATA and read back the quote the platform produced.

    Gramine serves both files from its attestation pseudo-filesystem once the
    manifest sets ``sgx.remote_attestation``. A host process has no such
    directory, which is exactly why an unattested host fails closed here.
    """
    if len(report_data) != 64:
        raise AttestationError("REPORTDATA must be 64 bytes")
    try:
        with open(report_data_path, "wb") as handle:
            handle.write(report_data)
    except OSError as exc:
        raise AttestationError(
            f"the enclave REPORTDATA file is unavailable: {exc}"
        ) from exc
    try:
        quote = quote_path.read_bytes()
    except OSError as exc:
        raise AttestationError(f"the platform quote is unavailable: {exc}") from exc
    if not quote:
        raise AttestationError("the platform returned an empty quote")
    return quote


def _post(
    base_url: str,
    path: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            document = {"detail": raw}
        return exc.code, document
    except urllib.error.URLError as exc:
        raise AttestationError(f"the KAS is unreachable: {exc}") from exc


def _generate_csr(role: str) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"a122-{role}")])
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), key


def _call(
    post: Callable[..., tuple[int, dict[str, Any]]],
    *,
    base_url: str,
    path: str,
    payload: Mapping[str, Any],
    timeout: float,
) -> tuple[int, dict[str, Any]]:
    """One KAS call, with every transport failure turned into a refusal."""
    try:
        return post(base_url, path, payload, timeout=timeout)
    except AttestationError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AttestationError(f"the KAS is unreachable: {exc}") from exc


def _write_identity_files(
    material_dir: Path,
    *,
    role: str,
    key: ec.EllipticCurvePrivateKey,
    certificate_pem: str,
    ca_bundle_pem: str,
) -> tuple[Path, Path, Path]:
    material_dir.mkdir(parents=True, exist_ok=True)
    certificate_path = material_dir / f"{role}-cert.pem"
    key_path = material_dir / f"{role}-key.pem"
    ca_bundle_path = material_dir / f"{role}-ca-bundle.pem"
    certificate_path.write_text(certificate_pem, encoding="ascii")
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    ca_bundle_path.write_text(ca_bundle_pem, encoding="ascii")
    return certificate_path, key_path, ca_bundle_path


def bootstrap_node_identity(
    config: AttestationConfig,
    *,
    role: str,
    material_dir: Path | None = None,
    quote_source: Callable[[bytes], bytes] | None = None,
    post: Callable[..., tuple[int, dict[str, Any]]] | None = None,
) -> AttestedNodeIdentity:
    """Attest with the platform quote and take the KAS-issued identity.

    ``quote_source`` and ``post`` exist so the acceptance can exercise the
    refusals on a host with no SGX device; the shipping path never injects
    either.
    """
    if role not in {"P0", "P1", "P2", "C"}:
        raise AttestationError("the attested role must be P0, P1, P2, or C")
    effective_post = post or _post
    source = quote_source or (
        lambda report_data: read_platform_quote(
            report_data,
            report_data_path=config.report_data_path,
            quote_path=config.quote_path,
        )
    )

    status, challenge = _call(
        effective_post,
        base_url=config.kas_url,
        path="/v1/challenge",
        payload={"role": role, "release_id": config.release_id},
        timeout=config.timeout_seconds,
    )
    if status != 201:
        raise AttestationError(
            f"the KAS refused the challenge ({status}): "
            f"{challenge.get('detail', challenge)}"
        )
    try:
        challenge_id = str(challenge["challenge_id"])
        nonce = bytes.fromhex(str(challenge["nonce"]))
    except (KeyError, ValueError) as exc:
        raise AttestationError("the KAS challenge response is malformed") from exc

    csr_pem, key = _generate_csr(role)
    report_data = build_report_data(
        csr_public_key_der(csr_pem), role, config.release_id, nonce
    )
    quote = source(report_data)
    try:
        claims = parse_quote(quote)
    except ValueError as exc:
        raise AttestationError(f"the platform quote is malformed: {exc}") from exc
    if claims.report_data != report_data:
        raise AttestationError(
            "the platform quote does not bind the node key this process generated"
        )

    status, issued = _call(
        effective_post,
        base_url=config.kas_url,
        path="/v1/attest",
        payload={
            "challenge_id": challenge_id,
            "role": role,
            "release_id": config.release_id,
            "csr_pem": csr_pem,
            "dcap_quote_b64": base64.b64encode(quote).decode("ascii"),
        },
        timeout=config.timeout_seconds,
    )
    if status != 200:
        raise AttestationError(
            f"the KAS rejected the attestation ({status}): "
            f"{issued.get('detail', issued)}"
        )
    try:
        certificate_pem = str(issued["node_certificate_pem"])
        ca_bundle_pem = str(issued["ca_bundle_pem"])
        lease_id = str(issued["lease_id"])
        expires_at = str(issued["expires_at"])
    except KeyError as exc:
        raise AttestationError(
            f"the KAS attestation response is missing {exc.args[0]!r}"
        ) from exc

    directory = material_dir or (config.private_dir / ATTESTATION_DIR_NAME / role)
    certificate_path, key_path, ca_bundle_path = _write_identity_files(
        directory,
        role=role,
        key=key,
        certificate_pem=certificate_pem,
        ca_bundle_pem=ca_bundle_pem,
    )
    # The driver reads this copy back to build the three-way peer map; the
    # private key never leaves the enclave-written material directory.
    published = config.shared_dir / f"{role}-cert.pem"
    try:
        published.parent.mkdir(parents=True, exist_ok=True)
        published.write_text(certificate_pem, encoding="ascii")
    except OSError as exc:
        raise AttestationError(
            f"the attested certificate could not be published: {exc}"
        ) from exc

    return AttestedNodeIdentity(
        identity=NodeIdentity(
            role=role,
            certificate_path=certificate_path,
            private_key_path=key_path,
            ca_bundle_path=ca_bundle_path,
        ),
        lease_id=lease_id,
        expires_at=expires_at,
        mrenclave=claims.mr_enclave.hex(),
        mrsigner=claims.mr_signer.hex(),
        quote_sha256=hashlib.sha256(quote).hexdigest(),
        quote_bytes=len(quote),
        report_data_hex=claims.report_data.hex(),
        certificate_path=certificate_path,
    )


def _peer_document(path: Path) -> dict[str, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"the peer map could not be read: {exc}") from exc
    if not isinstance(document, dict):
        raise AttestationError("the peer map must be a JSON object")
    return {str(role): str(pem) for role, pem in document.items()}


def assert_peer_certificate(
    certificate_pem: str,
    *,
    peer_role: str,
    release_id: str,
    ca_bundle_pem: str,
    now: dt.datetime | None = None,
) -> None:
    """Fail closed unless the peer leaf is a KAS-issued identity for its role."""
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    try:
        leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        authority = x509.load_pem_x509_certificate(ca_bundle_pem.encode("ascii"))
    except ValueError as exc:
        raise AttestationError(f"the peer certificate is not PEM: {exc}") from exc
    if not leaf.not_valid_before_utc <= current <= leaf.not_valid_after_utc:
        raise AttestationError(f"peer {peer_role} certificate is outside its window")
    if leaf.issuer != authority.subject:
        raise AttestationError(f"peer {peer_role} certificate is not from the KAS CA")
    try:
        authority.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(leaf.signature_hash_algorithm),
        )
    except Exception as exc:  # noqa: BLE001 - any failure is a refusal
        raise AttestationError(
            f"peer {peer_role} certificate signature does not verify"
        ) from exc
    try:
        sans = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as exc:
        raise AttestationError(f"peer {peer_role} certificate has no SAN") from exc
    if f"spiffe://a122/{peer_role}" not in list(sans):
        raise AttestationError(f"peer {peer_role} certificate SAN does not match")
    try:
        release = leaf.extensions.get_extension_for_oid(RELEASE_EXTENSION_OID).value
    except x509.ExtensionNotFound as exc:
        raise AttestationError(
            f"peer {peer_role} certificate carries no release binding"
        ) from exc
    if bytes(release.value).decode("utf-8", errors="replace") != release_id:
        raise AttestationError(
            f"peer {peer_role} certificate is bound to another release"
        )


def await_peer_certificates(
    config: AttestationConfig,
    *,
    peer_roles: Sequence[str],
    pin_dir: Path,
    ca_bundle_pem: str,
    poll_seconds: float = 0.5,
    deadline_seconds: float | None = None,
) -> dict[str, Path]:
    """Wait for the driver's three-way peer map and pin each leaf.

    The map is written into the host-visible shared directory, so the node
    learns its peers' identities only after every node has attested. A map that
    never arrives, names the wrong roles, or carries a leaf that is not a
    KAS-issued identity for that role stops the node here.
    """
    path = config.shared_dir / PEERS_FILE_NAME
    budget = (
        config.peers_timeout_seconds if deadline_seconds is None else deadline_seconds
    )
    deadline = time.monotonic() + budget
    document: dict[str, str] | None = None
    while time.monotonic() < deadline:
        if path.is_file():
            document = _peer_document(path)
            missing = [role for role in peer_roles if role not in document]
            if not missing:
                break
            document = None
        time.sleep(poll_seconds)
    if document is None:
        raise AttestationError(
            f"the peer map {path} did not list every peer role in {budget:.0f}s"
        )

    pin_dir.mkdir(parents=True, exist_ok=True)
    pinned: dict[str, Path] = {}
    for role in peer_roles:
        assert_peer_certificate(
            document[role],
            peer_role=role,
            release_id=config.release_id,
            ca_bundle_pem=ca_bundle_pem,
        )
        pin_path = pin_dir / f"{role}.pem"
        pin_path.write_text(document[role], encoding="ascii")
        pinned[role] = pin_path
    return pinned


__all__ = [
    "ATTESTATION_DIR_NAME",
    "AttestationConfig",
    "AttestationError",
    "AttestedNodeIdentity",
    "PEERS_FILE_NAME",
    "assert_peer_certificate",
    "await_peer_certificates",
    "bootstrap_node_identity",
    "read_platform_quote",
]

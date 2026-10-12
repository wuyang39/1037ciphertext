"""Certificate provisioning for the D4 three-node enclave cluster.

The plan requires every SPU node to bind a KAS-issued certificate and to check
the CA, the SAN, the role, and the lease before a link may start. D4 reuses the
KAS certificate authority from ``kas.ca`` so the local harness and the server
run share one issuance path.

The same module produces the negative material the acceptance needs: a leaf
signed by a foreign CA, and a leaf whose SAN names another role.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kas.ca import CertificateAuthority


DEFAULT_RELEASE_ID = "a122-d4"
DEFAULT_TTL_HOURS = 24
CA_COMMON_NAME = "A1-22 D4 KAS CA"
FOREIGN_CA_COMMON_NAME = "A1-22 D4 Foreign CA"


class D4PKIError(ValueError):
    """The D4 certificate material could not be produced."""


@dataclass(frozen=True)
class NodeCredentials:
    """One node identity on disk plus the peer material it must trust."""

    role: str
    san_role: str
    certificate_path: Path
    private_key_path: Path
    ca_bundle_path: Path
    certificate_sha256: str
    lease_expires_utc: str


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def generate_authority(
    directory: Path,
    *,
    common_name: str = CA_COMMON_NAME,
    valid_hours: int = 48,
) -> tuple[Path, Path]:
    """Create an EC P-256 CA and return ``(key_path, certificate_path)``."""
    if valid_hours < 1:
        raise D4PKIError("the CA lifetime must be positive")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=valid_hours))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "ca-key.pem"
    certificate_path = directory / "ca-cert.pem"
    _write_private_key(key_path, key)
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, certificate_path


def issue_node_credentials(
    *,
    ca_key_path: Path,
    ca_certificate_path: Path,
    role: str,
    out_dir: Path,
    san_role: str | None = None,
    release_id: str = DEFAULT_RELEASE_ID,
    ttl_hours: int = DEFAULT_TTL_HOURS,
) -> NodeCredentials:
    """Issue one node certificate through the KAS CA."""
    if role not in {"P0", "P1", "P2"}:
        raise D4PKIError("the node role must be P0, P1, or P2")
    effective_san = san_role or role
    if effective_san not in {"P0", "P1", "P2"}:
        raise D4PKIError("the SAN role must be P0, P1, or P2")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"a122-{role}")])
        )
        .sign(key, hashes.SHA256())
    )
    authority = CertificateAuthority.from_pem_files(
        Path(ca_key_path), Path(ca_certificate_path)
    )
    issued = authority.issue_node_certificate(
        csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        role=effective_san,
        release_id=release_id,
        now=now,
        ttl=dt.timedelta(hours=ttl_hours),
    )
    certificate_path = out_dir / f"{role}-cert.pem"
    private_key_path = out_dir / f"{role}-key.pem"
    ca_bundle_path = out_dir / f"{role}-ca-bundle.pem"
    certificate_path.write_text(issued.certificate_pem, encoding="ascii")
    _write_private_key(private_key_path, key)
    ca_bundle_path.write_text(issued.ca_bundle_pem, encoding="ascii")
    return NodeCredentials(
        role=role,
        san_role=effective_san,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        ca_bundle_path=ca_bundle_path,
        certificate_sha256=hashlib_sha256(issued.certificate_pem),
        lease_expires_utc=(now + dt.timedelta(hours=ttl_hours))
        .replace(microsecond=0)
        .isoformat(),
    )


def hashlib_sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("ascii")).hexdigest()


def provision_cluster(
    root: Path,
    *,
    roles: tuple[str, ...] = ("P0", "P1", "P2"),
    release_id: str = DEFAULT_RELEASE_ID,
    ttl_hours: int = DEFAULT_TTL_HOURS,
) -> dict[str, NodeCredentials]:
    """Issue the KAS CA and one certificate per role under ``root``."""
    root = Path(root)
    ca_dir = root / "ca"
    ca_key, ca_certificate = generate_authority(ca_dir)
    credentials: dict[str, NodeCredentials] = {}
    for role in roles:
        credentials[role] = issue_node_credentials(
            ca_key_path=ca_key,
            ca_certificate_path=ca_certificate,
            role=role,
            out_dir=root / "nodes" / role,
            release_id=release_id,
            ttl_hours=ttl_hours,
        )
    return credentials


def provision_negative_authority(root: Path) -> tuple[Path, Path]:
    """Create the foreign CA used by the wrong-CA negative case."""
    return generate_authority(
        Path(root) / "foreign-ca",
        common_name=FOREIGN_CA_COMMON_NAME,
    )


__all__ = [
    "CA_COMMON_NAME",
    "DEFAULT_RELEASE_ID",
    "DEFAULT_TTL_HOURS",
    "D4PKIError",
    "FOREIGN_CA_COMMON_NAME",
    "NodeCredentials",
    "generate_authority",
    "issue_node_credentials",
    "provision_cluster",
    "provision_negative_authority",
]

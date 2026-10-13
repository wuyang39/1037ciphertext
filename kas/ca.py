"""Short-lived node certificate issuance after successful attestation."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from .errors import AttestationRejected


RELEASE_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
# The CA signs one identity per SPU party plus the client that drives them.
# D6 introduces the client certificate so the share channel can authenticate
# "C" as its own role instead of borrowing a node identity.
SIGNED_IDENTITY_ROLES = frozenset({"C", "P0", "P1", "P2"})


@dataclass(frozen=True)
class NodeCertificate:
    certificate_pem: str
    ca_bundle_pem: str


class CertificateAuthority:
    """KAS-controlled CA. Its private key must come from protected storage."""

    def __init__(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        certificate: x509.Certificate,
    ) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("KAS CA key must use P-256")
        if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
            raise ValueError("KAS CA certificate does not match its private key")
        self._private_key = private_key
        self._certificate = certificate

    @classmethod
    def from_pem_files(cls, key_path: Path, certificate_path: Path) -> "CertificateAuthority":
        key_data = key_path.read_bytes()
        certificate_data = certificate_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_data, password=None)
        certificate = x509.load_pem_x509_certificate(certificate_data)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("KAS CA key must be an EC private key")
        return cls(private_key=private_key, certificate=certificate)

    @property
    def certificate_pem(self) -> str:
        return self._certificate.public_bytes(serialization.Encoding.PEM).decode(
            "ascii"
        )

    def issue_node_certificate(
        self,
        csr_pem: str,
        *,
        role: str,
        release_id: str,
        now: dt.datetime,
        ttl: dt.timedelta,
    ) -> NodeCertificate:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        except ValueError as exc:
            raise AttestationRejected("invalid PEM CSR") from exc
        if not csr.is_signature_valid:
            raise AttestationRejected("CSR signature is invalid")
        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise AttestationRejected("node key must be P-256")
        if role not in SIGNED_IDENTITY_ROLES:
            raise AttestationRejected("invalid certificate role")

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A1-22"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
                x509.NameAttribute(NameOID.COMMON_NAME, f"a122-{role}"),
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + ttl)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://a122/{role}")]
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    RELEASE_EXTENSION_OID, release_id.encode("utf-8")
                ),
                critical=False,
            )
            .sign(self._private_key, hashes.SHA256())
        )
        return NodeCertificate(
            certificate_pem=certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii"),
            ca_bundle_pem=self.certificate_pem,
        )

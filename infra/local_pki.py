"""Development-only PKI for the local TLS integration environment."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mpc.spu_backend.transport import TLSIdentity


class LocalPKIError(ValueError):
    """The development PKI could not be generated."""


@dataclass(frozen=True)
class LocalCertificate:
    role: str
    certificate_pem: str
    private_key_pem: str


class LocalPKI:
    """Generate short-lived, role-bound certificates for localhost only."""

    def __init__(self, *, valid_hours: int = 24) -> None:
        if valid_hours < 1 or valid_hours > 72:
            raise LocalPKIError("local certificate lifetime must be 1-72 hours")
        self._now = dt.datetime.now(dt.timezone.utc)
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 Local Dev CA")]
        )
        self.ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._now - dt.timedelta(minutes=5))
            .not_valid_after(self._now + dt.timedelta(hours=valid_hours))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        self.ca_pem = self.ca_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii")

    def issue(self, role: str) -> LocalCertificate:
        if role not in {"P0", "P1", "P2"}:
            raise LocalPKIError("local certificate role must be P0, P1, or P2")
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"A1-22 Local {role}")]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._now - dt.timedelta(minutes=5))
            .not_valid_after(self._now + dt.timedelta(hours=24))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://a122/{role}")]
                ),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        return LocalCertificate(
            role=role,
            certificate_pem=certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii"),
            private_key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
        )

    def identity(
        self,
        role: str,
        *,
        allowed_peer_roles: tuple[str, ...],
    ) -> TLSIdentity:
        certificate = self.issue(role)
        return TLSIdentity(
            role=role,
            certificate_pem=certificate.certificate_pem,
            private_key_pem=certificate.private_key_pem,
            ca_bundle_pem=self.ca_pem,
            allowed_peer_roles=allowed_peer_roles,
        )


__all__ = ["LocalCertificate", "LocalPKI", "LocalPKIError"]

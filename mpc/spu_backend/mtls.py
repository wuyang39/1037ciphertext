"""Fail-closed TLS policy for the SPU/BRPC boundary.

The D4 link terminates real TLS inside the enclave: the SPU runtime owns the
BRPC/OpenSSL context, and a second mutually authenticated channel moves input
and output shares between the parties. This module holds the policy both paths
share.

``MockTLSChannel`` is the original in-process model. It stays as the unit-test
double for the policy itself, but it is no longer the D4 acceptance path:
``verify_live_peer`` checks the certificate the peer actually presented on a
real handshake, and ``verify_session_version`` refuses any negotiated version
below TLS 1.3.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


class TLSPolicyError(ValueError):
    """The channel configuration or peer identity is not acceptable."""


@dataclass(frozen=True)
class TLSConfig:
    """Identity material and peer SAN policy for one SPU endpoint."""

    role: str
    certificate_pem: str = field(repr=False)
    private_key_pem: str = field(repr=False)
    ca_bundle_pem: str = field(repr=False)
    expected_peer_san: str
    min_version: str = "TLS1.3"
    require_client_certificate: bool = True
    allow_brpc_builtin_services: bool = False

    def __post_init__(self) -> None:
        if self.role not in {"P0", "P1", "P2"}:
            raise TLSPolicyError("SPU role must be P0, P1, or P2")
        if self.min_version != "TLS1.3":
            raise TLSPolicyError("TLS versions below 1.3 are forbidden")
        if not self.require_client_certificate:
            raise TLSPolicyError("client certificates are mandatory")
        if self.allow_brpc_builtin_services:
            raise TLSPolicyError("BRPC builtin services must remain disabled")
        for name in ("certificate_pem", "private_key_pem", "ca_bundle_pem"):
            if not getattr(self, name):
                raise TLSPolicyError(f"{name} must not be empty")
        if not self.expected_peer_san.startswith("spiffe://a122/"):
            raise TLSPolicyError("peer SAN must use the A1-22 SPIFFE prefix")


@dataclass(frozen=True)
class TLSSession:
    """The narrow metadata exposed after successful policy validation."""

    local_role: str
    peer_role: str
    peer_san: str
    tls_version: str
    mutual: bool = True


def _load_certificate(certificate_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except ValueError as exc:
        raise TLSPolicyError("certificate is not valid PEM") from exc


def _load_ca(ca_bundle_pem: str) -> x509.Certificate:
    certificates = x509.load_pem_x509_certificates(ca_bundle_pem.encode("ascii"))
    if not certificates:
        raise TLSPolicyError("CA bundle is empty")
    ca = certificates[0]
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise TLSPolicyError("configured CA is not a CA certificate")
    return ca


def _verify_leaf(
    leaf: x509.Certificate,
    *,
    ca: x509.Certificate,
    expected_san: str,
    now: dt.datetime,
) -> None:
    if now.tzinfo is None:
        raise TLSPolicyError("validation clock must be timezone-aware")
    try:
        not_before = leaf.not_valid_before_utc
        not_after = leaf.not_valid_after_utc
    except AttributeError:
        not_before = leaf.not_valid_before.replace(tzinfo=dt.timezone.utc)
        not_after = leaf.not_valid_after.replace(tzinfo=dt.timezone.utc)
    if not not_before <= now.astimezone(dt.timezone.utc) <= not_after:
        raise TLSPolicyError("peer certificate is outside its validity window")
    try:
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise TLSPolicyError("peer certificate has no SAN extension") from exc
    if expected_san not in san.get_values_for_type(x509.UniformResourceIdentifier):
        raise TLSPolicyError("peer certificate SAN does not match the role")
    try:
        public_key = ca.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(leaf.signature_hash_algorithm),
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf.signature_hash_algorithm,
            )
        else:
            raise TLSPolicyError("unsupported CA public-key algorithm")
    except Exception as exc:
        raise TLSPolicyError("peer certificate was not signed by the trusted CA") from exc


class MockTLSChannel:
    """Test-only: validate two endpoint configurations without a socket."""

    @staticmethod
    def connect(
        *,
        local: TLSConfig,
        peer: TLSConfig | None,
        now: dt.datetime | None = None,
    ) -> TLSSession:
        if peer is None:
            raise TLSPolicyError("client certificate is missing")
        if peer.role not in {"P0", "P1", "P2"} or peer.role == local.role:
            raise TLSPolicyError("peer role is not a distinct SPU node")
        if local.expected_peer_san != f"spiffe://a122/{peer.role}":
            raise TLSPolicyError("local peer SAN allowlist does not match the role")
        if peer.expected_peer_san != f"spiffe://a122/{local.role}":
            raise TLSPolicyError("peer role allowlist does not match the local role")
        current = now or dt.datetime.now(dt.timezone.utc)
        local_ca = _load_ca(local.ca_bundle_pem)
        peer_ca = _load_ca(peer.ca_bundle_pem)
        if local_ca.fingerprint(peer_ca.signature_hash_algorithm) != peer_ca.fingerprint(
            peer_ca.signature_hash_algorithm
        ):
            raise TLSPolicyError("endpoints do not trust the same CA")
        peer_certificate = _load_certificate(peer.certificate_pem)
        _verify_leaf(
            peer_certificate,
            ca=local_ca,
            expected_san=local.expected_peer_san,
            now=current,
        )
        local_certificate = _load_certificate(local.certificate_pem)
        _verify_leaf(
            local_certificate,
            ca=peer_ca,
            expected_san=peer.expected_peer_san,
            now=current,
        )
        try:
            peer_key = serialization.load_pem_private_key(
                peer.private_key_pem.encode("ascii"),
                password=None,
            )
        except (TypeError, ValueError) as exc:
            raise TLSPolicyError("peer private key is not valid") from exc
        if peer_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != peer_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            raise TLSPolicyError("peer private key does not match its certificate")
        return TLSSession(
            local_role=local.role,
            peer_role=peer.role,
            peer_san=local.expected_peer_san,
            tls_version="TLS1.3",
        )


def verify_session_version(negotiated_version: str) -> str:
    """Normalise and enforce the negotiated TLS version."""
    normalised = negotiated_version.replace("v", "").replace("V", "")
    if normalised not in {"TLS1.3"}:
        raise TLSPolicyError(
            f"the channel negotiated {negotiated_version!r}; TLS 1.3 is required"
        )
    return "TLS1.3"


def verify_live_peer(
    config: TLSConfig,
    *,
    peer_role: str,
    peer_certificate_der: bytes,
    negotiated_version: str,
    now: dt.datetime | None = None,
) -> TLSSession:
    """Validate the certificate a peer presented on a real TLS handshake.

    The check refuses a peer that is not on the role allowlist, negotiated
    anything below TLS 1.3, presented no certificate, or presented a leaf that
    does not chain to the configured CA with the expected role SAN.
    """
    if peer_role not in {"P0", "P1", "P2"}:
        raise TLSPolicyError("peer role is not an SPU node")
    if f"spiffe://a122/{peer_role}" != config.expected_peer_san:
        raise TLSPolicyError("live peer role is outside the configured allowlist")
    version = verify_session_version(negotiated_version)
    if not peer_certificate_der:
        raise TLSPolicyError("the live peer presented no certificate")
    try:
        peer_certificate = x509.load_der_x509_certificate(peer_certificate_der)
    except ValueError as exc:
        raise TLSPolicyError("the live peer certificate is not valid DER") from exc
    current = now or dt.datetime.now(dt.timezone.utc)
    _verify_leaf(
        peer_certificate,
        ca=_load_ca(config.ca_bundle_pem),
        expected_san=config.expected_peer_san,
        now=current,
    )
    return TLSSession(
        local_role=config.role,
        peer_role=peer_role,
        peer_san=config.expected_peer_san,
        tls_version=version,
    )


__all__ = [
    "MockTLSChannel",
    "TLSSession",
    "TLSPolicyError",
    "TLSConfig",
    "verify_live_peer",
    "verify_session_version",
]

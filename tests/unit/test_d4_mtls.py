from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mpc.spu_backend.mtls import (
    MockTLSChannel,
    TLSPolicyError,
    TLSConfig,
)
from mpc.spu_backend.topology import RSSTopology, TopologyError


NOW = dt.datetime(2026, 10, 9, 8, 0, tzinfo=dt.timezone.utc)


def make_identity(role: str, ca_key, ca_cert) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"a122-{role}")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(minutes=1))
        .not_valid_after(NOW + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"spiffe://a122/{role}")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(minutes=1))
        .not_valid_after(NOW + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def config(role: str, *, ca_pem: str, identity: tuple[str, str]) -> TLSConfig:
    return TLSConfig(
        role=role,
        certificate_pem=identity[0],
        private_key_pem=identity[1],
        ca_bundle_pem=ca_pem,
        expected_peer_san=f"spiffe://a122/{'P1' if role == 'P0' else 'P0'}",
    )


def test_mock_mtls_accepts_only_tls13_role_bound_peer() -> None:
    ca_key, ca_cert = make_ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    p0 = config("P0", ca_pem=ca_pem, identity=make_identity("P0", ca_key, ca_cert))
    p1 = config("P1", ca_pem=ca_pem, identity=make_identity("P1", ca_key, ca_cert))
    session = MockTLSChannel.connect(local=p0, peer=p1, now=NOW)
    assert session.tls_version == "TLS1.3"
    assert session.mutual
    with pytest.raises(TLSPolicyError, match="missing"):
        MockTLSChannel.connect(local=p0, peer=None, now=NOW)
    with pytest.raises(TLSPolicyError, match="below"):
        TLSConfig(
            role="P0",
            certificate_pem=p0.certificate_pem,
            private_key_pem=p0.private_key_pem,
            ca_bundle_pem=ca_pem,
            expected_peer_san="spiffe://a122/P1",
            min_version="TLS1.2",
        )
    with pytest.raises(TLSPolicyError, match="builtin"):
        TLSConfig(
            role="P0",
            certificate_pem=p0.certificate_pem,
            private_key_pem=p0.private_key_pem,
            ca_bundle_pem=ca_pem,
            expected_peer_san="spiffe://a122/P1",
            allow_brpc_builtin_services=True,
        )


def test_wrong_ca_wrong_san_and_two_party_topology_are_rejected() -> None:
    first_key, first_ca = make_ca()
    second_key, second_ca = make_ca()
    first_pem = first_ca.public_bytes(serialization.Encoding.PEM).decode("ascii")
    second_pem = second_ca.public_bytes(serialization.Encoding.PEM).decode("ascii")
    p0 = config("P0", ca_pem=first_pem, identity=make_identity("P0", first_key, first_ca))
    p1 = config("P1", ca_pem=second_pem, identity=make_identity("P1", second_key, second_ca))
    with pytest.raises(TLSPolicyError, match="same CA"):
        MockTLSChannel.connect(local=p0, peer=p1, now=NOW)
    wrong_san = TLSConfig(
        role="P1",
        certificate_pem=p1.certificate_pem,
        private_key_pem=p1.private_key_pem,
        ca_bundle_pem=second_pem,
        expected_peer_san="spiffe://a122/P2",
    )
    with pytest.raises(TLSPolicyError, match="allowlist"):
        MockTLSChannel.connect(local=p0, peer=wrong_san, now=NOW)
    with pytest.raises(TopologyError):
        RSSTopology(node_roles=("P0", "P1"))

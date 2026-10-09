from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from kas.app import create_app
from kas.binding import build_report_data
from kas.ca import RELEASE_EXTENSION_OID, CertificateAuthority
from kas.errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
    PolicyRejected,
)
from kas.models import AttestRequest, ChallengeRequest
from kas.policy import PolicyRegistry, ReleaseManifest, VerifiedQuote
from kas.service import KASService


NOW = dt.datetime(2026, 10, 9, 8, 0, tzinfo=dt.timezone.utc)
MRENCLAVE = "11" * 32
MRSIGNER = "22" * 32


def make_release() -> ReleaseManifest:
    return ReleaseManifest.from_dict(
        {
            "release_id": "a122-test-v1",
            "mrenclave": MRENCLAVE,
            "mrsigner": MRSIGNER,
            "min_isvsvn": 3,
            "debug_allowed": False,
            "spu_build_hash": "33" * 32,
            "expires_at": "2027-01-01T00:00:00Z",
        }
    )


def make_ca() -> CertificateAuthority:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return CertificateAuthority(private_key, certificate)


def make_csr() -> tuple[str, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a122-test-node")])
        )
        .sign(private_key, hashes.SHA256())
    )
    public_key_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), public_key_der


@dataclass
class FakeVerifier:
    mrenclave: str
    mrsigner: str
    isvsvn: int
    debug: bool
    report_data: bytes

    def verify(self, quote: bytes) -> VerifiedQuote:
        if quote != b"test-quote":
            raise AttestationRejected("unknown test Quote")
        return VerifiedQuote(
            mrenclave=self.mrenclave,
            mrsigner=self.mrsigner,
            isvsvn=self.isvsvn,
            debug=self.debug,
            report_data=self.report_data,
        )


def make_service(
    *,
    verifier: FakeVerifier | None = None,
    clock=None,
) -> KASService:
    return KASService(
        quote_verifier=verifier
        or FakeVerifier(MRENCLAVE, MRSIGNER, 3, False, b"\x00" * 64),
        policy_registry=PolicyRegistry([make_release()]),
        certificate_authority=make_ca(),
        clock=clock or (lambda: NOW),
    )


def test_attestation_issues_role_bound_p256_certificate() -> None:
    csr_pem, public_key_der = make_csr()
    verifier = FakeVerifier(MRENCLAVE, MRSIGNER, 3, False, b"\x00" * 64)
    service = make_service(verifier=verifier)
    challenge = service.issue_challenge(
        ChallengeRequest(role="P0", release_id="a122-test-v1")
    )
    report_data = build_report_data(
        public_key_der,
        "P0",
        "a122-test-v1",
        bytes.fromhex(challenge.nonce),
    )
    verifier.isvsvn = 4
    verifier.report_data = report_data

    response = service.attest(
        AttestRequest(
            challenge_id=challenge.challenge_id,
            role="P0",
            release_id="a122-test-v1",
            dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
            csr_pem=csr_pem,
        )
    )
    certificate = x509.load_pem_x509_certificate(response.node_certificate_pem.encode())
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        "spiffe://a122/P0"
    ]
    assert certificate.extensions.get_extension_for_oid(
        RELEASE_EXTENSION_OID
    ).value.value == b"a122-test-v1"
    assert response.lease_id


def test_challenge_is_single_use_even_after_failed_attestation() -> None:
    csr_pem, _ = make_csr()
    service = make_service()
    challenge = service.issue_challenge(
        ChallengeRequest(role="P1", release_id="a122-test-v1")
    )
    request = AttestRequest(
        challenge_id=challenge.challenge_id,
        role="P1",
        release_id="a122-test-v1",
        dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
        csr_pem=csr_pem,
    )
    with pytest.raises(AttestationRejected):
        service.attest(request)
    with pytest.raises(ChallengeNotFound):
        service.attest(request)


def test_debug_quote_is_rejected() -> None:
    csr_pem, public_key_der = make_csr()
    verifier = FakeVerifier(MRENCLAVE, MRSIGNER, 3, False, b"\x00" * 64)
    service = make_service(verifier=verifier)
    challenge = service.issue_challenge(
        ChallengeRequest(role="P2", release_id="a122-test-v1")
    )
    report_data = build_report_data(
        public_key_der,
        "P2",
        "a122-test-v1",
        bytes.fromhex(challenge.nonce),
    )
    verifier.debug = True
    verifier.report_data = report_data
    with pytest.raises(PolicyRejected, match="debug"):
        service.attest(
            AttestRequest(
                challenge_id=challenge.challenge_id,
                role="P2",
                release_id="a122-test-v1",
                dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
                csr_pem=csr_pem,
            )
        )


def test_report_data_mismatch_is_rejected() -> None:
    csr_pem, _ = make_csr()
    service = make_service(
        verifier=FakeVerifier(MRENCLAVE, MRSIGNER, 3, False, b"\x01" * 64)
    )
    challenge = service.issue_challenge(
        ChallengeRequest(role="P0", release_id="a122-test-v1")
    )
    with pytest.raises(AttestationRejected, match="REPORTDATA"):
        service.attest(
            AttestRequest(
                challenge_id=challenge.challenge_id,
                role="P0",
                release_id="a122-test-v1",
                dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
                csr_pem=csr_pem,
            )
        )


def test_wrong_measurement_is_rejected() -> None:
    csr_pem, public_key_der = make_csr()
    verifier = FakeVerifier("44" * 32, MRSIGNER, 3, False, b"\x00" * 64)
    service = make_service(verifier=verifier)
    challenge = service.issue_challenge(
        ChallengeRequest(role="P0", release_id="a122-test-v1")
    )
    verifier.report_data = build_report_data(
        public_key_der,
        "P0",
        "a122-test-v1",
        bytes.fromhex(challenge.nonce),
    )
    with pytest.raises(PolicyRejected, match="MRENCLAVE"):
        service.attest(
            AttestRequest(
                challenge_id=challenge.challenge_id,
                role="P0",
                release_id="a122-test-v1",
                dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
                csr_pem=csr_pem,
            )
        )


def test_expired_challenge_is_rejected() -> None:
    clock = [NOW]
    service = make_service(clock=lambda: clock[0])
    challenge = service.issue_challenge(
        ChallengeRequest(role="P0", release_id="a122-test-v1")
    )
    clock[0] = NOW + dt.timedelta(minutes=3)
    with pytest.raises(ChallengeExpired):
        service.attest(
            AttestRequest(
                challenge_id=challenge.challenge_id,
                role="P0",
                release_id="a122-test-v1",
                dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
                csr_pem=make_csr()[0],
            )
        )


def test_fastapi_challenge_endpoint() -> None:
    app = create_app(make_service())
    client = TestClient(app)
    response = client.post(
        "/v1/challenge",
        json={"role": "P0", "release_id": "a122-test-v1"},
    )
    assert response.status_code == 201
    assert len(response.json()["nonce"]) == 64

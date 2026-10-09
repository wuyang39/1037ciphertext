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

from crypto.sm2 import SM2KeyPair
from kas.app import create_app
from kas.binding import build_report_data
from kas.ca import CertificateAuthority
from kas.errors import (
    LeaseRejected,
    TicketAlreadyConsumed,
    TicketBindingRejected,
    TicketExpired,
)
from kas.models import (
    AttestRequest,
    ChallengeRequest,
    ConsumeTicketRequest,
    IssueJobTicketRequest,
)
from kas.policy import PolicyRegistry, ReleaseManifest, VerifiedQuote
from kas.service import KASService
from kas.tickets import verify_job_ticket


NOW = dt.datetime(2026, 10, 9, 8, 0, tzinfo=dt.timezone.utc)
MRENCLAVE = "11" * 32
MRSIGNER = "22" * 32
SESSION_ID = "55" * 32
MODEL_HASH = "66" * 32
PRECISION_HASH = "77" * 32
EPHEMERAL_PUB = SM2KeyPair.from_private_key("09" * 32).public_key


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
    report_data: bytes

    def verify(self, quote: bytes) -> VerifiedQuote:
        if quote != b"test-quote":
            raise ValueError("unexpected quote")
        return VerifiedQuote(
            mrenclave=MRENCLAVE,
            mrsigner=MRSIGNER,
            isvsvn=4,
            debug=False,
            report_data=self.report_data,
        )


def make_service(
    *,
    clock=None,
    ticket_ttl: dt.timedelta = dt.timedelta(minutes=2),
) -> tuple[KASService, SM2KeyPair, FakeVerifier]:
    ticket_key = SM2KeyPair.generate()
    verifier = FakeVerifier(b"\x00" * 64)
    service = KASService(
        quote_verifier=verifier,
        policy_registry=PolicyRegistry([make_release()]),
        certificate_authority=make_ca(),
        ticket_signing_key=ticket_key,
        ticket_ttl=ticket_ttl,
        clock=clock or (lambda: NOW),
    )
    return service, ticket_key, verifier


def acquire_lease(
    service: KASService,
    verifier: FakeVerifier,
    *,
    role: str = "P0",
) -> str:
    csr_pem, public_key_der = make_csr()
    challenge = service.issue_challenge(
        ChallengeRequest(role=role, release_id="a122-test-v1")
    )
    report_data = build_report_data(
        public_key_der,
        role,
        "a122-test-v1",
        bytes.fromhex(challenge.nonce),
    )
    verifier.report_data = report_data
    response = service.attest(
        AttestRequest(
            challenge_id=challenge.challenge_id,
            role=role,
            release_id="a122-test-v1",
            dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
            csr_pem=csr_pem,
        )
    )
    return response.lease_id


def issue_request(*, session_id: str = SESSION_ID) -> IssueJobTicketRequest:
    return IssueJobTicketRequest(
        session_id=session_id,
        node_role="P0",
        release_id="a122-test-v1",
        model_manifest_hash=MODEL_HASH,
        precision_plan_hash=PRECISION_HASH,
        share_epoch=7,
        length_bound=512,
        max_new_tokens=32,
        client_ephemeral_pub=EPHEMERAL_PUB,
    )


def test_ticket_is_signed_bound_and_single_use() -> None:
    service, ticket_key, verifier = make_service()
    lease_id = acquire_lease(service, verifier)
    issued = service.issue_job_ticket(issue_request())
    ticket = verify_job_ticket(issued.model_dump(mode="json"), kas_public_key=ticket_key.public_key)
    assert ticket.session_id == SESSION_ID
    assert ticket.node_role == "P0"

    accepted = service.consume_ticket(
        ConsumeTicketRequest(
            ticket_id=issued.ticket_id,
            enclave_lease_id=lease_id,
            session_id=SESSION_ID,
            counter=1,
        )
    )
    assert accepted.status == "accepted"
    with pytest.raises(TicketAlreadyConsumed):
        service.consume_ticket(
            ConsumeTicketRequest(
                ticket_id=issued.ticket_id,
                enclave_lease_id=lease_id,
                session_id=SESSION_ID,
                counter=1,
            )
        )


def test_expired_forged_and_mismatched_tickets_are_rejected() -> None:
    clock = [NOW]
    service, ticket_key, verifier = make_service(clock=lambda: clock[0])
    lease_id = acquire_lease(service, verifier)
    issued = service.issue_job_ticket(issue_request())
    document = issued.model_dump(mode="json")

    forged = dict(document)
    forged["max_new_tokens"] = 33
    with pytest.raises(TicketBindingRejected):
        verify_job_ticket(forged, kas_public_key=ticket_key.public_key)

    with pytest.raises(TicketBindingRejected, match="session"):
        service.consume_ticket(
            ConsumeTicketRequest(
                ticket_id=issued.ticket_id,
                enclave_lease_id=lease_id,
                session_id="99" * 32,
                counter=1,
            )
        )

    clock[0] = NOW + dt.timedelta(minutes=3)
    with pytest.raises(TicketExpired):
        service.consume_ticket(
            ConsumeTicketRequest(
                ticket_id=issued.ticket_id,
                enclave_lease_id=lease_id,
                session_id=SESSION_ID,
                counter=1,
            )
        )


def test_ticket_requires_a_matching_active_lease() -> None:
    service, _, verifier = make_service()
    other_lease = acquire_lease(service, verifier, role="P1")
    issued = service.issue_job_ticket(issue_request())
    with pytest.raises(LeaseRejected, match="role"):
        service.consume_ticket(
            ConsumeTicketRequest(
                ticket_id=issued.ticket_id,
                enclave_lease_id=other_lease,
                session_id=SESSION_ID,
                counter=1,
            )
        )


def test_ticket_fastapi_surface() -> None:
    service, _, verifier = make_service()
    lease_id = acquire_lease(service, verifier)
    client = TestClient(create_app(service))
    response = client.post(
        "/v1/issue-job-ticket",
        json=issue_request().model_dump(),
    )
    assert response.status_code == 200
    assert response.json()["session_id"] == SESSION_ID
    consume_body = {
        "ticket_id": response.json()["ticket_id"],
        "enclave_lease_id": lease_id,
        "session_id": SESSION_ID,
        "counter": 1,
    }
    assert client.post("/v1/consume-ticket", json=consume_body).status_code == 200
    assert client.post("/v1/consume-ticket", json=consume_body).status_code == 409
    public_key = client.get("/v1/ticket-public-key")
    assert public_key.status_code == 200
    assert len(public_key.json()["public_key"]) == 128

"""Fail-closed KAS attestation state machine."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import secrets
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Protocol

from crypto.sm2 import SM2KeyPair
from crypto.sm3 import hkdf, sm3

from .binding import build_report_data, csr_public_key_der, verify_report_data
from .ca import CertificateAuthority
from .errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
    LeaseRejected,
    StorageKeyRejected,
)
from .models import (
    AttestRequest,
    AttestationResponse,
    ChallengeRequest,
    ChallengeResponse,
    ConsumeTicketRequest,
    ConsumeTicketResponse,
    IssueJobTicketRequest,
    JobTicketResponse,
    ReleaseStorageKeyRequest,
    ReleaseStorageKeyResponse,
    TicketPublicKeyResponse,
)
from .policy import PolicyRegistry, VerifiedQuote
from .tickets import JobTicketLedger


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class QuoteVerifier(Protocol):
    """Production quote verifier boundary."""

    def verify(self, quote: bytes) -> VerifiedQuote:
        """Return verified quote claims or raise AttestationRejected."""


@dataclass(frozen=True)
class _Challenge:
    role: str
    release_id: str
    nonce: bytes
    expires_at: dt.datetime


@dataclass(frozen=True)
class _NodeLease:
    role: str
    release_id: str
    expires_at: dt.datetime


class KASService:
    """Issue one-use challenges and short-lived node credentials."""

    def __init__(
        self,
        *,
        quote_verifier: QuoteVerifier,
        policy_registry: PolicyRegistry,
        certificate_authority: CertificateAuthority,
        ticket_signing_key: SM2KeyPair,
        storage_key_master: bytes | None = None,
        challenge_ttl: dt.timedelta = dt.timedelta(minutes=2),
        node_lease_ttl: dt.timedelta = dt.timedelta(hours=1),
        ticket_ttl: dt.timedelta = dt.timedelta(minutes=5),
        clock: Callable[[], dt.datetime] = utc_now,
    ) -> None:
        self._quote_verifier = quote_verifier
        self._policies = policy_registry
        self._ca = certificate_authority
        self._challenge_ttl = challenge_ttl
        self._node_lease_ttl = node_lease_ttl
        storage_key_master = storage_key_master or secrets.token_bytes(32)
        if len(storage_key_master) < 32:
            raise ValueError("storage_key_master must contain at least 32 bytes")
        self._storage_key_master = bytes(storage_key_master)
        self._clock = clock
        self._challenges: dict[str, _Challenge] = {}
        self._leases: dict[str, _NodeLease] = {}
        self._released_storage_keys: set[tuple[str, int, str]] = set()
        self._storage_key_lock = threading.Lock()
        self._lease_lock = threading.Lock()
        self._tickets = JobTicketLedger(
            signing_key=ticket_signing_key,
            ticket_ttl=ticket_ttl,
            clock=clock,
        )

    def issue_challenge(self, request: ChallengeRequest) -> ChallengeResponse:
        now = self._clock()
        self._policies.get(request.release_id, now=now)
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_bytes(32)
        expires_at = now + self._challenge_ttl
        self._challenges[challenge_id] = _Challenge(
            role=request.role,
            release_id=request.release_id,
            nonce=nonce,
            expires_at=expires_at,
        )
        return ChallengeResponse(
            challenge_id=challenge_id,
            nonce=nonce.hex(),
            expires_at=expires_at,
        )

    def attest(self, request: AttestRequest) -> AttestationResponse:
        now = self._clock()
        challenge = self._challenges.pop(request.challenge_id, None)
        if challenge is None:
            raise ChallengeNotFound("challenge is unknown or already consumed")
        if now >= challenge.expires_at:
            raise ChallengeExpired("challenge has expired")
        if request.role != challenge.role or request.release_id != challenge.release_id:
            raise AttestationRejected("challenge request binding mismatch")

        try:
            quote_bytes = base64.b64decode(request.dcap_quote_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AttestationRejected("DCAP Quote is not valid base64") from exc
        if not quote_bytes:
            raise AttestationRejected("DCAP Quote is empty")

        try:
            public_key_der = csr_public_key_der(request.csr_pem)
        except ValueError as exc:
            raise AttestationRejected(str(exc)) from exc

        verified_quote = self._quote_verifier.verify(quote_bytes)
        self._policies.validate_quote(
            request.release_id,
            verified_quote,
            now=now,
        )
        if not verify_report_data(
            verified_quote.report_data,
            public_key_der,
            request.role,
            request.release_id,
            challenge.nonce,
        ):
            raise AttestationRejected("REPORTDATA does not bind the temporary node key")

        lease_expires_at = now + self._node_lease_ttl
        certificate = self._ca.issue_node_certificate(
            request.csr_pem,
            role=request.role,
            release_id=request.release_id,
            now=now,
            ttl=self._node_lease_ttl,
        )
        lease_id = str(uuid.uuid4())
        with self._lease_lock:
            self._leases[lease_id] = _NodeLease(
                role=request.role,
                release_id=request.release_id,
                expires_at=lease_expires_at,
            )
        return AttestationResponse(
            node_certificate_pem=certificate.certificate_pem,
            ca_bundle_pem=certificate.ca_bundle_pem,
            lease_id=lease_id,
            expires_at=lease_expires_at,
        )

    def issue_job_ticket(self, request: IssueJobTicketRequest) -> JobTicketResponse:
        now = self._clock()
        self._policies.get(request.release_id, now=now)
        ticket = self._tickets.issue(request)
        return JobTicketResponse(**ticket.to_dict())

    def consume_ticket(
        self,
        request: ConsumeTicketRequest,
    ) -> ConsumeTicketResponse:
        self._tickets.consume(
            request,
            lease_check=self._require_active_lease,
        )
        return ConsumeTicketResponse(status="accepted")

    def ticket_public_key(self) -> TicketPublicKeyResponse:
        return TicketPublicKeyResponse(public_key=self._tickets.public_key)

    def release_storage_key(
        self,
        request: ReleaseStorageKeyRequest,
    ) -> ReleaseStorageKeyResponse:
        """Release one purpose-bound key only through an active Lease."""
        lease = self._require_active_lease(
            request.lease_id,
            request.role,
            request.release_id,
        )
        replay_key = (request.lease_id, request.share_epoch, request.purpose)
        with self._storage_key_lock:
            if replay_key in self._released_storage_keys:
                raise StorageKeyRejected(
                    "storage key was already released for this Lease and epoch"
                )
            self._released_storage_keys.add(replay_key)

        context = b"".join(
            (
                b"A1-22:storage-key:v1\0",
                request.role.encode("ascii"),
                b"\0",
                request.release_id.encode("utf-8"),
                b"\0",
                request.share_epoch.to_bytes(8, "big"),
                b"\0",
                request.purpose.encode("ascii"),
            )
        )
        key = hkdf(
            salt=sm3(b"A1-22:storage-key-salt:v1\0"),
            input_key_material=self._storage_key_master,
            info=context,
            length=32,
        )
        key_id = hashlib.sha256(
            b"A1-22:storage-key-id:v1\0" + key
        ).hexdigest()
        return ReleaseStorageKeyResponse(
            key_id=key_id,
            key_hex=key.hex(),
            expires_at=lease.expires_at,
        )

    def _require_active_lease(
        self,
        lease_id: str,
        expected_node_role: str,
        expected_release_id: str,
    ) -> _NodeLease:
        now = self._clock()
        with self._lease_lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise LeaseRejected("enclave Lease is unknown")
            if now >= lease.expires_at:
                self._leases.pop(lease_id, None)
                raise LeaseRejected("enclave Lease has expired")
        if lease.role != expected_node_role:
            raise LeaseRejected("enclave Lease role mismatch")
        if lease.release_id != expected_release_id:
            raise LeaseRejected("enclave Lease release mismatch")
        return lease

    def expected_report_data(self, challenge_id: str, csr_pem: str) -> bytes:
        """Build expected REPORTDATA for enclave-side integration tests."""
        challenge = self._challenges.get(challenge_id)
        if challenge is None:
            raise ChallengeNotFound("challenge is unknown or already consumed")
        return build_report_data(
            csr_public_key_der(csr_pem),
            challenge.role,
            challenge.release_id,
            challenge.nonce,
        )

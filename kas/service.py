"""Fail-closed KAS attestation state machine."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import secrets
import uuid
from dataclasses import dataclass
from typing import Callable, Protocol

from .binding import build_report_data, csr_public_key_der, verify_report_data
from .ca import CertificateAuthority
from .errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
)
from .models import (
    AttestRequest,
    AttestationResponse,
    ChallengeRequest,
    ChallengeResponse,
)
from .policy import PolicyRegistry, VerifiedQuote


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


class KASService:
    """Issue one-use challenges and short-lived node credentials."""

    def __init__(
        self,
        *,
        quote_verifier: QuoteVerifier,
        policy_registry: PolicyRegistry,
        certificate_authority: CertificateAuthority,
        challenge_ttl: dt.timedelta = dt.timedelta(minutes=2),
        node_lease_ttl: dt.timedelta = dt.timedelta(hours=1),
        clock: Callable[[], dt.datetime] = utc_now,
    ) -> None:
        self._quote_verifier = quote_verifier
        self._policies = policy_registry
        self._ca = certificate_authority
        self._challenge_ttl = challenge_ttl
        self._node_lease_ttl = node_lease_ttl
        self._clock = clock
        self._challenges: dict[str, _Challenge] = {}

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
        return AttestationResponse(
            node_certificate_pem=certificate.certificate_pem,
            ca_bundle_pem=certificate.ca_bundle_pem,
            lease_id=str(uuid.uuid4()),
            expires_at=lease_expires_at,
        )

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

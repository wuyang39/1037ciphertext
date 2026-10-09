"""Signed one-use JobTickets and the online consumption ledger."""

from __future__ import annotations

import datetime as dt
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from contracts import canonical_bytes, validate_contract
from crypto.sm2 import (
    SM2Error,
    SM2KeyPair,
    validate_sm2_public_key,
    verify_sm2,
)

from .errors import (
    LeaseRejected,
    TicketAlreadyConsumed,
    TicketBindingRejected,
    TicketExpired,
    TicketNotFound,
)
from .models import ConsumeTicketRequest, IssueJobTicketRequest


def _require_utc(value: dt.datetime, *, name: str) -> dt.datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return value.astimezone(dt.timezone.utc)


def _format_timestamp(value: dt.datetime) -> str:
    return _require_utc(value, name="timestamp").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return _require_utc(dt.datetime.fromisoformat(normalized), name="expiry")
    except ValueError as exc:
        raise TicketBindingRejected("ticket expiry is malformed") from exc


@dataclass(frozen=True)
class JobTicket:
    """Canonical KAS-signed authorization for one session and node role."""

    ticket_id: str
    session_id: str
    node_role: str
    release_id: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    length_bound: int
    max_new_tokens: int
    client_ephemeral_pub: str
    expiry: str
    counter: int
    KAS_signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "session_id": self.session_id,
            "node_role": self.node_role,
            "release_id": self.release_id,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": self.share_epoch,
            "length_bound": self.length_bound,
            "max_new_tokens": self.max_new_tokens,
            "client_ephemeral_pub": self.client_ephemeral_pub,
            "expiry": self.expiry,
            "counter": self.counter,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.unsigned_dict()
        value["KAS_signature"] = self.KAS_signature
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "JobTicket":
        validate_contract("job_ticket", value)
        _parse_timestamp(str(value["expiry"]))
        return cls(
            ticket_id=str(value["ticket_id"]),
            session_id=str(value["session_id"]),
            node_role=str(value["node_role"]),
            release_id=str(value["release_id"]),
            model_manifest_hash=str(value["model_manifest_hash"]),
            precision_plan_hash=str(value["precision_plan_hash"]),
            share_epoch=int(value["share_epoch"]),
            length_bound=int(value["length_bound"]),
            max_new_tokens=int(value["max_new_tokens"]),
            client_ephemeral_pub=str(value["client_ephemeral_pub"]),
            expiry=str(value["expiry"]),
            counter=int(value["counter"]),
            KAS_signature=str(value["KAS_signature"]),
        )


def verify_job_ticket(
    ticket: JobTicket | Mapping[str, Any],
    *,
    kas_public_key: str,
) -> JobTicket:
    """Verify the KAS signature without making an online expiry decision."""
    parsed = ticket if isinstance(ticket, JobTicket) else JobTicket.from_dict(ticket)
    try:
        valid = verify_sm2(
            bytes.fromhex(parsed.KAS_signature),
            canonical_bytes(parsed.unsigned_dict()),
            kas_public_key,
        )
    except (SM2Error, ValueError) as exc:
        raise TicketBindingRejected("JobTicket signature is malformed") from exc
    if not valid:
        raise TicketBindingRejected("JobTicket signature is invalid")
    return parsed


class JobTicketLedger:
    """Online, atomic, one-use ledger; state is never stored only on a node."""

    def __init__(
        self,
        *,
        signing_key: SM2KeyPair,
        ticket_ttl: dt.timedelta = dt.timedelta(minutes=5),
        clock: Callable[[], dt.datetime],
    ) -> None:
        if ticket_ttl <= dt.timedelta(0):
            raise ValueError("ticket_ttl must be positive")
        self._signing_key = signing_key
        self._ticket_ttl = ticket_ttl
        self._clock = clock
        self._tickets: dict[str, JobTicket] = {}
        self._consumed: dict[str, dt.datetime] = {}
        self._lock = threading.Lock()

    @property
    def public_key(self) -> str:
        return self._signing_key.public_key

    def issue(self, request: IssueJobTicketRequest) -> JobTicket:
        now = _require_utc(self._clock(), name="now")
        try:
            client_ephemeral_pub = validate_sm2_public_key(
                request.client_ephemeral_pub
            )
        except SM2Error as exc:
            raise TicketBindingRejected(
                "JobTicket client ephemeral key is invalid"
            ) from exc
        unsigned = {
            "ticket_id": secrets.token_hex(16),
            "session_id": request.session_id,
            "node_role": request.node_role,
            "release_id": request.release_id,
            "model_manifest_hash": request.model_manifest_hash,
            "precision_plan_hash": request.precision_plan_hash,
            "share_epoch": request.share_epoch,
            "length_bound": request.length_bound,
            "max_new_tokens": request.max_new_tokens,
            "client_ephemeral_pub": client_ephemeral_pub,
            "expiry": _format_timestamp(now + self._ticket_ttl),
            "counter": 1,
        }
        signature = self._signing_key.sign(canonical_bytes(unsigned)).hex()
        document = dict(unsigned)
        document["KAS_signature"] = signature
        ticket = JobTicket.from_dict(document)
        with self._lock:
            self._tickets[ticket.ticket_id] = ticket
        return ticket

    def consume(
        self,
        request: ConsumeTicketRequest,
        *,
        lease_check: Callable[[str, str, str], None],
    ) -> JobTicket:
        now = _require_utc(self._clock(), name="now")
        with self._lock:
            ticket = self._tickets.get(request.ticket_id)
            if ticket is None:
                raise TicketNotFound("JobTicket is unknown")
            if ticket.ticket_id in self._consumed:
                raise TicketAlreadyConsumed("JobTicket was already consumed")
            if now >= _parse_timestamp(ticket.expiry):
                raise TicketExpired("JobTicket has expired")
            if request.session_id != ticket.session_id:
                raise TicketBindingRejected("JobTicket session binding mismatch")
            if request.counter != ticket.counter:
                raise TicketBindingRejected("JobTicket counter binding mismatch")
            lease_check(request.enclave_lease_id, ticket.node_role, ticket.release_id)
            self._consumed[ticket.ticket_id] = now
        return ticket

    def ticket(self, ticket_id: str) -> JobTicket:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFound("JobTicket is unknown")
        return ticket


def assert_ticket_matches_session(
    ticket: JobTicket,
    *,
    session_id: str,
    node_role: str,
    model_manifest_hash: str,
    precision_plan_hash: str,
    share_epoch: int,
    client_ephemeral_pub: str,
    now: dt.datetime,
) -> None:
    """Reject a ticket before it can authorize any MPC entry."""
    if now.astimezone(dt.timezone.utc) >= _parse_timestamp(ticket.expiry):
        raise TicketExpired("JobTicket has expired")
    checks = {
        "session_id": (ticket.session_id, session_id),
        "node_role": (ticket.node_role, node_role),
        "model_manifest_hash": (
            ticket.model_manifest_hash,
            model_manifest_hash,
        ),
        "precision_plan_hash": (
            ticket.precision_plan_hash,
            precision_plan_hash,
        ),
        "share_epoch": (ticket.share_epoch, share_epoch),
        "client_ephemeral_pub": (
            ticket.client_ephemeral_pub,
            client_ephemeral_pub,
        ),
    }
    for name, (actual, expected) in checks.items():
        if actual != expected:
            raise TicketBindingRejected(f"JobTicket {name} binding mismatch")


def require_active_lease(
    *,
    active: bool,
    role: str,
    release_id: str,
    expected_role: str,
    expected_release_id: str,
) -> None:
    """Small fail-closed helper shared by the KAS service."""
    if not active:
        raise LeaseRejected("enclave Lease is missing or expired")
    if role != expected_role:
        raise LeaseRejected("enclave Lease role mismatch")
    if release_id != expected_release_id:
        raise LeaseRejected("enclave Lease release mismatch")

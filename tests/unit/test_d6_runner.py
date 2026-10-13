"""The D6 client runner: what it builds before it dials a node."""

from __future__ import annotations

import datetime as dt

from client.d6_runner import build_ledger
from crypto.sm2 import SM2KeyPair
from kas.models import IssueJobTicketRequest
from kas.tickets import verify_job_ticket


def _request() -> IssueJobTicketRequest:
    return IssueJobTicketRequest(
        session_id="00" * 32,
        node_role="P0",
        release_id="local",
        model_manifest_hash="11" * 32,
        precision_plan_hash="22" * 32,
        share_epoch=0,
        length_bound=8,
        max_new_tokens=3,
        client_ephemeral_pub=SM2KeyPair.generate().public_key,
    )


def test_the_runner_ledger_issues_a_ticket_that_verifies() -> None:
    """The ledger needs an explicit clock, and the clock has to be real UTC.

    A node compares the ticket expiry against its own wall clock, so a runner
    that froze time or left the argument out would fail every handshake.
    """
    signing_key = SM2KeyPair.generate()
    ledger = build_ledger({"kas_signing_private_key": signing_key.private_key})
    ticket = ledger.issue(_request())
    verified = verify_job_ticket(ticket, kas_public_key=signing_key.public_key)
    assert verified.ticket_id == ticket.ticket_id
    expiry = dt.datetime.fromisoformat(ticket.expiry.replace("Z", "+00:00"))
    assert expiry > dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)

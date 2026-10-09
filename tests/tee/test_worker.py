from __future__ import annotations

import datetime as dt

import pytest

from crypto.sm2 import SM2KeyPair
from kas.models import IssueJobTicketRequest
from kas.tickets import JobTicketLedger
from tee.storage import ActiveLease, StorageKey
from tee.worker import ProtectedWorker, WorkerRejected, WorkerStartup


NOW = dt.datetime(2030, 1, 1, 8, 0, tzinfo=dt.timezone.utc)
MODEL_HASH = "11" * 32
PLAN_HASH = "22" * 32
SESSION_ID = "33" * 32


def make_ticket():
    key = SM2KeyPair.generate()
    ledger = JobTicketLedger(signing_key=key, clock=lambda: NOW)
    ticket = ledger.issue(
        IssueJobTicketRequest(
            session_id=SESSION_ID,
            node_role="P0",
            release_id="a122-test-v1",
            model_manifest_hash=MODEL_HASH,
            precision_plan_hash=PLAN_HASH,
            share_epoch=7,
            length_bound=64,
            max_new_tokens=2,
            client_ephemeral_pub=SM2KeyPair.from_private_key("09" * 32).public_key,
        )
    )
    return key.public_key, ticket


def test_worker_fails_closed_until_lease_key_and_ticket_are_valid() -> None:
    public_key, ticket = make_ticket()
    storage_key = StorageKey(key_id="44" * 32, key=b"k" * 32)
    startup = WorkerStartup(
        role="P0",
        release_id="a122-test-v1",
        model_version="tiny-v1",
        model_manifest_hash=MODEL_HASH,
        precision_plan_hash=PLAN_HASH,
        share_epoch=7,
        expected_storage_key_id=storage_key.key_id,
    )
    worker = ProtectedWorker(
        startup=startup,
        kas_public_key=public_key,
        inference_fn=lambda _ticket, share: b"result:" + share,
        clock=lambda: NOW,
    )
    with pytest.raises(WorkerRejected, match="did not complete"):
        worker.run_inference(ticket, b"share")
    with pytest.raises(WorkerRejected, match="does not match"):
        worker.start(
            lease=ActiveLease(
                "lease",
                "P0",
                "a122-test-v1",
                7,
                NOW + dt.timedelta(minutes=10),
            ),
            storage_key=StorageKey(key_id="55" * 32, key=b"x" * 32),
        )
    worker.start(
        lease=ActiveLease(
            "lease",
            "P0",
            "a122-test-v1",
            7,
            NOW + dt.timedelta(minutes=10),
        ),
        storage_key=storage_key,
    )
    assert worker.run_inference(ticket, b"share") == b"result:share"
    worker.close()
    with pytest.raises(WorkerRejected, match="closed"):
        worker.run_inference(ticket, b"share")

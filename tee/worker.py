"""Strict Worker startup and the single fixed inference entry point."""

from __future__ import annotations

import datetime as dt
import threading
from dataclasses import dataclass
from typing import Callable

from kas.tickets import JobTicket, assert_ticket_matches_session, verify_job_ticket

from crypto.enclave_key import worker_startup_digest

from .storage import ActiveLease, StorageKey


class WorkerRejected(RuntimeError):
    """The Worker cannot start or accept the requested inference."""


@dataclass(frozen=True)
class WorkerStartup:
    """Immutable values measured and bound before Worker code is loaded."""

    role: str
    release_id: str
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    expected_storage_key_id: str

    def digest(self) -> str:
        return worker_startup_digest(
            role=self.role,
            release_id=self.release_id,
            model_version=self.model_version,
            model_manifest_hash=self.model_manifest_hash,
            precision_plan_hash=self.precision_plan_hash,
            share_epoch=self.share_epoch,
            expected_storage_key_id=self.expected_storage_key_id,
        )


class ProtectedWorker:
    """A Worker that exposes only ``run_inference(ticket, input_share)``."""

    def __init__(
        self,
        *,
        startup: WorkerStartup,
        kas_public_key: str,
        inference_fn: Callable[[JobTicket, bytes], bytes],
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self._startup = startup
        self._kas_public_key = kas_public_key
        self._inference_fn = inference_fn
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._started = False
        self._closed = False
        self._lock = threading.Lock()

    @property
    def started(self) -> bool:
        return self._started

    @property
    def closed(self) -> bool:
        return self._closed

    def start(self, *, lease: ActiveLease, storage_key: StorageKey) -> None:
        """Start only with an active matching Lease and released key."""
        if self._started:
            raise WorkerRejected("Worker has already started")
        try:
            lease.require_active(
                now=self._clock(),
                role=self._startup.role,
                release_id=self._startup.release_id,
                share_epoch=self._startup.share_epoch,
            )
        except ValueError as exc:
            raise WorkerRejected(str(exc)) from exc
        if storage_key.key_id != self._startup.expected_storage_key_id:
            raise WorkerRejected("released storage key does not match the release")
        with self._lock:
            self._started = True

    def run_inference(self, ticket: JobTicket, input_share: bytes) -> bytes:
        """Validate a JobTicket and invoke the fixed, measured graph only."""
        if self._closed:
            raise WorkerRejected("Worker is closed")
        if not self._started:
            raise WorkerRejected("Worker did not complete protected startup")
        if not isinstance(ticket, JobTicket):
            raise WorkerRejected("run_inference requires a parsed JobTicket")
        if not isinstance(input_share, bytes):
            raise WorkerRejected("input_share must be an opaque byte sequence")
        if len(input_share) > ticket.length_bound:
            raise WorkerRejected("input_share exceeds the JobTicket length bound")
        try:
            verify_job_ticket(ticket, kas_public_key=self._kas_public_key)
            assert_ticket_matches_session(
                ticket,
                session_id=ticket.session_id,
                node_role=self._startup.role,
                model_manifest_hash=self._startup.model_manifest_hash,
                precision_plan_hash=self._startup.precision_plan_hash,
                share_epoch=self._startup.share_epoch,
                client_ephemeral_pub=ticket.client_ephemeral_pub,
                now=self._clock(),
            )
        except ValueError as exc:
            raise WorkerRejected(str(exc)) from exc
        result = self._inference_fn(ticket, input_share)
        if not isinstance(result, bytes):
            raise WorkerRejected("fixed inference graph must return bytes")
        return result

    def close(self) -> None:
        """Irreversibly close the Worker so no later request can execute."""
        with self._lock:
            self._closed = True
            self._started = False


__all__ = ["ProtectedWorker", "WorkerRejected", "WorkerStartup"]

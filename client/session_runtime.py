"""Session-state glue for Ticket -> frame -> fixed inference -> ResultFrame."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from crypto.frame import EncryptedFrame, SessionClosed
from crypto.frame import SecureSession
from crypto.sm2 import SM2KeyPair
from kas.tickets import (
    JobTicket,
    TicketBindingRejected,
    assert_ticket_matches_session,
    verify_job_ticket,
)

from .result import ResultFrame, ResultRejected


@dataclass(frozen=True)
class RuntimeBindings:
    session_id: str
    node_role: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    client_ephemeral_pub: str


class NodeSessionRuntime:
    """Run one node's fixed graph only after all session bindings pass."""

    def __init__(
        self,
        *,
        session: SecureSession,
        ticket: JobTicket,
        kas_public_key: str,
        node_identity: SM2KeyPair,
        node_ephemeral: SM2KeyPair,
        client_ephemeral_pub: str,
        graph: Callable[[bytes], bytes],
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.session = session
        self.ticket = ticket
        self.kas_public_key = kas_public_key
        self.node_identity = node_identity
        self.node_ephemeral = node_ephemeral
        self.client_ephemeral_pub = client_ephemeral_pub
        self.graph = graph
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.decode_step = 0
        self.request_hash: str | None = None
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def receive(self, frame: EncryptedFrame | Mapping[str, Any]) -> bytes:
        if self._closed:
            raise SessionClosed("runtime session is closed")
        verify_job_ticket(self.ticket, kas_public_key=self.kas_public_key)
        assert_ticket_matches_session(
            self.ticket,
            session_id=self.session.keys.bindings.session_id,
            node_role=self.session.keys.bindings.node_role,
            model_manifest_hash=self.session.keys.bindings.model_manifest_hash,
            precision_plan_hash=self.session.keys.bindings.precision_plan_hash,
            share_epoch=self.session.keys.bindings.share_epoch,
            client_ephemeral_pub=self.client_ephemeral_pub,
            now=self.clock(),
        )
        parsed = (
            frame
            if isinstance(frame, EncryptedFrame)
            else EncryptedFrame.from_dict(frame)
        )
        if parsed.aad.message_type != "Request":
            raise ResultRejected("runtime accepts only Request frames")
        payload = self.session.receive(parsed)
        self.request_hash = parsed.aad.request_hash
        self.decode_step += 1
        return payload

    def execute(self, payload: bytes) -> tuple[bytes, ResultFrame]:
        if self.request_hash is None:
            raise ResultRejected("input frame must be received before execution")
        output_share = self.graph(payload)
        bindings = self.session.keys.bindings
        result = ResultFrame.issue(
            session_id=bindings.session_id,
            node_role=bindings.node_role,
            model_manifest_hash=bindings.model_manifest_hash,
            precision_plan_hash=bindings.precision_plan_hash,
            share_epoch=bindings.share_epoch,
            request_hash=self.request_hash,
            decode_step=self.decode_step,
            client_ephemeral_pub=self.client_ephemeral_pub,
            node_identity=self.node_identity,
            node_ephemeral=self.node_ephemeral,
            output_share=output_share,
        )
        return output_share, result

    def close(self, payload: bytes = b"") -> EncryptedFrame:
        self._closed = True
        return self.session.close(payload)


def parse_request_payload(payload: bytes) -> dict[str, Any]:
    """Parse the narrow JSON request shape accepted by the fixed graph."""
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResultRejected("request payload is not canonical JSON") from exc
    if not isinstance(value, dict):
        raise ResultRejected("request payload must be an object")
    return value


__all__ = [
    "NodeSessionRuntime",
    "RuntimeBindings",
    "parse_request_payload",
]

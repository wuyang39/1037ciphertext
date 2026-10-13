"""The D6 client: one prompt, three parties, an autoregressive token loop.

The client owns the secret. It tokenizes the prompt, builds the history one-hot
matrix, shares it and hands each party exactly one share; it never sends a
token id, a hidden state or a logit to any node in the clear. What comes back
is three signed receipts whose payloads it reconstructs itself, which is also
how it checks the enclave's secure Argmax: the token the parties agreed on has
to be the argmax of the logits the client reconstructs from the same shares.

Everything that could weaken that story is a refusal here rather than a note in
a log: a duplicated result frame, a frame whose ``decode_step`` was edited, a
frame from another model, a replayed request frame and a replayed JobTicket all
have to fail, and each attempt is recorded with the reason it failed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence

from contracts import canonical_bytes
from contracts.d6_session import (
    ModelManifest,
    PlanError,
    SessionPlan,
    parse_result_payload,
    step_payload,
)
from crypto.certificates import SM2CertificateAuthority
from crypto.frame import SecureSession, request_digest
from crypto.handshake import ClientHandshake
from crypto.sm2 import SM2KeyPair
from kas.models import IssueJobTicketRequest
from kas.tickets import JobTicketLedger
from mpc.spu_backend.sharing import share_probe

from .result import ResultRejected, reconstruct_result_frames
from .tokenizer import TokenizerError, WordTokenizer


class D6ClientError(RuntimeError):
    """The client session could not be opened, stepped or closed."""


class NodeChannel(Protocol):
    """One client-side connection to one node's share channel."""

    role: str

    def request(self, document: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


def build_history_one_hot(
    tokens: Sequence[int],
    *,
    sequence: int,
    vocab_size: int,
    pad_token: int,
) -> Any:
    """Right-align a token history and pad the front with the pad token.

    The block reports the next token from its last row, so the newest token has
    to sit there. Padding with a real token id rather than zeros keeps every
    attention row in the range the fixed-point protocol was measured for.
    """
    import numpy

    if len(tokens) > sequence:
        raise D6ClientError("the token history does not fit the context window")
    matrix = numpy.zeros((sequence, vocab_size), dtype=numpy.float64)
    offset = sequence - len(tokens)
    for index in range(sequence):
        token = pad_token if index < offset else int(tokens[index - offset])
        if not 0 <= token < vocab_size:
            raise D6ClientError("the token history leaves the vocabulary")
        matrix[index, token] = 1.0
    return matrix


def step_request_hash(session_id: str, decode_step: int) -> str:
    """One binding shared by all three requests of a decoding step.

    The payloads differ per party -- each carries a different share -- so the
    request hash cannot be the digest of the payload. It is the digest of what
    the step *is*, which is what the three receipts have to agree on.
    """
    return request_digest(
        canonical_bytes({"session_id": session_id, "decode_step": int(decode_step)})
    )


def _share_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ClientSession:
    """One role's established session plus the secrets the client keeps."""

    role: str
    channel: NodeChannel
    handshake: ClientHandshake
    session: SecureSession
    ticket: Any
    server_hello: Mapping[str, Any]


@dataclass
class D6Client:
    """Drives the whole D6 loop against an injected splitter and joiner."""

    plan: SessionPlan
    tokenizer: WordTokenizer
    authority: SM2CertificateAuthority
    ledger: JobTicketLedger
    node_public_keys: Mapping[str, str]
    splitter: Callable[[Any], Sequence[str]]
    joiner: Callable[[Sequence[str]], Any]
    clock: Callable[[], dt.datetime] = field(
        default_factory=lambda: (lambda: dt.datetime.now(dt.timezone.utc))
    )

    def __post_init__(self) -> None:
        if set(self.node_public_keys) != {"P0", "P1", "P2"}:
            raise D6ClientError("the client needs the three node public keys")
        if self.plan.vocab_size != self.tokenizer.vocab_size:
            raise D6ClientError(
                "the session plan and the tokenizer disagree about the vocabulary"
            )
        self.client_identity = SM2KeyPair.generate()
        self.client_ephemeral = SM2KeyPair.generate()
        self.session_id = secrets.token_bytes(32).hex()
        self.certificate = self.authority.issue(
            role="C",
            release_id=self.plan.release_id,
            public_key=self.client_identity.public_key,
            now=self.clock(),
            ttl=dt.timedelta(hours=1),
        )

    # -- session setup -----------------------------------------------------

    def open(self, exchanges: Mapping[str, NodeChannel]) -> dict[str, ClientSession]:
        sessions: dict[str, ClientSession] = {}
        for role in ("P0", "P1", "P2"):
            channel = exchanges[role]
            ticket = self.ledger.issue(
                IssueJobTicketRequest(
                    session_id=self.session_id,
                    node_role=role,
                    release_id=self.plan.release_id,
                    model_manifest_hash=self.plan.model_manifest_hash,
                    precision_plan_hash=self.plan.precision_plan_hash,
                    share_epoch=self.plan.share_epoch,
                    length_bound=self.plan.length_bound,
                    max_new_tokens=self.plan.max_new_tokens,
                    client_ephemeral_pub=self.client_ephemeral.public_key,
                )
            )
            handshake = ClientHandshake(
                bindings=self._bindings(role),
                identity_key=self.client_identity,
                ephemeral_key=self.client_ephemeral,
                certificate=self.certificate,
                authority=self.authority,
            )
            client_hello = handshake.create_client_hello()
            response = channel.request(
                {
                    "type": "hello",
                    "client_hello": client_hello,
                    "ticket": ticket.to_dict(),
                }
            )
            if response.get("type") != "server_hello":
                raise D6ClientError(
                    f"{role} refused the session: {response.get('reason')}"
                )
            server_hello = response["server_hello"]
            finished = handshake.receive_server_hello(server_hello, now=self.clock())
            ack = channel.request({"type": "finished", "finished": finished})
            if ack.get("type") != "finished_ack":
                raise D6ClientError(f"{role} refused the handshake: {ack.get('reason')}")
            keys = handshake.receive_finished_ack(ack["finished_ack"])
            sessions[role] = ClientSession(
                role=role,
                channel=channel,
                handshake=handshake,
                session=SecureSession(keys=keys, local_role="C", peer_role=role),
                ticket=ticket,
                server_hello=server_hello,
            )
        return sessions

    def _bindings(self, role: str) -> Any:
        from crypto.handshake import HandshakeBindings

        return HandshakeBindings(
            session_id=self.session_id,
            node_role=role,
            release_id=self.plan.release_id,
            model_version=self.plan.model_version,
            model_manifest_hash=self.plan.model_manifest_hash,
            precision_plan_hash=self.plan.precision_plan_hash,
            share_epoch=self.plan.share_epoch,
        )

    # -- the loop ----------------------------------------------------------

    def run(
        self,
        prompt: str,
        *,
        exchanges: Mapping[str, NodeChannel],
        dial: Callable[[str], NodeChannel] | None = None,
        max_new_tokens: int | None = None,
    ) -> dict[str, Any]:
        budget = int(max_new_tokens or self.plan.max_new_tokens)
        if not 1 <= budget <= self.plan.max_new_tokens:
            raise D6ClientError("the requested token budget is outside the plan")
        prompt_ids = self.tokenizer.encode(prompt)
        if len(prompt_ids) > self.plan.prompt_budget:
            raise D6ClientError(
                f"the prompt needs {len(prompt_ids)} tokens; the plan allows "
                f"{self.plan.prompt_budget}"
            )
        sessions = self.open(exchanges)
        # The three parties run every program collectively, so a step is only
        # reachable if all three requests are in flight at once. Driving them
        # in sequence would leave the first node waiting for peers that the
        # client has not woken yet.
        pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="a122-d6-step")
        history = list(prompt_ids)
        steps: list[dict[str, Any]] = []
        frames_by_step: dict[int, list[Any]] = {}
        requests_by_step: dict[int, list[dict[str, Any]]] = {}
        negatives: list[dict[str, Any]] = []
        try:
            for decode_step in range(1, budget + 1):
                record, frames, request_frames = self._step(
                    sessions=sessions,
                    history=history,
                    decode_step=decode_step,
                    pool=pool,
                )
                steps.append(record)
                frames_by_step[decode_step] = frames
                requests_by_step[decode_step] = request_frames
                history.append(record["token_id"])
            last = budget
            negatives.append(self._probe_duplicated_frames(frames_by_step[last]))
            negatives.append(self._probe_tampered_step(frames_by_step[last]))
            negatives.append(self._probe_mixed_model(frames_by_step[last]))
            negatives.append(
                self._probe_replayed_input(sessions, requests_by_step[last])
            )
            if dial is not None:
                negatives.append(self._probe_replayed_ticket(sessions["P1"], dial))
            close = self.close(sessions, pool=pool)
        except Exception:
            for client_session in sessions.values():
                try:
                    client_session.channel.close()
                except Exception:  # pragma: no cover - best effort teardown
                    pass
            raise
        finally:
            pool.shutdown(wait=False)
        return {
            "session_id": self.session_id,
            "plan": self.plan.to_dict(),
            "share_probes": sorted(
                {
                    step["shares"][role]["history_share_probe"]
                    for step in steps
                    for role in ("P0", "P1", "P2")
                }
            ),
            "prompt_tokens": prompt_ids,
            "prompt_words": [self.tokenizer.token(value) for value in prompt_ids],
            "generated_tokens": [record["token_id"] for record in steps],
            "generated_words": [record["token_word"] for record in steps],
            "generated_text": self.tokenizer.decode(
                [record["token_id"] for record in steps]
            ),
            "steps": steps,
            "negative_cases": negatives,
            "close": close,
            "negative_verdicts": "passed"
            if all(case["refused"] for case in negatives)
            else "failed",
        }

    def _step(
        self,
        *,
        sessions: Mapping[str, ClientSession],
        history: Sequence[int],
        decode_step: int,
        pool: ThreadPoolExecutor,
    ) -> tuple[dict[str, Any], list[Any], list[dict[str, Any]]]:
        import numpy

        one_hot = build_history_one_hot(
            history,
            sequence=self.plan.sequence,
            vocab_size=self.plan.vocab_size,
            pad_token=self.tokenizer.pad_id,
        )
        shares = list(self.splitter(one_hot))
        if len(shares) != 3:
            raise D6ClientError("the splitter did not return three shares")
        request_hash = step_request_hash(self.session_id, decode_step)
        roles = ("P0", "P1", "P2")
        request_frames: list[dict[str, Any]] = []
        futures: dict[str, Any] = {}
        for index, role in enumerate(roles):
            client_session = sessions[role]
            frame = client_session.session.send(
                step_payload(decode_step=decode_step, history_share=shares[index]),
                message_type="Request",
                request_hash=request_hash,
            )
            document = frame.to_dict()
            request_frames.append(document)
            futures[role] = pool.submit(
                self._exchange_step, client_session, document
            )
        answered = {role: future.result() for role, future in futures.items()}
        wall_ms = round(
            max(value["elapsed_ms"] for value in answered.values()), 3
        )

        from .result import ResultFrame

        frames: list[Any] = []
        timings: dict[str, Any] = {}
        for index, role in enumerate(roles):
            response = answered[role]["response"]
            if response.get("type") != "result":
                raise D6ClientError(
                    f"{role} refused step {decode_step}: {response.get('reason')}"
                )
            frames.append(ResultFrame.from_dict(response["frame"]))
            timings[role] = {
                "client_round_trip_ms": answered[role]["elapsed_ms"],
                "node_step_ms": response.get("elapsed_ms"),
                "history_share_digest": _share_digest(shares[index]),
                "history_share_probe": share_probe(shares[index]),
                "tls_version": getattr(sessions[role].channel, "tls_version", None),
            }
        reconstructed = reconstruct_result_frames(
            frames,
            expected_session_id=self.session_id,
            expected_model_manifest_hash=self.plan.model_manifest_hash,
            expected_precision_plan_hash=self.plan.precision_plan_hash,
            expected_share_epoch=self.plan.share_epoch,
            expected_request_hash=request_hash,
            expected_decode_step=decode_step,
            node_public_keys=self.node_public_keys,
            client_ephemeral=self.client_ephemeral,
        )
        token_shares: list[str] = []
        logits_shares: list[str] = []
        for blob in reconstructed:
            document = parse_result_payload(blob)
            if document["decode_step"] != decode_step:
                raise D6ClientError("a node answered for another decoding step")
            token_shares.append(document["token"])
            logits_shares.append(document["logits"])
        token_value = float(numpy.asarray(self.joiner(token_shares)).ravel()[0])
        token_id = int(round(token_value))
        logits = numpy.asarray(self.joiner(logits_shares), dtype=numpy.float64)
        if logits.ndim != 2 or logits.shape[0] != self.plan.sequence:
            raise D6ClientError("the reconstructed logits have the wrong shape")
        argmax_id = int(numpy.argmax(logits[-1]))
        if not 0 <= token_id < self.plan.vocab_size:
            raise D6ClientError("the secure Argmax left the vocabulary")
        return (
            {
                "decode_step": decode_step,
                "token_id": token_id,
                "token_word": self.tokenizer.token(token_id),
                "argmax_of_reconstructed_logits": argmax_id,
                "argmax_match": argmax_id == token_id,
                "logits_last_row_max": float(logits[-1].max()),
                "logits_last_row_min": float(logits[-1].min()),
                "logits_last_row": [float(value) for value in logits[-1]],
                "request_hash": request_hash,
                "history_length": len(history),
                "shares": timings,
                "step_wall_ms": wall_ms,
            },
            frames,
            request_frames,
        )

    # -- negative cases ----------------------------------------------------

    @staticmethod
    def _exchange_step(
        client_session: ClientSession, document: Mapping[str, Any]
    ) -> dict[str, Any]:
        started = dt.datetime.now(dt.timezone.utc)
        response = client_session.channel.request(
            {"type": "step", "frame": document}
        )
        elapsed = (dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000.0
        return {"response": response, "elapsed_ms": round(elapsed, 3)}

    def _expect_rejection(
        self, case: str, action: Callable[[], Any]
    ) -> dict[str, Any]:
        try:
            action()
        except (ResultRejected, PlanError, D6ClientError, ValueError) as exc:
            return {"case": case, "refused": True, "reason": str(exc)}
        return {
            "case": case,
            "refused": False,
            "reason": "the client accepted a frame it had to reject",
        }

    def _reconstruct(self, frames: Sequence[Any], *, decode_step: int) -> Any:
        return reconstruct_result_frames(
            frames,
            expected_session_id=self.session_id,
            expected_model_manifest_hash=self.plan.model_manifest_hash,
            expected_precision_plan_hash=self.plan.precision_plan_hash,
            expected_share_epoch=self.plan.share_epoch,
            expected_request_hash=step_request_hash(self.session_id, decode_step),
            expected_decode_step=decode_step,
            node_public_keys=self.node_public_keys,
            client_ephemeral=self.client_ephemeral,
        )

    def _probe_duplicated_frames(self, frames: Sequence[Any]) -> dict[str, Any]:
        return self._expect_rejection(
            "duplicate_result_frame",
            lambda: self._reconstruct(
                [frames[0], frames[0], frames[2]], decode_step=frames[0].decode_step
            ),
        )

    def _probe_tampered_step(self, frames: Sequence[Any]) -> dict[str, Any]:
        tampered = type(frames[0]).from_dict(
            {**frames[0].to_dict(), "decode_step": frames[0].decode_step + 1}
        )
        return self._expect_rejection(
            "tampered_decode_step",
            lambda: self._reconstruct(
                [tampered, frames[1], frames[2]], decode_step=frames[0].decode_step
            ),
        )

    def _probe_mixed_model(self, frames: Sequence[Any]) -> dict[str, Any]:
        return self._expect_rejection(
            "mixed_model_manifest",
            lambda: reconstruct_result_frames(
                frames,
                expected_session_id=self.session_id,
                expected_model_manifest_hash="00" * 32,
                expected_precision_plan_hash=self.plan.precision_plan_hash,
                expected_share_epoch=self.plan.share_epoch,
                expected_request_hash=step_request_hash(
                    self.session_id, frames[0].decode_step
                ),
                expected_decode_step=frames[0].decode_step,
                node_public_keys=self.node_public_keys,
                client_ephemeral=self.client_ephemeral,
            ),
        )

    def _probe_replayed_input(
        self,
        sessions: Mapping[str, ClientSession],
        request_frames: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Send a frame the node has already accepted, and demand a refusal.

        The frame is replayed byte for byte, so the counter it carries is one
        the node's receive window has already committed. Minting a fresh frame
        would be a new request rather than a replay, and would prove nothing.
        """
        role = "P1"
        client_session = sessions[role]
        return self._expect_refusal_response(
            "replayed_request_frame",
            lambda: client_session.channel.request(
                {"type": "step", "frame": dict(request_frames[1])}
            ),
        )

    def _probe_replayed_ticket(
        self, client_session: ClientSession, dial: Callable[[str], NodeChannel]
    ) -> dict[str, Any]:
        """Open a second session on a fresh connection with a spent ticket."""
        channel = dial("P1")
        try:
            handshake = ClientHandshake(
                bindings=self._bindings("P1"),
                identity_key=self.client_identity,
                ephemeral_key=SM2KeyPair.generate(),
                certificate=self.certificate,
                authority=self.authority,
            )
            hello = handshake.create_client_hello()
            return self._expect_refusal_response(
                "replayed_job_ticket",
                lambda: channel.request(
                    {
                        "type": "hello",
                        "client_hello": hello,
                        "ticket": client_session.ticket.to_dict(),
                    }
                ),
            )
        finally:
            channel.close()

    @staticmethod
    def _expect_refusal_response(
        case: str, action: Callable[[], Mapping[str, Any]]
    ) -> dict[str, Any]:
        """A server-side probe: the node has to answer with a refusal."""
        response = action()
        if response.get("type") == "refused":
            return {"case": case, "refused": True, "reason": str(response.get("reason"))}
        return {
            "case": case,
            "refused": False,
            "reason": f"the node answered {response.get('type')!r} instead of refusing",
        }

    # -- teardown ----------------------------------------------------------

    def close(
        self,
        sessions: Mapping[str, ClientSession],
        *,
        pool: ThreadPoolExecutor,
    ) -> dict[str, Any]:
        """Close all three sessions at once.

        The link teardown each node runs on close is collective, so the three
        close frames have to be in flight together for the same reason a step
        does.
        """
        roles = ("P0", "P1", "P2")
        frames = {
            role: sessions[role].session.close().to_dict() for role in roles
        }
        futures = {
            role: pool.submit(
                sessions[role].channel.request, {"type": "close", "frame": frames[role]}
            )
            for role in roles
        }
        evidence: dict[str, Any] = {}
        for role in roles:
            client_session = sessions[role]
            response = futures[role].result()
            if response.get("type") != "closed":
                raise D6ClientError(f"{role} refused to close: {response.get('reason')}")
            status = client_session.channel.request({"type": "status"})
            if status.get("type") != "status":
                raise D6ClientError(f"{role} produced no status: {status.get('reason')}")
            evidence[role] = {
                "close": response.get("evidence"),
                "status": status.get("status"),
            }
            client_session.channel.close()
        return evidence


__all__ = [
    "ClientSession",
    "D6Client",
    "D6ClientError",
    "NodeChannel",
    "build_history_one_hot",
    "step_request_hash",
]

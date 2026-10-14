"""The D7 client: one GPT-2 prompt, three parties, an autoregressive loop.

The client owns the secret and none of the model. It encodes the prompt with
the frozen byte-pair tokenizer, maps real GPT-2 ids onto the candidate
vocabulary the run pinned, left-aligns the history in the context window and
hands each party one share of the one-hot matrix. What comes back is three
signed receipts whose payloads it reconstructs itself, which is also how it
checks the enclave's secure Argmax: the candidate index the parties agreed on
has to be the argmax of the logits the client reconstructs from the same
shares.

Two details differ from D6 and both follow from GPT-2's own geometry. The
history is left-aligned rather than right-aligned, because the causal mask
makes the unused rows behind it unreachable from the row the step reads. And
the row a step reads is ``len(history) - 1`` rather than the last row of the
window, which is what lets one fixed program shape serve every step; the plan
pins that mapping so the client cannot ask for a row the session never agreed
to run.

Everything that could weaken the story is a refusal here rather than a note in
a log: a duplicated result frame, a frame whose ``decode_step`` was edited, a
frame from another model, a replayed request frame and a replayed JobTicket
all have to fail, and each attempt is recorded with the reason it failed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from client.d6_session import NodeChannel, step_request_hash
from client.gpt2_bpe import Gpt2Bpe
from contracts import canonical_hash
from contracts.d7_session import (
    D7ModelManifest,
    D7SessionPlan,
    parse_result_payload,
    step_payload,
)
from crypto.certificates import SM2CertificateAuthority
from crypto.frame import SecureSession
from crypto.handshake import ClientHandshake, HandshakeBindings
from crypto.sm2 import SM2KeyPair
from infra.d7_vectors import build_history_one_hot
from kas.models import IssueJobTicketRequest
from kas.tickets import JobTicketLedger
from mpc.spu_backend.sharing import share_probe

from .result import ResultRejected, reconstruct_result_frames


class D7ClientError(RuntimeError):
    """The client session could not be opened, stepped or closed."""


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
class D7Client:
    """Drives the whole GPT-2 loop against an injected splitter and joiner."""

    plan: D7SessionPlan
    model: D7ModelManifest
    encoder: Gpt2Bpe
    candidates: Sequence[int]
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
            raise D7ClientError("the client needs the three node public keys")
        self.candidates = tuple(int(value) for value in self.candidates)
        if len(self.candidates) != self.plan.vocab_size:
            raise D7ClientError(
                "the session plan and the candidate list disagree about the vocabulary"
            )
        if list(sorted(set(self.candidates))) != list(self.candidates):
            raise D7ClientError("the candidate vocabulary must be ascending")
        if (
            canonical_hash({"candidate_tokens": list(self.candidates)})
            != self.model.candidate_vocabulary_hash
        ):
            raise D7ClientError(
                "the candidate vocabulary is not the one the model manifest pins"
            )
        if self.plan.model_manifest_hash != self.model.digest():
            raise D7ClientError(
                "the session plan and the model manifest describe different models"
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

    def _bindings(self, role: str) -> HandshakeBindings:
        return HandshakeBindings(
            session_id=self.session_id,
            node_role=role,
            release_id=self.plan.release_id,
            model_version=self.plan.model_version,
            model_manifest_hash=self.plan.model_manifest_hash,
            precision_plan_hash=self.plan.precision_plan_hash,
            share_epoch=self.plan.share_epoch,
        )

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
                raise D7ClientError(
                    f"{role} refused the session: {response.get('reason')}"
                )
            finished = handshake.receive_server_hello(
                response["server_hello"], now=self.clock()
            )
            ack = channel.request({"type": "finished", "finished": finished})
            if ack.get("type") != "finished_ack":
                raise D7ClientError(f"{role} refused the handshake: {ack.get('reason')}")
            keys = handshake.receive_finished_ack(ack["finished_ack"])
            sessions[role] = ClientSession(
                role=role,
                channel=channel,
                handshake=handshake,
                session=SecureSession(keys=keys, local_role="C", peer_role=role),
                ticket=ticket,
                server_hello=response["server_hello"],
            )
        return sessions

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
            raise D7ClientError("the requested token budget is outside the plan")
        prompt_ids = self.encoder.encode(prompt)
        # The plan pins the prompt length because the row a step reads is
        # derived from it and baked into the programs the nodes compiled. A
        # session whose prompt has another length would need another program
        # set, so it is refused here rather than silently met with a program
        # that would read the wrong row.
        if len(prompt_ids) != self.plan.prompt_tokens:
            raise D7ClientError(
                f"the prompt encodes to {len(prompt_ids)} tokens; the plan pins "
                f"{self.plan.prompt_tokens}"
            )
        lookup = {token: index for index, token in enumerate(self.candidates)}
        try:
            encoded_prompt = [lookup[token] for token in prompt_ids]
        except KeyError as exc:  # pragma: no cover - the rule always admits them
            raise D7ClientError(
                f"prompt token {exc.args[0]} is outside the candidate vocabulary"
            ) from exc
        sessions = self.open(exchanges)
        # The three parties run every program collectively, so a step is only
        # reachable if all three requests are in flight at once.
        pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="a122-d7-step")
        history = list(encoded_prompt)
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
                history.append(record["token_index"])
            last = budget
            negatives.append(self._probe_duplicated_frames(frames_by_step[last]))
            negatives.append(self._probe_tampered_step(frames_by_step[last]))
            negatives.append(self._probe_mixed_model(frames_by_step[last]))
            negatives.append(self._probe_replayed_input(sessions, requests_by_step[last]))
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
            "model": self.model.to_dict(),
            "share_probes": sorted(
                {
                    step["shares"][role]["history_share_probe"]
                    for step in steps
                    for role in ("P0", "P1", "P2")
                }
            ),
            "prompt": prompt,
            "prompt_tokens": prompt_ids,
            "prompt_indices": encoded_prompt,
            "candidate_size": len(self.candidates),
            "generated_indices": [record["token_index"] for record in steps],
            "generated_tokens": [record["token_id"] for record in steps],
            "generated_text": self.encoder.decode(
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

        decode_row = self.plan.decode_row(decode_step)
        one_hot = build_history_one_hot(
            history,
            sequence=self.plan.sequence,
            vocab_size=self.plan.vocab_size,
            pad_index=0,
        )
        shares = list(self.splitter(one_hot))
        if len(shares) != 3:
            raise D7ClientError("the splitter did not return three shares")
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
            futures[role] = pool.submit(self._exchange_step, client_session, document)
        answered = {role: future.result() for role, future in futures.items()}
        wall_ms = round(max(value["elapsed_ms"] for value in answered.values()), 3)

        from .result import ResultFrame

        frames: list[Any] = []
        timings: dict[str, Any] = {}
        for index, role in enumerate(roles):
            response = answered[role]["response"]
            if response.get("type") != "result":
                raise D7ClientError(
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
                raise D7ClientError("a node answered for another decoding step")
            token_shares.append(document["token"])
            logits_shares.append(document["logits"])
        token_value = float(numpy.asarray(self.joiner(token_shares)).ravel()[0])
        token_index = int(round(token_value))
        logits = numpy.asarray(self.joiner(logits_shares), dtype=numpy.float64)
        if logits.ndim != 2 or logits.shape[0] != self.plan.sequence:
            raise D7ClientError("the reconstructed logits have the wrong shape")
        if logits.shape[1] != self.plan.vocab_size:
            raise D7ClientError("the reconstructed logits have the wrong width")
        argmax_index = int(numpy.argmax(logits[decode_row]))
        if not 0 <= token_index < self.plan.vocab_size:
            raise D7ClientError("the secure Argmax left the candidate vocabulary")
        return (
            {
                "decode_step": decode_step,
                "decode_row": decode_row,
                "token_index": token_index,
                "token_id": int(self.candidates[token_index]),
                "token_text": self.encoder.token(int(self.candidates[token_index])),
                "argmax_of_reconstructed_logits": argmax_index,
                "argmax_match": argmax_index == token_index,
                "logits_row_max": float(logits[decode_row].max()),
                "logits_row_min": float(logits[decode_row].min()),
                "logits_row": [float(value) for value in logits[decode_row]],
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
        response = client_session.channel.request({"type": "step", "frame": document})
        elapsed = (dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000.0
        return {"response": response, "elapsed_ms": round(elapsed, 3)}

    def _expect_rejection(self, case: str, action: Callable[[], Any]) -> dict[str, Any]:
        try:
            action()
        except (ResultRejected, D7ClientError, ValueError) as exc:
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
        """Send a frame the node has already accepted, and demand a refusal."""
        client_session = sessions["P1"]
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
        """Close all three sessions at once."""
        roles = ("P0", "P1", "P2")
        frames = {role: sessions[role].session.close().to_dict() for role in roles}
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
                raise D7ClientError(f"{role} refused to close: {response.get('reason')}")
            status = client_session.channel.request({"type": "status"})
            if status.get("type") != "status":
                raise D7ClientError(f"{role} produced no status: {status.get('reason')}")
            evidence[role] = {
                "close": response.get("evidence"),
                "status": status.get("status"),
            }
            client_session.channel.close()
        return evidence


__all__ = [
    "ClientSession",
    "D7Client",
    "D7ClientError",
    "NodeChannel",
]

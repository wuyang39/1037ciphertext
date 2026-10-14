"""D6 enclave node: one SPU party serving a private autoregressive session.

D5 drove a fixed case grid from P0. D6 puts a real client in front of the same
three parties: the client tokenizes a prompt, shares its history one-hot matrix
and asks each node for one decoding step at a time, and the nodes run the fused
embedding-plus-decoder-block program collectively until the client closes the
session.

Three things live here that D5 did not have:

* the client-facing session, whose ``NodeHandshake``/``JobTicket``/frame state
  machine decides whether a step may run at all;
* a session KV cache that keeps this party's share of every step and is
  overwritten and re-checked before the node will call the session closed;
* a per-step state spill under the session directory, so the cleanup the
  acceptance measures is a real overwrite of real bytes rather than a claim.

The node refuses to guess: a step whose payload disagrees with the frame's
``decode_step``, a ticket that does not cover the requested token budget, a
replayed frame or a frame for another session all end the session with a typed
refusal, and the refusal is written into the node status.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping, Sequence

from client.session_runtime import NodeSessionRuntime
from contracts.d6_session import (
    NODE_CONFIG_VERSION,
    ModelManifest,
    PlanError,
    SessionPlan,
    parse_step_payload,
    result_payload,
)
from crypto.certificates import SM2Certificate, SM2CertificateAuthority
from crypto.frame import EncryptedFrame, SecureSession
from crypto.handshake import HandshakeBindings, NodeHandshake
from crypto.sm2 import SM2KeyPair
from infra.evidence import write_json
from kas.tickets import JobTicket, assert_ticket_matches_session, verify_job_ticket
from mpc.secure_ops.kv_cache import SecureKVCache
from mpc.spu_backend.d5_program import D5Config, SpuProgram
from mpc.spu_backend.d6_program import build_step_program
from mpc.spu_backend.program_runtime import SpuProgramRuntime
from mpc.spu_backend.spu_link import (
    CLIENT_VERIFY_DEPTH,
    SERVER_VERIFY_DEPTH,
    NodeIdentity,
    SpuBackendError,
    SpuEndpoint,
    SpuLinkPolicy,
    decode_share,
    encode_share,
    load_libspu,
    verify_peer_certificates,
)
from mpc.spu_backend.transport import (
    TLSChannelClosed,
    TLSChannelError,
    TLSFrameChannel,
    TLSIdentity,
)
from tee.enclave.node_common import (
    NodeError,
    decode_document,
    encode_document,
    log,
    runtime_label,
    serve_share_channel,
)


READY_MARKER = "A122-D6-NODE-READY"
DONE_MARKER = "A122-D6-NODE-DONE"
REFUSED_MARKER = "A122-D6-NODE-REFUSED"
CLIENT_ROLE = "C"
# The share bundle the offline dealer produced for this party. Every value is
# one additive share of the tiny decoder's weights; the node never sees the
# table, only its own slice of it.
SPILL_MARKER = "kv"


class D6NodeError(NodeError):
    """The D6 node could not start or could not serve its session."""


@dataclass(frozen=True)
class SessionPrograms:
    """The program set one node hosts and how a decoding step selects from it.

    D6 runs one fixed-shape step program for the whole session, so the default
    mapping answers every step with the same name. D7 bakes the row it predicts
    from into each program, so a step has to name the program built for its own
    context length; everything else about the node -- the handshake, the
    ticket, the spill and the wipe -- is unchanged.
    """

    programs: tuple[SpuProgram, ...]
    program_for_step: Callable[[int], str]
    kv_max_layers: int = 1

    def __post_init__(self) -> None:
        if not self.programs:
            raise D6NodeError("a node needs at least one program")
        names = [program.name for program in self.programs]
        if len(set(names)) != len(names):
            raise D6NodeError("program names must be unique")
        if self.kv_max_layers <= 0:
            raise D6NodeError("the KV cache needs at least one layer")

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(program.name for program in self.programs)

    @property
    def weight_tensors(self) -> tuple[str, ...]:
        """Every secret input the node has to hold a share of."""
        found: list[str] = []
        for program in self.programs:
            for name in program.input_names:
                if name != "history" and name not in found:
                    found.append(name)
        return tuple(found)

    def name_for_step(self, decode_step: int) -> str:
        name = self.program_for_step(int(decode_step))
        if name not in set(self.names):
            raise D6NodeError(f"no program is bound to decoding step {decode_step}")
        return name

    @classmethod
    def fixed(cls, program: SpuProgram) -> "SessionPrograms":
        return cls(
            programs=(program,),
            program_for_step=lambda step: program.name,
            kv_max_layers=1,
        )


@dataclass(frozen=True)
class SessionPayloads:
    """The two payload shapes one session speaks, as callables.

    The node's frame handling does not care which phase it is serving; only the
    protocol tag and the field names of the step and result payloads differ, so
    they are injected rather than branched on inside the state machine.
    """

    parse_step: Callable[[bytes], dict[str, Any]]
    result: Callable[..., bytes]

    @classmethod
    def d6(cls) -> "SessionPayloads":
        return cls(parse_step=parse_step_payload, result=result_payload)


@dataclass(frozen=True)
class D6NodeConfig:
    """Everything one D6 node needs, already validated by the orchestrator."""

    # A phase that speaks its own config version and plan subclasses this and
    # overrides the two; the field set and the validator stay shared.
    CONFIG_VERSION: ClassVar[str] = NODE_CONFIG_VERSION

    run_id: str
    role: str
    partition_id: str
    endpoints: tuple[SpuEndpoint, ...]
    identity: NodeIdentity
    peer_certificates: dict[str, Path]
    share_host: str
    share_port: int
    out_dir: Path
    plan: SessionPlan
    model: ModelManifest
    weights_path: Path
    sm2_private_key: str
    sm2_certificate: dict[str, Any]
    kas_public_key: str
    client_authority_public_key: str
    session_dir: Path
    seed: int
    present_client_certificate: bool = True
    enable_ssl: bool = True
    server_verify_depth: int = SERVER_VERIFY_DEPTH
    client_verify_depth: int = CLIENT_VERIFY_DEPTH
    connect_retry_times: int = 120
    connect_retry_interval_ms: int = 500
    spill_session_state: bool = True

    @staticmethod
    def plan_from_dict(document: Mapping[str, Any]) -> Any:
        return SessionPlan.from_dict(document)

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "D6NodeConfig":
        try:
            if document.get("config_version") != cls.CONFIG_VERSION:
                raise D6NodeError("unknown node configuration version")
            identity_document = document["identity"]
            return cls(
                run_id=str(document["run_id"]),
                role=str(document["role"]),
                partition_id=str(document["partition_id"]),
                endpoints=tuple(
                    SpuEndpoint(
                        role=str(entry["role"]),
                        host=str(entry["host"]),
                        port=int(entry["port"]),
                    )
                    for entry in document["endpoints"]
                ),
                identity=NodeIdentity(
                    role=str(identity_document["role"]),
                    certificate_path=Path(identity_document["certificate"]),
                    private_key_path=Path(identity_document["private_key"]),
                    ca_bundle_path=Path(identity_document["ca_bundle"]),
                ),
                peer_certificates={
                    str(role): Path(path)
                    for role, path in (document.get("peer_certificates") or {}).items()
                },
                share_host=str(document["share_channel"]["host"]),
                share_port=int(document["share_channel"]["port"]),
                out_dir=Path(document["out_dir"]),
                plan=cls.plan_from_dict(document["plan"]),
                model=ModelManifest.from_dict(document["model"]),
                weights_path=Path(document["weights"]),
                sm2_private_key=str(document["sm2_identity"]["private_key"]),
                sm2_certificate=dict(document["sm2_certificate"]),
                kas_public_key=str(document["kas_public_key"]),
                client_authority_public_key=str(
                    document["client_authority_public_key"]
                ),
                session_dir=Path(document["session_dir"]),
                seed=int(document.get("seed", 0)),
                present_client_certificate=bool(
                    document.get("present_client_certificate", True)
                ),
                enable_ssl=bool(document.get("enable_ssl", True)),
                server_verify_depth=int(
                    document.get("server_verify_depth", SERVER_VERIFY_DEPTH)
                ),
                client_verify_depth=int(
                    document.get("client_verify_depth", CLIENT_VERIFY_DEPTH)
                ),
                connect_retry_times=int(document.get("connect_retry_times", 120)),
                connect_retry_interval_ms=int(
                    document.get("connect_retry_interval_ms", 500)
                ),
                spill_session_state=bool(
                    document.get("spill_session_state", True)
                ),
            )
        except D6NodeError:
            raise
        except (KeyError, TypeError, ValueError, PlanError) as exc:
            raise D6NodeError(f"the node configuration is malformed: {exc}") from exc

    @property
    def peer_roles(self) -> tuple[str, ...]:
        return tuple(
            endpoint.role for endpoint in self.endpoints if endpoint.role != self.role
        )

    def policy(self) -> SpuLinkPolicy:
        return SpuLinkPolicy(
            role=self.role,
            endpoints=self.endpoints,
            enable_ssl=self.enable_ssl,
            server_verify_depth=self.server_verify_depth,
            client_verify_depth=self.client_verify_depth,
            partition_id=self.partition_id,
            connect_retry_times=self.connect_retry_times,
            connect_retry_interval_ms=self.connect_retry_interval_ms,
        )

    def share_identity(self) -> TLSIdentity:
        """The party's own share-channel identity.

        Only the client ever dials this channel, so the allowlist names exactly
        one peer role instead of the node mesh D5 used.
        """
        return TLSIdentity(
            role=self.role,
            certificate_pem=self.identity.certificate_path.read_text(encoding="ascii"),
            private_key_pem=self.identity.private_key_path.read_text(encoding="ascii"),
            ca_bundle_pem=self.identity.ca_bundle_path.read_text(encoding="ascii"),
            allowed_peer_roles=(CLIENT_ROLE,),
        )

    def handshake_bindings(self, session_id: str) -> HandshakeBindings:
        return HandshakeBindings(
            session_id=session_id,
            node_role=self.role,
            release_id=self.plan.release_id,
            model_version=self.plan.model_version,
            model_manifest_hash=self.plan.model_manifest_hash,
            precision_plan_hash=self.plan.precision_plan_hash,
            share_epoch=self.plan.share_epoch,
        )


def load_weight_shares(path: Path) -> dict[str, str]:
    """Read this party's slice of the model.

    The file holds one encoded SPU share per tensor. It carries no shape and no
    plaintext value, so a node that reads it still cannot name a single weight.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise D6NodeError(f"the weight share bundle is unreadable: {exc}") from exc
    tensors = document.get("tensors") if isinstance(document, dict) else None
    if not isinstance(tensors, dict) or not tensors:
        raise D6NodeError("the weight share bundle carries no tensors")
    if not all(isinstance(value, str) for value in tensors.values()):
        raise D6NodeError("a weight share is not an encoded share")
    return {str(name): str(value) for name, value in tensors.items()}


def _share_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SessionState:
    """The enclave-side state of exactly one client session."""

    def __init__(
        self,
        *,
        config: D6NodeConfig,
        runner: SpuProgramRuntime,
        weight_shares: Mapping[str, str],
        programs: SessionPrograms | None = None,
        payloads: SessionPayloads | None = None,
        clock: Callable[[], dt.datetime] | None = None,
        ticket_registry: set[str] | None = None,
    ) -> None:
        self.config = config
        self.runner = runner
        self.weight_shares = dict(weight_shares)
        # ``None`` means the caller put the D6 step program into the runtime
        # itself -- the in-process session tests do exactly that -- so the
        # default the node keeps is the single program name D6 has always used.
        self.programs = programs
        self.payloads = payloads or SessionPayloads.d6()
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.identity_key = SM2KeyPair.from_private_key(config.sm2_private_key)
        self.certificate = SM2Certificate.from_dict(config.sm2_certificate)
        if self.certificate.role != config.role:
            raise D6NodeError("the SM2 certificate names another role")
        if self.certificate.public_key != self.identity_key.public_key:
            raise D6NodeError("the SM2 certificate does not bind the identity key")
        self.authority = SM2CertificateAuthority.verifier(
            config.client_authority_public_key
        )
        self.cache = SecureKVCache(
            max_layers=(programs.kv_max_layers if programs else 1),
            max_tokens=config.plan.max_new_tokens + 1,
        )
        self.handshake: NodeHandshake | None = None
        self.runtime: NodeSessionRuntime | None = None
        self.ephemeral: SM2KeyPair | None = None
        self.session_id: str | None = None
        self.ticket: JobTicket | None = None
        self.ticket_hash: str | None = None
        self.steps: list[dict[str, Any]] = []
        self.refusals: list[dict[str, Any]] = []
        self.opened_at: str | None = None
        self.closed = False
        self.close_evidence: dict[str, Any] = {}
        self.teardown_finished: bool | None = None
        self.spilled_files: list[Path] = []
        self.spilled_probes: list[str] = []
        self.session_hash: str | None = None
        self.ticket_registry = ticket_registry if ticket_registry is not None else set()

    # -- session lifecycle -------------------------------------------------

    def hello(
        self,
        *,
        message: Mapping[str, Any],
        ticket_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self.handshake is not None:
            raise D6NodeError("the session has already been opened")
        ticket = verify_job_ticket(
            ticket_document, kas_public_key=self.config.kas_public_key
        )
        # The online ledger owns the one-use decision; the node additionally
        # refuses a ticket it has already accepted, so replaying an accepted
        # ticket on a second connection cannot open a second session here.
        if ticket.ticket_id in self.ticket_registry:
            raise D6NodeError("the JobTicket has already been accepted by this node")
        session_id = str(message.get("session_id"))
        client_ephemeral_pub = str(message.get("client_ephemeral_pub"))
        # Fail before any key agreement: a ticket that does not name this
        # session, this role and this client key never reaches the MPC entry.
        assert_ticket_matches_session(
            ticket,
            session_id=session_id,
            node_role=self.config.role,
            model_manifest_hash=self.config.plan.model_manifest_hash,
            precision_plan_hash=self.config.plan.precision_plan_hash,
            share_epoch=self.config.plan.share_epoch,
            client_ephemeral_pub=client_ephemeral_pub,
            now=self.clock(),
        )
        self.ticket = ticket
        self.ticket_registry.add(ticket.ticket_id)
        self.ticket_hash = hashlib.sha256(
            json.dumps(ticket.to_dict(), sort_keys=True).encode("utf-8")
        ).hexdigest()
        bindings = self.config.handshake_bindings(session_id)
        ephemeral = SM2KeyPair.generate()
        handshake = NodeHandshake(
            bindings=bindings,
            identity_key=self.identity_key,
            ephemeral_key=ephemeral,
            certificate=self.certificate,
            authority=self.authority,
        )
        server_hello = handshake.receive_client_hello(message, now=self.clock())
        self.handshake = handshake
        self.ephemeral = ephemeral
        self.session_id = session_id
        self.client_ephemeral_pub = client_ephemeral_pub
        self.opened_at = self.clock().isoformat()
        return server_hello

    def finish(self, *, message: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.handshake is None:
            raise D6NodeError("the handshake has not started")
        if self.ephemeral is None or self.session_id is None or self.ticket is None:
            raise D6NodeError("the session is not ready to finish")
        ack, keys = self.handshake.receive_finished(message)
        session = SecureSession(keys=keys, local_role=self.config.role, peer_role=CLIENT_ROLE)
        self.runtime = NodeSessionRuntime(
            session=session,
            ticket=self.ticket,
            kas_public_key=self.config.kas_public_key,
            node_identity=self.identity_key,
            node_ephemeral=self.ephemeral,
            client_ephemeral_pub=self.client_ephemeral_pub,
            graph=self._graph,
            clock=self.clock,
        )
        self.session_hash = session.session_hash
        return ack, {
            "session_hash": session.session_hash,
            "tls_version": keys.bindings.protocol_version,
        }

    def _graph(self, payload: bytes) -> bytes:
        """Run one decoding step and return this party's result payload."""
        document = self.payloads.parse_step(payload)
        if self.runtime is None:
            raise D6NodeError("the session runtime is missing")
        token_budget = self.ticket.max_new_tokens if self.ticket else 0
        if document["decode_step"] > token_budget:
            raise D6NodeError("the step exceeds the JobTicket token budget")
        if len(payload) > (self.ticket.length_bound if self.ticket else 0):
            raise D6NodeError("the step exceeds the JobTicket length bound")
        history = document["history"]
        inputs: dict[str, Any] = {
            name: decode_share(self.runner.libspu, value)
            for name, value in self.weight_shares.items()
        }
        inputs["history"] = decode_share(self.runner.libspu, history)
        started = time.monotonic()
        outputs = self.runner.run(
            program=(
                self.programs.name_for_step(int(document["decode_step"]))
                if self.programs is not None
                else "step"
            ),
            inputs=inputs,
        )
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        hidden_share = encode_share(outputs["hidden"])
        token_share = encode_share(outputs["token"])
        logits_share = encode_share(outputs["logits"])
        spill = self._spill(step=document["decode_step"], hidden_share=hidden_share)
        self.cache.append_buffer(
            layer=0,
            label=f"step-{document['decode_step']}",
            shape=(self.config.plan.sequence, self.config.plan.hidden_size),
            data=hidden_share.encode("utf-8"),
        )
        self.steps.append(
            {
                "decode_step": int(document["decode_step"]),
                "history_share_digest": _share_digest(history),
                "token_share_digest": _share_digest(token_share),
                "hidden_share_digest": _share_digest(hidden_share),
                "logits_share_digest": _share_digest(logits_share),
                "elapsed_ms": elapsed_ms,
                "spilled": spill,
            }
        )
        return self.payloads.result(
            decode_step=int(document["decode_step"]),
            token_share=token_share,
            logits_share=logits_share,
        )

    # -- session state on disk --------------------------------------------

    def _spill(self, *, step: int, hidden_share: str) -> bool:
        """Stage this step's share on the session filesystem.

        The path is what the cleanup proof has to remove; a session with
        nothing on disk would make the post-close scan vacuous.
        """
        if not self.config.spill_session_state:
            return False
        directory = self.config.session_dir / SPILL_MARKER
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"step-{step:04d}.share"
        path.write_text(hidden_share, encoding="utf-8", newline="\n")
        self.spilled_files.append(path)
        from mpc.spu_backend.sharing import share_probe

        self.spilled_probes.append(share_probe(hidden_share))
        return True

    def close(self, *, reason: str) -> dict[str, Any]:
        """Wipe the session and report what the wipe actually did."""
        if self.closed:
            return dict(self.close_evidence)
        overwritten = 0
        for path in self.spilled_files:
            if path.is_file():
                size = path.stat().st_size
                path.write_bytes(b"\0" * size)
                overwritten += size
                path.unlink()
        if self.config.session_dir.exists():
            shutil.rmtree(self.config.session_dir, ignore_errors=True)
        self.cache.wipe()
        self.cache.assert_empty()
        self.cache.assert_scrubbed()
        keys_wiped = 0
        if self.runtime is not None:
            keys_wiped = self.runtime.session.wipe()
        self.closed = True
        self.close_evidence = {
            "reason": reason,
            "closed_at": self.clock().isoformat(),
            "steps": len(self.steps),
            "spilled_files": len(self.spilled_files),
            "spilled_bytes_overwritten": overwritten,
            "spilled_probes": list(self.spilled_probes),
            "session_dir_removed": not self.config.session_dir.exists(),
            "session_keys_wiped_bytes": keys_wiped,
            "kv": self.cache.wipe_record,
        }
        return dict(self.close_evidence)

    def status(self, *, transport: str, inside_enclave: bool) -> dict[str, Any]:
        return {
            "run_id": self.config.run_id,
            "role": self.config.role,
            "partition_id": self.config.partition_id,
            "opened_at": self.opened_at,
            "closed": self.closed,
            "steps": self.steps,
            "refusals": self.refusals,
            "close_evidence": self.close_evidence,
            "teardown_finished": self.teardown_finished,
            "ticket_sha256": self.ticket_hash,
            "session_dir": str(self.config.session_dir),
            "spill_enabled": self.config.spill_session_state,
            "transport": transport,
            "inside_enclave": inside_enclave,
            "plan_manifest": {
                "model_manifest_hash": self.config.plan.model_manifest_hash,
                "precision_plan_hash": self.config.plan.precision_plan_hash,
                "share_epoch": self.config.plan.share_epoch,
                "release_id": self.config.plan.release_id,
            },
        }


def _refusal(state: SessionState | None, kind: str, exc: BaseException) -> dict[str, Any]:
    """Record a typed refusal so the acceptance can point at a reason."""
    reason = f"{type(exc).__name__}: {exc}"
    if state is not None:
        state.refusals.append({"message": kind, "reason": reason})
    return {"type": "refused", "reason": reason}


def _serve(
    config: D6NodeConfig,
    runner: SpuProgramRuntime,
    weight_shares: Mapping[str, str],
    programs: SessionPrograms,
    payloads: SessionPayloads,
    holder: dict[str, Any],
    stop_event: threading.Event,
    served: dict[str, int],
) -> Any:
    identity = config.share_identity()

    def handler(channel: TLSFrameChannel) -> None:
        state: SessionState | None = None
        while not stop_event.is_set():
            try:
                request = decode_document(channel.receive_frame())
            except TLSChannelClosed:
                return
            except (TLSChannelError, NodeError):
                return
            kind = str(request.get("type"))
            try:
                if kind == "ping":
                    reply: dict[str, Any] = {
                        "type": "pong",
                        "role": config.role,
                        "tls_version": channel.tls_version,
                    }
                elif kind == "shutdown":
                    channel.send_frame(
                        encode_document({"type": "bye", "role": config.role})
                    )
                    stop_event.set()
                    return
                elif kind == "hello":
                    if state is not None:
                        raise D6NodeError("a session is already open")
                    # The candidate is only published as the session once its
                    # ticket and hello have both been accepted. A refused
                    # hello -- a replayed JobTicket arrives this way -- must not
                    # replace the session the node will report on at shutdown.
                    candidate = SessionState(
                        config=config,
                        runner=runner,
                        weight_shares=weight_shares,
                        programs=programs,
                        payloads=payloads,
                        ticket_registry=holder["tickets"],
                    )
                    server_hello = candidate.hello(
                        message=request["client_hello"],
                        ticket_document=request["ticket"],
                    )
                    state = candidate
                    holder["session"] = state
                    reply = {"type": "server_hello", "server_hello": server_hello}
                elif kind == "finished":
                    if state is None:
                        raise D6NodeError("no session is open")
                    ack, facts = state.finish(message=request["finished"])
                    reply = {"type": "finished_ack", "finished_ack": ack, **facts}
                elif kind == "step":
                    if state is None or state.runtime is None:
                        raise D6NodeError("no session is open")
                    started = time.monotonic()
                    frame = EncryptedFrame.from_dict(request["frame"])
                    payload = state.runtime.receive(frame)
                    _output_share, result = state.runtime.execute(payload)
                    served["steps"] += 1
                    reply = {
                        "type": "result",
                        "frame": result.to_dict(),
                        "decode_step": result.decode_step,
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    }
                elif kind == "close":
                    if state is None or state.runtime is None:
                        raise D6NodeError("no session is open")
                    frame = EncryptedFrame.from_dict(request["frame"])
                    state.runtime.accept_close(frame)
                    evidence = state.close(reason="client-close")
                    channel.send_frame(
                        encode_document({"type": "closed", "evidence": evidence})
                    )
                    # The link teardown is collective, so it runs after the
                    # client has its acknowledgement rather than inside it.
                    state.teardown_finished = runner.stop()
                    continue
                elif kind == "status":
                    if state is None:
                        raise D6NodeError("no session has been opened")
                    transport, inside_enclave = runtime_label()
                    reply = {
                        "type": "status",
                        "status": state.status(
                            transport=transport, inside_enclave=inside_enclave
                        ),
                    }
                else:
                    raise D6NodeError(f"unknown message type {kind!r}")
            except Exception as exc:  # noqa: BLE001 - reported to the client
                # A refusal on a connection that never opened a session -- the
                # replayed-ticket probe dials a second one -- still belongs in
                # the record of the session the node is serving.
                reply = _refusal(
                    state if state is not None else holder.get("session"), kind, exc
                )
            channel.send_frame(encode_document(reply))

    return serve_share_channel(
        identity=identity,
        host=config.share_host,
        port=config.share_port,
        handler=handler,
        threaded=True,
        connection_timeout=900.0,
    )


def block_config(config: D6NodeConfig) -> D5Config:
    """The D5 geometry the D6 step program is built for."""
    return D5Config(
        sequence=config.plan.sequence,
        hidden_size=config.plan.hidden_size,
        num_heads=config.plan.num_heads,
        intermediate_size=config.plan.intermediate_size,
        vocab_size=config.plan.vocab_size,
        fractional_bits=config.plan.fractional_bits,
    )


def run_node(
    config: D6NodeConfig,
    *,
    programs: SessionPrograms | None = None,
    payloads: SessionPayloads | None = None,
    session_timeout: float = 1800.0,
) -> int:
    config.out_dir.mkdir(parents=True, exist_ok=True)
    policy = config.policy()
    peer_fingerprints = verify_peer_certificates(
        policy,
        config.peer_certificates,
        ca_bundle_path=config.identity.ca_bundle_path,
    )
    libspu, _ = load_libspu()
    programs = programs or SessionPrograms.fixed(build_step_program(block_config(config)))
    payloads = payloads or SessionPayloads.d6()
    weight_shares = load_weight_shares(config.weights_path)
    expected = set(programs.weight_tensors)
    missing = sorted(expected - set(weight_shares))
    if missing:
        raise D6NodeError(
            "the weight share bundle is missing: " + ", ".join(missing)
        )
    runner = SpuProgramRuntime(
        libspu=libspu,
        policy=policy,
        identity=config.identity,
        programs=list(programs.programs),
        fraction_bits=config.plan.fractional_bits,
        present_client_certificate=config.present_client_certificate,
    )
    stop_event = threading.Event()
    holder: dict[str, Any] = {"session": None, "tickets": set()}
    served = {"steps": 0}
    # A stale session directory is removed before the link starts, so the
    # post-close scan can only find what this session wrote.
    if config.session_dir.exists():
        shutil.rmtree(config.session_dir, ignore_errors=True)
    server = _serve(
        config, runner, weight_shares, programs, payloads, holder, stop_event, served
    )

    started = time.monotonic()
    runner.start()
    link_seconds = round(time.monotonic() - started, 3)
    log(
        f"{READY_MARKER} "
        + json.dumps(
            {
                "run_id": config.run_id,
                "role": config.role,
                "rank": policy.rank,
                "programs": list(programs.names),
                "kv_max_layers": programs.kv_max_layers,
                "share_port": config.share_port,
                "identity_sha256": runner.identity_fingerprint["sha256"],
                "peer_certificates": peer_fingerprints,
                "link_seconds": link_seconds,
                "weight_tensors": sorted(weight_shares),
                "session_dir": str(config.session_dir),
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )

    stop_event.wait(timeout=session_timeout)
    server.close()
    server.wait(timeout_seconds=2.0)
    state: SessionState | None = holder.get("session")
    if state is not None and not state.closed:
        state.close(reason="node-shutdown")
    if state is not None and state.teardown_finished is not None:
        teardown_finished = bool(state.teardown_finished)
    else:
        teardown_finished = runner.stop()
    transport, inside_enclave = runtime_label()
    status = (
        state.status(transport=transport, inside_enclave=inside_enclave)
        if state is not None
        else {
            "run_id": config.run_id,
            "role": config.role,
            "opened_at": None,
            "steps": [],
            "refusals": [],
            "closed": False,
        }
    )
    status.update(
        {
            "verdicts": "served" if state is not None and state.closed else "idle",
            "steps_served": served["steps"],
            "identity_sha256": runner.identity_fingerprint["sha256"],
            "peer_certificates": peer_fingerprints,
            "link_seconds": link_seconds,
            "teardown_finished": teardown_finished,
        }
    )
    write_json(config.out_dir / "node-status.json", status)
    log(f"{DONE_MARKER} {config.role}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D6 enclave SPU node")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--session-timeout", type=float, default=1800.0)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"the node configuration could not be read: {exc}")
        return 2
    try:
        config = D6NodeConfig.from_document(document)
        return run_node(config, session_timeout=args.session_timeout)
    except (NodeError, SpuBackendError, ValueError) as exc:
        log(f"{REFUSED_MARKER} {type(exc).__name__}: {exc}")
        return 3


__all__ = [
    "CLIENT_ROLE",
    "DONE_MARKER",
    "READY_MARKER",
    "REFUSED_MARKER",
    "D6NodeConfig",
    "D6NodeError",
    "SessionPayloads",
    "SessionPrograms",
    "SessionState",
    "block_config",
    "load_weight_shares",
    "run_node",
]


if __name__ == "__main__":
    raise SystemExit(main())

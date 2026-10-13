"""D6 end to end, in one process, with the MPC runtime replaced by numpy.

The enclave node cannot be imported into a test that has no ``libspu``, but
almost none of the D6 logic is the MPC: the handshake, the JobTicket check, the
frame state machine, the per-step share handling, the session cache, the state
spill and the wipe all run as ordinary Python. So this test drives the real
:class:`client.d6_session.D6Client` against the real
:class:`tee.enclave.d6_node.SessionState` and swaps only the collective program
execution for a barrier plus the float reference from :mod:`infra.d6_vectors`.

The stand-in sharing is deliberate and is *not* a security claim: three fixed
fractions of a tensor add back to it, which is enough to prove the plumbing and
nothing else. The real additive shares are the ones D6 measures on the three
instances.
"""

from __future__ import annotations

import copy
import datetime as dt
import base64
import json
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pytest

from client.d6_session import D6Client, build_history_one_hot
from client.tokenizer import WordTokenizer
from contracts.d6_session import ModelManifest, SessionPlan
from crypto.certificates import SM2CertificateAuthority
from crypto.sm2 import SM2KeyPair
from infra.d6_vectors import D6_GEOMETRY, build_weights, reference_step
from kas.models import IssueJobTicketRequest
from kas.tickets import JobTicketLedger
from mpc.spu_backend.d5_program import D5Config
from mpc.spu_backend.d6_program import build_step_program
from tee.enclave.d6_node import SessionState, block_config, load_weight_shares


NOW = dt.datetime(2026, 10, 13, 9, 0, tzinfo=dt.timezone.utc)
RELEASE_ID = "a122-d6-test"
ROLES = ("P0", "P1", "P2")


def _encode_share(payload: bytes) -> str:
    """Wrap inner bytes the way ``encode_share`` wraps a real SPU share."""
    return json.dumps(
        {"meta": "", "chunks": [base64.b64encode(payload).decode("ascii")]},
        sort_keys=True,
    )


def _inner(share_document: str) -> bytes:
    return base64.b64decode(json.loads(share_document)["chunks"][0])


def _split(value: Any) -> list[str]:
    array = np.asarray(value, dtype=np.float64)
    first = array * 0.5
    second = array * 0.25
    third = array - first - second
    return [
        _encode_share(json.dumps(part.tolist()).encode("utf-8"))
        for part in (first, second, third)
    ]


def _join(payloads: Sequence[str]) -> Any:
    """Reconstruct from share documents, the way the client's joiner does."""
    return sum(
        np.asarray(json.loads(_inner(payload)), dtype=np.float64)
        for payload in payloads
    )


def _join_inner(payloads: Sequence[str]) -> Any:
    return sum(
        np.asarray(json.loads(payload), dtype=np.float64) for payload in payloads
    )


class _ShareStub:
    """The two attributes ``encode_share``/``decode_share`` touch."""

    def __init__(self, payload: bytes = b"") -> None:
        self.meta = b""
        self.share_chunks = [payload]

    @property
    def payload(self) -> bytes:
        return self.share_chunks[0]


class _LibSpuStub:
    VIS_SECRET = 1
    Share = _ShareStub


class _Cluster:
    """The three parties' shared view: a barrier and the step's float reference."""

    def __init__(self, weights: Mapping[str, Any]) -> None:
        self.weights = weights
        self.barrier = threading.Barrier(len(ROLES), timeout=20.0)
        self.shares: list[str | None] = [None, None, None]
        self.steps = 0

    def execute(self, role_index: int, history_share: _ShareStub) -> Mapping[str, Any]:
        self.shares[role_index] = history_share.payload.decode("utf-8")
        self.barrier.wait()
        one_hot = _join_inner([share for share in self.shares if share is not None])
        tokens = [int(np.argmax(row)) for row in one_hot]
        reference = reference_step(tokens, self.weights)
        self.steps += 1
        outputs = {
            "hidden": _inner(_split(reference["hidden"])[role_index]),
            "logits": _inner(_split(reference["logits"])[role_index]),
            "token": _inner(_split(reference["token"])[role_index]),
        }
        return {name: _ShareStub(value) for name, value in outputs.items()}


class _Runner:
    """Stands in for :class:`mpc.spu_backend.program_runtime.SpuProgramRuntime`."""

    def __init__(self, cluster: _Cluster, role_index: int) -> None:
        self.cluster = cluster
        self.role_index = role_index
        self.libspu = _LibSpuStub()

    def run(self, *, program: str, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        assert program == "step"
        return self.cluster.execute(self.role_index, inputs["history"])


class _Channel:
    """A node's in-process share channel, exercising the real SessionState.

    One instance is one connection: ``state`` is the session this connection
    opened, while ``state_box`` is the node-wide registry every connection
    shares. Keeping the two apart is what makes a second connection carrying a
    spent JobTicket behave the way it does on the instance.
    """

    def __init__(self, *, cluster: _Cluster, config: Any, role_index: int, state_box: dict):
        self.role = ROLES[role_index]
        self.cluster = cluster
        self.config = config
        self.role_index = role_index
        self.state_box = state_box
        self.state: Any | None = None
        self.refusals: list[str] = []
        self.seen: list[dict[str, Any]] = []

    def request(self, document: Mapping[str, Any]) -> Mapping[str, Any]:
        self.seen.append(copy.deepcopy(dict(document)))
        kind = document.get("type")
        try:
            if kind == "hello":
                if self.state is not None:
                    raise RuntimeError("a session is already open")
                candidate = SessionState(
                    config=self.config,
                    runner=_Runner(self.cluster, self.role_index),
                    weight_shares=self.state_box["weights"],
                    clock=lambda: NOW,
                    ticket_registry=self.state_box["tickets"],
                )
                server_hello = candidate.hello(
                    message=document["client_hello"],
                    ticket_document=document["ticket"],
                )
                self.state = candidate
                self.state_box["state"] = candidate
                return {
                    "type": "server_hello",
                    "server_hello": server_hello,
                }
            state = self.state
            if kind == "finished":
                ack, facts = state.finish(message=document["finished"])
                return {"type": "finished_ack", "finished_ack": ack, **facts}
            if kind == "step":
                from crypto.frame import EncryptedFrame

                payload = state.runtime.receive(
                    EncryptedFrame.from_dict(document["frame"])
                )
                _share, result = state.runtime.execute(payload)
                return {
                    "type": "result",
                    "frame": result.to_dict(),
                    "elapsed_ms": 1.0,
                }
            if kind == "close":
                from crypto.frame import EncryptedFrame

                state.runtime.accept_close(EncryptedFrame.from_dict(document["frame"]))
                return {"type": "closed", "evidence": state.close(reason="test")}
            if kind == "status":
                return {
                    "type": "status",
                    "status": state.status(transport="test", inside_enclave=False),
                }
            raise RuntimeError(f"unknown message {kind!r}")
        except Exception as exc:  # noqa: BLE001 - mirrors the node's refusal path
            reason = f"{type(exc).__name__}: {exc}"
            self.refusals.append(reason)
            # A refusal on a connection that never opened a session still
            # belongs in the record of the session the node is serving.
            recorded = self.state if self.state is not None else self.state_box.get("state")
            if recorded is not None:
                recorded.refusals.append({"message": kind, "reason": reason})
            return {"type": "refused", "reason": f"{type(exc).__name__}: {exc}"}

    def close(self) -> None:
        return None


def _manifest() -> ModelManifest:
    tokenizer = WordTokenizer()
    return ModelManifest(
        model_version="tiny-decoder-d6-v1",
        weight_seed=20261013,
        sequence=D6_GEOMETRY["sequence"],
        hidden_size=D6_GEOMETRY["hidden_size"],
        num_heads=D6_GEOMETRY["num_heads"],
        intermediate_size=D6_GEOMETRY["intermediate_size"],
        vocab_size=tokenizer.vocab_size,
        tokenizer_digest=tokenizer.vocabulary_digest,
        fractional_bits=D6_GEOMETRY["fractional_bits"],
    )


def _rig(tmp_path: Path) -> tuple[D6Client, dict[str, _Channel], _Cluster]:
    tokenizer = WordTokenizer()
    manifest = _manifest()
    plan = SessionPlan.for_manifest(
        manifest,
        release_id=RELEASE_ID,
        share_epoch=7,
        max_new_tokens=3,
        length_bound=1 << 20,
    )
    weights = build_weights(manifest.weight_seed)
    program = build_step_program(
        D5Config(
            sequence=manifest.sequence,
            hidden_size=manifest.hidden_size,
            num_heads=manifest.num_heads,
            intermediate_size=manifest.intermediate_size,
            vocab_size=manifest.vocab_size,
            fractional_bits=manifest.fractional_bits,
        )
    )
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    ledger = JobTicketLedger(signing_key=SM2KeyPair.generate(), clock=lambda: NOW)
    node_keys = {role: SM2KeyPair.generate() for role in ROLES}
    certificates = {
        role: authority.issue(
            role=role,
            release_id=RELEASE_ID,
            public_key=node_keys[role].public_key,
            now=NOW,
            ttl=dt.timedelta(hours=1),
        )
        for role in ROLES
    }
    cluster = _Cluster(weights)
    encoded_stub = json.dumps({"meta": "", "chunks": ["eA=="]}, sort_keys=True)
    weight_shares = {
        name: encoded_stub for name in program.input_names if name != "history"
    }
    channels: dict[str, _Channel] = {}
    for index, role in enumerate(ROLES):
        config = _node_config(
            tmp_path=tmp_path,
            role=role,
            plan=plan,
            manifest=manifest,
            authority=authority,
            node_key=node_keys[role],
            certificate=certificates[role],
            ledger=ledger,
        )
        channels[role] = _Channel(
            cluster=cluster,
            config=config,
            role_index=index,
            state_box={"state": None, "weights": weight_shares, "tickets": set()},
        )
    client = D6Client(
        plan=plan,
        tokenizer=tokenizer,
        authority=authority,
        ledger=ledger,
        node_public_keys={role: node_keys[role].public_key for role in ROLES},
        splitter=_split,
        joiner=_join,
        clock=lambda: NOW,
    )
    return client, channels, cluster


def _node_config(
    *,
    tmp_path: Path,
    role: str,
    plan: SessionPlan,
    manifest: ModelManifest,
    authority: SM2CertificateAuthority,
    node_key: SM2KeyPair,
    certificate: Any,
    ledger: JobTicketLedger,
) -> Any:
    from tee.enclave.d6_node import D6NodeConfig

    # The node holds the KAS public key and the client authority's public key
    # and nothing else: it cannot mint a ticket or a client certificate.
    document = {
        "config_version": "a122-d6-node-v1",
        "run_id": "d6-unit",
        "role": role,
        "partition_id": "a122-d6-d6-unit",
        "endpoints": [
            {"role": name, "host": "127.0.0.1", "port": 47100 + index}
            for index, name in enumerate(ROLES)
        ],
        "identity": {
            "role": role,
            "certificate": str(tmp_path / f"{role}.pem"),
            "private_key": str(tmp_path / f"{role}-key.pem"),
            "ca_bundle": str(tmp_path / "ca.pem"),
        },
        "peer_certificates": {},
        "share_channel": {"host": "127.0.0.1", "port": 47200},
        "out_dir": str(tmp_path / "out" / role),
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "weights": str(tmp_path / "weights.json"),
        "sm2_identity": {
            "private_key": node_key.private_key,
            "public_key": node_key.public_key,
        },
        "sm2_certificate": certificate.to_dict(),
        "kas_public_key": ledger.public_key,
        "client_authority_public_key": authority.public_key,
        "session_dir": str(tmp_path / "session" / role),
        "seed": 20261013,
    }
    return D6NodeConfig.from_document(document)


def test_private_two_token_generation_and_cleanup(tmp_path: Path) -> None:
    client, channels, cluster = _rig(tmp_path)
    result = client.run("the cipher key is secret", exchanges=channels)
    assert len(result["generated_tokens"]) == 3
    assert all(
        step["argmax_match"] for step in result["steps"]
    ), "the secure Argmax must agree with the reconstructed logits"
    assert result["negative_verdicts"] == "passed", result["negative_cases"]
    assert {case["case"] for case in result["negative_cases"]} >= {
        "duplicate_result_frame",
        "tampered_decode_step",
        "mixed_model_manifest",
        "replayed_request_frame",
    }
    for role in ROLES:
        close = result["close"][role]["close"]
        assert close["session_dir_removed"] is True
        assert close["kv"]["all_zero"] is True
        assert close["spilled_files"] >= 1
        assert close["spilled_bytes_overwritten"] > 0
        assert close["session_keys_wiped_bytes"] > 0
        state = channels[role].state_box["state"]
        assert state.closed is True
        assert state.runtime.session.keys_wiped is True
        with pytest.raises(Exception):
            state.cache.layer(0)
        with pytest.raises(Exception):
            state.cache.buffers(0)


def test_only_shares_reach_the_nodes(tmp_path: Path) -> None:
    client, channels, cluster = _rig(tmp_path)
    result = client.run("the cipher key is secret", exchanges=channels)
    plan = result["plan"]
    prompt = list(result["prompt_tokens"])
    plaintext_history: set[str] = set()
    for step in range(len(result["steps"])):
        one_hot = build_history_one_hot(
            prompt[: len(prompt) + step],
            sequence=plan["sequence"],
            vocab_size=plan["vocab_size"],
            pad_token=0,
        )
        plaintext_history.add(json.dumps(one_hot.tolist()))

    # What each node received is one share, and the three differ from each
    # other: the matrix itself never crosses the share-channel boundary.
    step_blobs = {
        role: [
            json.dumps(message["frame"], sort_keys=True)
            for message in channel.seen
            if message.get("type") == "step"
        ]
        for role, channel in channels.items()
    }
    for index in range(len(result["steps"])):
        assert (
            len({step_blobs[role][index] for role in ROLES}) == 3
        ), "every party has to receive its own share"
    everything = json.dumps(step_blobs, sort_keys=True)
    for plaintext in plaintext_history:
        assert plaintext not in everything
    # And the node's own status keeps digests, never the share it handled.
    for channel in channels.values():
        status = channel.state_box["state"].status(
            transport="test", inside_enclave=False
        )
        blob = json.dumps(status, sort_keys=True)
        for plaintext in plaintext_history:
            assert plaintext not in blob
        for message in step_blobs[channel.role]:
            assert message not in blob


def test_ticket_budget_and_replay_are_enforced(tmp_path: Path) -> None:
    client, channels, cluster = _rig(tmp_path)
    result = client.run("cipher key", exchanges=channels, max_new_tokens=2)
    assert len(result["generated_tokens"]) == 2
    assert any(
        case["case"] == "replayed_request_frame" and case["refused"]
        for case in result["negative_cases"]
    )
    assert any(
        "already been accepted" in refusal or "replay" in refusal.lower()
        for channel in channels.values()
        for refusal in channel.refusals
    )


def test_replaying_a_spent_ticket_on_a_new_connection_leaves_the_session_alone(
    tmp_path: Path,
) -> None:
    client, channels, cluster = _rig(tmp_path)

    def dial(role: str) -> _Channel:
        # A fresh connection to the same node: same state_box, new state.
        return _Channel(
            cluster=cluster,
            config=channels[role].config,
            role_index=ROLES.index(role),
            state_box=channels[role].state_box,
        )

    result = client.run("cipher key", exchanges=channels, dial=dial)
    ticket_case = next(
        case for case in result["negative_cases"] if case["case"] == "replayed_job_ticket"
    )
    assert ticket_case["refused"] is True, ticket_case
    assert "already been accepted" in ticket_case["reason"]
    # The refused second connection must not have replaced the session the
    # node keeps reporting on: P1 still has its steps and now also carries the
    # probe's refusal.
    served = channels["P1"].state_box["state"]
    assert channels["P1"].state is served
    assert len(served.steps) == len(result["generated_tokens"])
    assert any(
        refusal["message"] == "hello" and "already been accepted" in refusal["reason"]
        for refusal in served.refusals
    )
    assert served.closed is True
    assert served.close_evidence["session_dir_removed"] is True


def test_weight_bundle_is_validated_before_use(tmp_path: Path) -> None:
    bundle = tmp_path / "weights.json"
    bundle.write_text(json.dumps({"tensors": {}}), encoding="utf-8")
    with pytest.raises(Exception):
        load_weight_shares(bundle)
    bundle.write_text(json.dumps({"tensors": {"wq": 7}}), encoding="utf-8")
    with pytest.raises(Exception):
        load_weight_shares(bundle)
    bundle.write_text("{ not json", encoding="utf-8")
    with pytest.raises(Exception):
        load_weight_shares(bundle)
    bundle.write_text(json.dumps({"tensors": {"wq": "share"}}), encoding="utf-8")
    assert load_weight_shares(bundle) == {"wq": "share"}

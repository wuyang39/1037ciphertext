"""Run the D6 client on a host that can reach the three enclave nodes.

The runner is the operator's view of one session: it reads the workspace the
dealer produced, dials P0/P1/P2 over their share channels with the client's own
certificate, drives :class:`client.d6_session.D6Client`, and then checks what
came back against the float reference the dealer can compute.

That last check is the reason the runner exists as its own process. The client
is not allowed to hold the model, so it cannot compute a reference; the dealer
side can, and comparing the reconstructed logits against it turns "the session
completed" into "the private loop produced the numbers the public reference
did".
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from client.d6_session import D6Client
from client.tokenizer import WordTokenizer
from contracts.d6_session import ModelManifest, SessionPlan
from crypto.certificates import SM2CertificateAuthority
from crypto.sm2 import SM2KeyPair
from infra.d6_vectors import build_weights, reference_step
from kas.tickets import JobTicketLedger
from mpc.spu_backend.sharing import make_joiner, make_splitter
from mpc.spu_backend.spu_link import load_libspu, make_io, runtime_config
from mpc.spu_backend.transport import TLSFrameChannel, TLSIdentity
from tee.enclave.node_common import decode_document, encode_document


CLIENT = "C"
DONE_MARKER = "A122-D6-CLIENT-DONE"
STEP_TIMEOUT_SECONDS = 900.0
ROLES = ("P0", "P1", "P2")


class D6RunnerError(RuntimeError):
    """The client run could not be prepared or completed."""


class TLSExchange:
    """One persistent mTLS connection to one node's share channel."""

    def __init__(
        self,
        *,
        role: str,
        host: str,
        port: int,
        identity: TLSIdentity,
        timeout_seconds: float = STEP_TIMEOUT_SECONDS,
    ) -> None:
        self.role = role
        self._channel = TLSFrameChannel.connect(
            host=host,
            port=port,
            identity=identity,
            peer_role=role,
            timeout_seconds=timeout_seconds,
        )
        if self._channel.tls_version != "TLSv1.3":
            raise D6RunnerError(
                f"the share channel to {role} negotiated {self._channel.tls_version!r}"
            )

    @property
    def tls_version(self) -> str:
        return self._channel.tls_version

    def request(self, document: Mapping[str, Any]) -> Mapping[str, Any]:
        self._channel.send_frame(encode_document(dict(document)))
        return decode_document(self._channel.receive_frame())

    def close(self) -> None:
        self._channel.close()


def _tls_identity(document: Mapping[str, Any]) -> TLSIdentity:
    identity = document["identity"]
    return TLSIdentity(
        role=str(identity["role"]),
        certificate_pem=Path(identity["certificate"]).read_text(encoding="ascii"),
        private_key_pem=Path(identity["private_key"]).read_text(encoding="ascii"),
        ca_bundle_pem=Path(identity["ca_bundle"]).read_text(encoding="ascii"),
        allowed_peer_roles=("P0", "P1", "P2"),
    )


def build_ledger(kas_document: Mapping[str, Any]) -> JobTicketLedger:
    """The client issues its own JobTickets from the KAS signing key it holds.

    The ledger's clock is the runner's own wall clock: the ticket expiry is
    what a node checks against its clock, so it has to be real UTC rather than
    a value frozen for a test.
    """
    return JobTicketLedger(
        signing_key=SM2KeyPair.from_private_key(
            str(kas_document["kas_signing_private_key"])
        ),
        clock=lambda: dt.datetime.now(dt.timezone.utc),
    )


def build_client(
    client_document: Mapping[str, Any],
    kas_document: Mapping[str, Any],
) -> tuple[D6Client, WordTokenizer, ModelManifest, SessionPlan]:
    plan = SessionPlan.from_dict(client_document["plan"])
    manifest = ModelManifest.from_dict(client_document["model"])
    tokenizer = WordTokenizer.from_dict(client_document["tokenizer"])
    if manifest.digest() != plan.model_manifest_hash:
        raise D6RunnerError("the client configuration does not describe its own plan")
    authority = SM2CertificateAuthority(
        SM2KeyPair.from_private_key(str(kas_document["client_authority_private_key"]))
    )
    ledger = build_ledger(kas_document)
    libspu, _ = load_libspu()
    io = make_io(libspu, runtime_config(libspu, fraction_bits=plan.fractional_bits))
    client = D6Client(
        plan=plan,
        tokenizer=tokenizer,
        authority=authority,
        ledger=ledger,
        node_public_keys={
            role: str(client_document["nodes"][role]["identity_public_key"])
            for role in ("P0", "P1", "P2")
        },
        splitter=make_splitter(libspu, io),
        joiner=make_joiner(libspu, io),
    )
    return client, tokenizer, manifest, plan


def reference_check(
    *,
    result: Mapping[str, Any],
    manifest: ModelManifest,
) -> list[dict[str, Any]]:
    """Compare every reconstructed step against the float reference."""
    weights = build_weights(manifest.weight_seed, manifest.to_dict())
    prompt = list(result["prompt_tokens"])
    checks: list[dict[str, Any]] = []
    for index, step in enumerate(result["steps"]):
        history = prompt + [record["token_id"] for record in result["steps"][:index]]
        reference = reference_step(history, weights, manifest.to_dict())
        want = np.asarray(reference["logits"], dtype=np.float64)[-1]
        got = np.asarray(step["logits_last_row"], dtype=np.float64)
        delta = np.abs(got - want)
        reference_token = int(round(float(np.asarray(reference["token"]).ravel()[0])))
        checks.append(
            {
                "decode_step": step["decode_step"],
                "max_abs_error": float(delta.max()) if delta.size else 0.0,
                "mean_abs_error": float(delta.mean()) if delta.size else 0.0,
                "reference_token": reference_token,
                "token_match": reference_token == step["token_id"],
                "argmax_match": step["argmax_match"],
            }
        )
    return checks


def write_result(out_path: Path | str, result: Mapping[str, Any]) -> None:
    """Write the session result, creating the directory it lands in.

    The node creates its own out directory when it starts; the client's is
    only ever written here, at the end of a session that has already run, so a
    missing directory must not be what loses the result.
    """
    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(dict(result), ensure_ascii=True, sort_keys=True, indent=2),
        encoding="utf-8",
        newline="\n",
    )


def run(
    *,
    client_document: Mapping[str, Any],
    kas_document: Mapping[str, Any],
    prompt: str,
    out_path: Path | None = None,
    max_new_tokens: int | None = None,
) -> dict[str, Any]:
    client, _tokenizer, manifest, _plan = build_client(client_document, kas_document)
    identity = _tls_identity(client_document)
    nodes = client_document["nodes"]

    def dial(role: str) -> TLSExchange:
        node = nodes[role]
        return TLSExchange(
            role=role,
            host=str(node["share_host"]),
            port=int(node["share_port"]),
            identity=identity,
        )

    started = time.monotonic()
    exchanges = {role: dial(role) for role in ("P0", "P1", "P2")}
    try:
        result = client.run(
            prompt,
            exchanges=exchanges,
            dial=dial,
            max_new_tokens=max_new_tokens,
        )
    finally:
        for exchange in exchanges.values():
            try:
                exchange.close()
            except Exception:  # pragma: no cover - best effort teardown
                pass
    result["wall_seconds"] = round(time.monotonic() - started, 3)
    result["reference_check"] = reference_check(result=result, manifest=manifest)
    result["reference_verdicts"] = (
        "passed"
        if all(
            check["token_match"] and check["argmax_match"]
            for check in result["reference_check"]
        )
        else "failed"
    )
    result["shutdown"] = release_nodes(dial=dial)
    result["shutdown_verdicts"] = (
        "passed"
        if all(record["released"] for record in result["shutdown"])
        else "failed"
    )
    if out_path is not None:
        write_result(out_path, result)
    return result


def release_nodes(*, dial: Any) -> list[dict[str, Any]]:
    """Tell all three nodes the session is over so they exit and write status.

    A node keeps serving after it closes a session, waiting for either this
    message or its own idle timeout, and only writes ``node-status.json`` on
    the way out. The three releases are sent together so a node whose link
    teardown is still outstanding is not left waiting for peers the client has
    not reached yet.
    """
    outcomes: list[dict[str, Any]] = []

    def release(role: str) -> dict[str, Any]:
        try:
            exchange = dial(role)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return {
                "role": role,
                "released": False,
                "reason": f"{type(exc).__name__}: {exc}",
            }
        try:
            response = exchange.request({"type": "shutdown"})
            return {
                "role": role,
                "released": response.get("type") == "bye",
                "reply": response.get("type"),
            }
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return {
                "role": role,
                "released": False,
                "reason": f"{type(exc).__name__}: {exc}",
            }
        finally:
            try:
                exchange.close()
            except Exception:  # pragma: no cover - best effort teardown
                pass

    with ThreadPoolExecutor(max_workers=len(ROLES), thread_name_prefix="a122-d6-release") as pool:
        futures = {role: pool.submit(release, role) for role in ROLES}
        for role in ROLES:
            outcomes.append(futures[role].result())
    return outcomes


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D6 client runner")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--kas", required=True, type=Path)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-new-tokens", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        client_document = json.loads(args.config.read_text(encoding="utf-8"))
        kas_document = json.loads(args.kas.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"the client configuration could not be read: {exc}", flush=True)
        return 2
    try:
        result = run(
            client_document=client_document,
            kas_document=kas_document,
            prompt=args.prompt,
            out_path=args.out,
            max_new_tokens=args.max_new_tokens,
        )
    except Exception as exc:  # noqa: BLE001 - reported to the driver
        print(f"A122-D6-CLIENT-FAILED {type(exc).__name__}: {exc}", flush=True)
        return 3
    print(
        json.dumps(
            {
                "session_id": result["session_id"],
                "generated_words": result["generated_words"],
                "generated_text": result["generated_text"],
                "negative_verdicts": result["negative_verdicts"],
                "reference_verdicts": result["reference_verdicts"],
                "shutdown_verdicts": result["shutdown_verdicts"],
                "wall_seconds": result["wall_seconds"],
            },
            ensure_ascii=True,
            sort_keys=True,
        ),
        flush=True,
    )
    print(DONE_MARKER, flush=True)
    passed = (
        result["reference_verdicts"] == "passed"
        and result["shutdown_verdicts"] == "passed"
    )
    return 0 if passed else 1


__all__ = [
    "DONE_MARKER",
    "STEP_TIMEOUT_SECONDS",
    "D6RunnerError",
    "TLSExchange",
    "build_client",
    "reference_check",
    "release_nodes",
    "run",
    "write_result",
]


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the D7 client on a host that can reach the three enclave nodes.

The runner is the operator's view of one GPT-2 session: it reads the workspace
the dealer produced, dials P0/P1/P2 over their share channels with the client's
own certificate, drives :class:`client.d7_session.D7Client`, and then checks
what came back against the float reference the dealer can compute.

That last check is the reason the runner exists as its own process. The client
is not allowed to hold the model, so it cannot compute a reference; the dealer
side holds the export the shares were split from, and comparing the
reconstructed logits against the same tensors turns "the session completed"
into "the private loop produced the numbers the public reference did".
"""

from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from client.d6_runner import TLSExchange, build_ledger, write_result
from client.d7_session import D7Client
from client.gpt2_bpe import load_bpe
from contracts.d7_session import D7ModelManifest, D7SessionPlan
from crypto.certificates import SM2CertificateAuthority
from crypto.sm2 import SM2KeyPair
from infra.d7_vectors import reference_step
from infra.d7_workspace import load_export
from kas.tickets import JobTicketLedger
from mpc.spu_backend.d7_program import D7Config
from mpc.spu_backend.sharing import make_joiner, make_splitter
from mpc.spu_backend.spu_link import load_libspu, make_io, runtime_config
from mpc.spu_backend.transport import TLSIdentity


CLIENT = "C"
DONE_MARKER = "A122-D7-CLIENT-DONE"
FAILED_MARKER = "A122-D7-CLIENT-FAILED"
STEP_TIMEOUT_SECONDS = 900.0
ROLES = ("P0", "P1", "P2")


class D7RunnerError(RuntimeError):
    """The client run could not be prepared or completed."""


def _tls_identity(document: Mapping[str, Any]) -> TLSIdentity:
    identity = document["identity"]
    return TLSIdentity(
        role=str(identity["role"]),
        certificate_pem=Path(identity["certificate"]).read_text(encoding="ascii"),
        private_key_pem=Path(identity["private_key"]).read_text(encoding="ascii"),
        ca_bundle_pem=Path(identity["ca_bundle"]).read_text(encoding="ascii"),
        allowed_peer_roles=("P0", "P1", "P2"),
    )


def geometry(plan: D7SessionPlan) -> D7Config:
    return D7Config(
        sequence=plan.sequence,
        layers=plan.layers,
        hidden_size=plan.hidden_size,
        num_heads=plan.num_heads,
        intermediate_size=plan.intermediate_size,
        vocab_size=plan.vocab_size,
        fractional_bits=plan.fractional_bits,
    )


def build_client(
    client_document: Mapping[str, Any],
    kas_document: Mapping[str, Any],
) -> tuple[D7Client, D7ModelManifest, D7SessionPlan, dict[str, Any]]:
    plan = D7SessionPlan.from_dict(client_document["plan"])
    manifest = D7ModelManifest.from_dict(client_document["model"])
    export_document = client_document["export"]
    exported = load_export(Path(str(export_document["directory"])))
    if exported["bundle"].model_hash != manifest.model_hash:
        raise D7RunnerError("the export on this host is not the pinned model")
    encoder = load_bpe(str(client_document["tokenizer"]["directory"]))
    authority = SM2CertificateAuthority(
        SM2KeyPair.from_private_key(str(kas_document["client_authority_private_key"]))
    )
    ledger: JobTicketLedger = build_ledger(kas_document)
    libspu, _ = load_libspu()
    io = make_io(libspu, runtime_config(libspu, fraction_bits=plan.fractional_bits))
    client = D7Client(
        plan=plan,
        model=manifest,
        encoder=encoder,
        candidates=[int(value) for value in export_document["candidate_tokens"]],
        authority=authority,
        ledger=ledger,
        node_public_keys={
            role: str(client_document["nodes"][role]["identity_public_key"])
            for role in ROLES
        },
        splitter=make_splitter(libspu, io),
        joiner=make_joiner(libspu, io),
    )
    return client, manifest, plan, exported


def reference_check(
    *,
    result: Mapping[str, Any],
    plan: D7SessionPlan,
    exported: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare every reconstructed step against the float reference.

    The reference is computed from the very tensors the dealer split, with the
    candidate vocabulary the session pinned, so a mismatch is a protocol,
    fixed-point or binding defect rather than two readings of the same maths.
    """
    weights = dict(exported["weights"])
    config = geometry(plan)
    prompt_indices = [int(value) for value in result["prompt_indices"]]
    checks: list[dict[str, Any]] = []
    for index, step in enumerate(result["steps"]):
        history = prompt_indices + [
            int(record["token_index"]) for record in result["steps"][:index]
        ]
        reference = reference_step(
            history, weights, config, decode_row=int(step["decode_row"])
        )
        row = int(step["decode_row"])
        want = np.asarray(reference["logits"], dtype=np.float64)[row]
        got = np.asarray(step["logits_row"], dtype=np.float64)
        delta = np.abs(got - want)
        reference_token = int(
            round(float(np.asarray(reference["token"]).ravel()[0]))
        )
        checks.append(
            {
                "decode_step": step["decode_step"],
                "decode_row": row,
                "max_abs_error": float(delta.max()) if delta.size else 0.0,
                "mean_abs_error": float(delta.mean()) if delta.size else 0.0,
                "reference_token_index": reference_token,
                "token_match": reference_token == int(step["token_index"]),
                "argmax_match": bool(step["argmax_match"]),
            }
        )
    return {
        "steps": checks,
        "token_agreement": "passed"
        if checks and all(check["token_match"] for check in checks)
        else "failed",
        "argmax_agreement": "passed"
        if checks and all(check["argmax_match"] for check in checks)
        else "failed",
        "worst_max_abs_error": max(
            (check["max_abs_error"] for check in checks), default=None
        ),
    }


def release_nodes(*, dial: Any) -> list[dict[str, Any]]:
    """Tell all three nodes the session is over so they exit and write status."""
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

    with ThreadPoolExecutor(
        max_workers=len(ROLES), thread_name_prefix="a122-d7-release"
    ) as pool:
        futures = {role: pool.submit(release, role) for role in ROLES}
        for role in ROLES:
            outcomes.append(futures[role].result())
    return outcomes


def run(
    *,
    client_document: Mapping[str, Any],
    kas_document: Mapping[str, Any],
    prompt: str,
    out_path: Path | None = None,
    max_new_tokens: int | None = None,
) -> dict[str, Any]:
    client, _manifest, plan, exported = build_client(client_document, kas_document)
    identity = _tls_identity(client_document)
    nodes = client_document["nodes"]

    def dial(role: str) -> TLSExchange:
        node = nodes[role]
        return TLSExchange(
            role=role,
            host=str(node["share_host"]),
            port=int(node["share_port"]),
            identity=identity,
            timeout_seconds=STEP_TIMEOUT_SECONDS,
        )

    started = time.monotonic()
    exchanges = {role: dial(role) for role in ROLES}
    try:
        result = client.run(
            prompt, exchanges=exchanges, dial=dial, max_new_tokens=max_new_tokens
        )
    finally:
        for exchange in exchanges.values():
            try:
                exchange.close()
            except Exception:  # pragma: no cover - best effort teardown
                pass
    result["wall_seconds"] = round(time.monotonic() - started, 3)
    result["reference_check"] = reference_check(
        result=result, plan=plan, exported=exported
    )
    result["reference_verdicts"] = (
        "passed"
        if result["reference_check"]["token_agreement"] == "passed"
        and result["reference_check"]["argmax_agreement"] == "passed"
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 GPT-2 client runner")
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
        print(f"{FAILED_MARKER} {type(exc).__name__}: {exc}", flush=True)
        return 3
    print(
        json.dumps(
            {
                "session_id": result["session_id"],
                "prompt_tokens": result["prompt_tokens"],
                "generated_tokens": result["generated_tokens"],
                "generated_text": result["generated_text"],
                "worst_max_abs_error": result["reference_check"][
                    "worst_max_abs_error"
                ],
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
    "CLIENT",
    "DONE_MARKER",
    "FAILED_MARKER",
    "ROLES",
    "STEP_TIMEOUT_SECONDS",
    "D7RunnerError",
    "TLSExchange",
    "build_client",
    "geometry",
    "main",
    "reference_check",
    "release_nodes",
    "run",
]


if __name__ == "__main__":
    raise SystemExit(main())

"""D5 enclave node: one SPU party running the secure Transformer block.

The node owns the same two channels as the D4 node: the SPU/YACL/BRPC link,
whose TLS context is built from the KAS-issued certificate, and the mutually
authenticated share channel that carries one party's input share and returns
its output share. P0 drives the case grid; P1 and P2 only ever see shares.

The programs are the four non-linear operators and one whole pre-norm decoder
block from :mod:`mpc.spu_backend.d5_program`. Every case is generated from the
recorded seed, so the same inputs and the same float reference can be rebuilt
offline, and the per-operator table records the fixed-point protocol error
against that reference: ``max_abs_error``, ``mean_abs_error``,
``relative_error``, ``overflow_count`` and, for Argmax, ``argmax_match``.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d5_vectors import (
    ARGMAX_TOLERANCE,
    BLOCK_HIDDEN_TOLERANCE,
    BLOCK_LOGITS_TOLERANCE,
    GELU_TOLERANCE,
    LAYERNORM_TOLERANCE,
    SOFTMAX_TOLERANCE,
    build_grid,
    case_inputs,
    digest_grid,
    reference_argmax,
    reference_block,
    reference_gelu,
    reference_gelu_erf,
    reference_layernorm,
    reference_softmax,
)
from infra.evidence import sha256_bytes, write_json
from mpc.spu_backend.d5_program import (
    D5Config,
    build_argmax_program,
    build_block_program,
    build_gelu_program,
    build_layernorm_program,
    build_softmax_program,
)
from mpc.spu_backend.program_runtime import SpuProgramRuntime
from mpc.spu_backend.spu_link import (
    CLIENT_VERIFY_DEPTH,
    FXP_FRACTION_BITS,
    SERVER_VERIFY_DEPTH,
    NodeIdentity,
    SpuBackendError,
    SpuEndpoint,
    SpuLinkPolicy,
    decode_share,
    encode_share,
    load_libspu,
    reconstruct,
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
    PeerSession,
    decode_document,
    encode_document,
    log,
    runtime_label,
    serve_share_channel,
    wait_for_port,
)


READY_MARKER = "A122-D5-NODE-READY"
SHUTDOWN_MARKER = "A122-D5-NODE-DONE"
REPRESENTABLE_LIMIT = float(1 << (64 - FXP_FRACTION_BITS - 1))
"""The FM64 fixed-point range; a value past it has saturated."""


def _tolerance(name: str) -> float:
    return {
        "softmax": SOFTMAX_TOLERANCE,
        "layernorm": LAYERNORM_TOLERANCE,
        "gelu": GELU_TOLERANCE,
    }[name]


def _program_set(config: D5Config) -> list[Any]:
    ops = [
        build_softmax_program(config.sequence, config.sequence),
        build_layernorm_program(config.sequence, config.hidden_size),
        build_gelu_program(config.sequence, config.hidden_size),
        build_argmax_program(config.vocab_size),
    ]
    return ops + [build_block_program(config)]


@dataclass(frozen=True)
class D5NodeConfig:
    """Everything one D5 node needs, already validated by the orchestrator."""

    run_id: str
    role: str
    partition_id: str
    endpoints: tuple[SpuEndpoint, ...]
    identity: NodeIdentity
    peer_certificates: dict[str, Path]
    share_host: str
    share_port: int
    peer_share_channels: dict[str, tuple[str, int]]
    out_dir: Path
    block_config: D5Config
    seed: int
    present_client_certificate: bool = True
    enable_ssl: bool = True
    server_verify_depth: int = SERVER_VERIFY_DEPTH
    client_verify_depth: int = CLIENT_VERIFY_DEPTH
    connect_retry_times: int = 120
    connect_retry_interval_ms: int = 500

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "D5NodeConfig":
        try:
            endpoints = tuple(
                SpuEndpoint(
                    role=str(entry["role"]),
                    host=str(entry["host"]),
                    port=int(entry["port"]),
                )
                for entry in document["endpoints"]
            )
            identity_document = document["identity"]
            block = document.get("block") or {}
            return cls(
                run_id=str(document["run_id"]),
                role=str(document["role"]),
                partition_id=str(document["partition_id"]),
                endpoints=endpoints,
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
                peer_share_channels={
                    str(role): (str(value["host"]), int(value["port"]))
                    for role, value in (
                        document.get("peer_share_channels") or {}
                    ).items()
                },
                out_dir=Path(document["out_dir"]),
                block_config=D5Config(
                    sequence=int(block.get("sequence", 8)),
                    hidden_size=int(block.get("hidden_size", 8)),
                    num_heads=int(block.get("num_heads", 2)),
                    intermediate_size=int(block.get("intermediate_size", 16)),
                    vocab_size=int(block.get("vocab_size", 32)),
                    fractional_bits=int(
                        block.get("fractional_bits", FXP_FRACTION_BITS)
                    ),
                ),
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
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise NodeError(f"the node configuration is malformed: {exc}") from exc

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
        return TLSIdentity(
            role=self.role,
            certificate_pem=self.identity.certificate_path.read_text(encoding="ascii"),
            private_key_pem=self.identity.private_key_path.read_text(encoding="ascii"),
            ca_bundle_pem=self.identity.ca_bundle_path.read_text(encoding="ascii"),
            allowed_peer_roles=("P0",) if self.role != "P0" else ("P1", "P2"),
        )


def _split(libspu: Any, io: Any, value: Any) -> Sequence[Any]:
    import numpy

    shares = io.MakeShares(numpy.asarray(value, dtype=numpy.float64), int(libspu.VIS_SECRET))
    if len(shares) != 3:
        raise NodeError("SPU returned an unexpected number of shares")
    return shares


def _error_stats(
    actual: Any,
    expected: Any,
    *,
    atol: float = 0.0,
    rtol: float = 0.0,
    anchor: Any | None = None,
) -> dict[str, Any]:
    """Absolute, relative and allclose-style error for one tensor.

    ``relative_error`` divides by ``max(|want|, atol)`` so a reference value of
    zero -- the GELU output for every negative input, for instance -- does not
    turn a correct answer into an infinite ratio. ``max_scaled_error`` is the
    quantity the verdict uses: it is at most one exactly when every element
    satisfies ``|got - want| <= atol + rtol * |want|``, the same rule numpy's
    ``allclose`` applies.

    ``anchor`` replaces the reference magnitude in that budget with the
    largest of the two. GELU needs it: SPU's tanh saturates to about
    ``+/-(1 - 2.7e-3)``, so on the negative tail the output is ``|x| * d``
    rather than zero, and the error is proportional to the *input* even though
    the output is nearly zero.
    """
    import numpy

    got = numpy.asarray(actual, dtype=numpy.float64)
    want = numpy.asarray(expected, dtype=numpy.float64)
    if got.shape != want.shape:
        return {
            "shape_mismatch": True,
            "got_shape": list(got.shape),
            "want_shape": list(want.shape),
        }
    delta = numpy.abs(got - want)
    floor = max(float(atol), 1e-9)
    scale_reference = numpy.abs(want)
    if anchor is not None:
        anchored = numpy.asarray(anchor, dtype=numpy.float64)
        if anchored.shape == want.shape:
            scale_reference = numpy.maximum(scale_reference, numpy.abs(anchored))
    budget = float(atol) + float(rtol) * scale_reference
    scale = numpy.maximum(numpy.abs(want), floor)
    return {
        "shape_mismatch": False,
        "max_abs_error": float(delta.max()) if delta.size else 0.0,
        "mean_abs_error": float(delta.mean()) if delta.size else 0.0,
        "relative_error": float((delta / scale).max()) if delta.size else 0.0,
        "max_scaled_error": float((delta / budget).max()) if delta.size else 0.0,
        "overflow_count": int(numpy.count_nonzero(numpy.abs(got) >= REPRESENTABLE_LIMIT)),
        "elements": int(delta.size),
    }


def _serve(
    config: D5NodeConfig,
    runtime_holder: dict[str, Any],
    stop_event: Any,
    served: dict[str, int],
) -> Any:
    identity = config.share_identity()

    def handler(channel: TLSFrameChannel) -> None:
        while not stop_event.is_set():
            try:
                request = decode_document(channel.receive_frame())
            except TLSChannelClosed:
                return
            except (TLSChannelError, NodeError):
                return
            message_type = request.get("type")
            if message_type == "shutdown":
                channel.send_frame(encode_document({"type": "bye", "role": config.role}))
                stop_event.set()
                return
            if message_type == "ping":
                channel.send_frame(
                    encode_document(
                        {
                            "type": "pong",
                            "role": config.role,
                            "tls_version": channel.tls_version,
                        }
                    )
                )
                continue
            if message_type != "run":
                channel.send_frame(
                    encode_document(
                        {"type": "error", "role": config.role, "reason": "unknown"}
                    )
                )
                continue
            try:
                runtime = runtime_holder["runtime"]
                inputs = {
                    name: decode_share(runtime.libspu, payload)
                    for name, payload in request["inputs"].items()
                }
                outputs = runtime.run(program=str(request["program"]), inputs=inputs)
                served["runs"] += 1
                response = {
                    "type": "result",
                    "role": config.role,
                    "program": str(request["program"]),
                    "case": str(request.get("case", "")),
                    "tls_version": channel.tls_version,
                    "outputs": {
                        name: encode_share(value) for name, value in outputs.items()
                    },
                }
            except Exception as exc:  # pragma: no cover - reported to the driver
                response = {
                    "type": "error",
                    "role": config.role,
                    "program": str(request.get("program", "")),
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            channel.send_frame(encode_document(response))

    return serve_share_channel(
        identity=identity,
        host=config.share_host,
        port=config.share_port,
        handler=handler,
    )


def _verdict(
    program: str,
    outputs: dict[str, Any],
    reference: dict[str, Any],
    inputs: dict[str, Any],
    *,
    case: str,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"program": program, "case": case}
    if program == "argmax":
        expected = float(reference["index"][0])
        actual = float(outputs["index"].ravel()[0])
        entry["expected"] = expected
        entry["actual"] = actual
        entry["argmax_match"] = actual == expected
        entry["verdict"] = "pass" if actual == expected else "fail"
        entry["tolerance"] = ARGMAX_TOLERANCE
        return entry
    if program == "block":
        checks = {
            "hidden": BLOCK_HIDDEN_TOLERANCE,
            "logits": BLOCK_LOGITS_TOLERANCE,
        }
        failed: list[str] = []
        for name, tolerance in checks.items():
            stats = _error_stats(
                outputs[name], reference[name], atol=tolerance, rtol=tolerance
            )
            entry[name] = stats
            entry[f"{name}_tolerance"] = tolerance
            if stats.get("shape_mismatch") or stats["max_scaled_error"] > 1.0:
                failed.append(name)
        expected_token = float(reference["token"][0])
        actual_token = float(outputs["token"].ravel()[0])
        entry["token"] = {"expected": expected_token, "actual": actual_token}
        entry["argmax_match"] = actual_token == expected_token
        if actual_token != expected_token:
            failed.append("token")
        entry["verdict"] = "pass" if not failed else "fail"
        entry["failed_outputs"] = failed
        return entry
    tolerance = _tolerance(program)
    key = next(iter(reference))
    anchor = inputs["x"] if program == "gelu" else None
    stats = _error_stats(
        outputs[key], reference[key], atol=tolerance, rtol=tolerance, anchor=anchor
    )
    entry.update(stats)
    entry["tolerance"] = tolerance
    if program == "gelu":
        import numpy

        # The program evaluates the tanh form; the exact erf GELU is what the
        # float model uses, so the gap between them is an approximation cost
        # recorded next to the protocol error rather than a failure.
        entry["approximation_error"] = _error_stats(
            reference_gelu_erf(inputs["x"]),
            reference["y"],
            atol=GELU_TOLERANCE,
            rtol=GELU_TOLERANCE,
        )["max_abs_error"]
        delta = numpy.abs(
            numpy.asarray(outputs[key], dtype=numpy.float64)
            - numpy.asarray(reference[key], dtype=numpy.float64)
        )
        entry["tail_error_per_input"] = float(
            (delta / numpy.maximum(numpy.abs(numpy.asarray(inputs["x"])), 1e-9)).max()
        )
    entry["verdict"] = (
        "pass"
        if not stats.get("shape_mismatch") and stats["max_scaled_error"] <= 1.0
        else "fail"
    )
    return entry


def run_node(config: D5NodeConfig) -> int:
    config.out_dir.mkdir(parents=True, exist_ok=True)
    policy = config.policy()
    peer_fingerprints = verify_peer_certificates(
        policy,
        config.peer_certificates,
        ca_bundle_path=config.identity.ca_bundle_path,
    )
    libspu, _ = load_libspu()
    programs = _program_set(config.block_config)
    program_names = [program.name for program in programs]
    runtime = SpuProgramRuntime(
        libspu=libspu,
        policy=policy,
        identity=config.identity,
        programs=programs,
        fraction_bits=config.block_config.fractional_bits,
        present_client_certificate=config.present_client_certificate,
    )
    stop_event = threading.Event()
    holder: dict[str, Any] = {"runtime": runtime}
    served = {"runs": 0}
    server = None
    if config.role != "P0":
        server = _serve(config, holder, stop_event, served)

    started = time.monotonic()
    runtime.start()
    link_seconds = round(time.monotonic() - started, 3)
    log(
        f"{READY_MARKER} "
        + json.dumps(
            {
                "run_id": config.run_id,
                "role": config.role,
                "rank": policy.rank,
                "programs": program_names,
                "share_port": config.share_port if server is not None else None,
                "identity_sha256": runtime.identity_fingerprint["sha256"],
                "peer_certificates": peer_fingerprints,
                "link_seconds": link_seconds,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )

    if config.role != "P0":
        stop_event.wait(timeout=60 * 60)
        if server is not None:
            server.close()
            server.wait(timeout_seconds=2.0)
        teardown_finished = runtime.stop()
        write_json(
            config.out_dir / "node-status.json",
            {
                "run_id": config.run_id,
                "role": config.role,
                "verdicts": "served",
                "runs_served": served["runs"],
                "identity_sha256": runtime.identity_fingerprint["sha256"],
                "peer_certificates": peer_fingerprints,
                "link_seconds": link_seconds,
                "teardown_finished": teardown_finished,
            },
        )
        log(f"{SHUTDOWN_MARKER} {config.role}")
        return 0

    for role in config.peer_roles:
        if role not in config.peer_share_channels:
            raise NodeError(f"no share channel configured for {role}")
        host, port = config.peer_share_channels[role]
        wait_for_port(host, port, timeout_seconds=180.0)
    share_identity = config.share_identity()
    sessions = {
        role: PeerSession(
            role=role,
            host=config.peer_share_channels[role][0],
            port=config.peer_share_channels[role][1],
            identity=share_identity,
            timeout_seconds=180.0,
        )
        for role in config.peer_roles
    }
    pool = ThreadPoolExecutor(max_workers=len(sessions))
    trust = {role: pool.submit(session.run_batch, {"type": "ping"}) for role, session in sessions.items()}
    for role, future in trust.items():
        response = future.result(timeout=180.0)
        if response.get("type") != "pong":
            raise NodeError(f"peer {role} rejected the share-channel handshake")

    grid = build_grid(config.block_config)
    grid_digest = digest_grid(grid)
    entries: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    share_bytes = 0
    try:
        for program in program_names:
            for case in grid[program]:
                inputs = case_inputs(case)
                shares = {name: _split(libspu, runtime.io, value) for name, value in inputs.items()}
                payloads: dict[str, dict[str, Any]] = {}
                for rank, endpoint in enumerate(policy.endpoints):
                    if endpoint.role == config.role:
                        continue
                    payloads[endpoint.role] = {
                        "type": "run",
                        "program": program,
                        "case": case["case"],
                        "inputs": {
                            name: encode_share(party[rank])
                            for name, party in shares.items()
                        },
                    }
                started_run = time.monotonic()
                futures = {
                    role: pool.submit(sessions[role].run_batch, payloads[role])
                    for role in sessions
                }
                own = runtime.run(
                    program=program,
                    inputs={name: party[policy.rank] for name, party in shares.items()},
                )
                responses: dict[str, dict[str, Any]] = {}
                for role, future in futures.items():
                    response = future.result(timeout=600.0)
                    if response.get("type") != "result":
                        raise NodeError(
                            f"peer {role} failed {program}/{case['case']}: "
                            f"{response.get('reason', 'unknown')}"
                        )
                    responses[role] = response
                reference = _reference(program, inputs, config.block_config)
                outputs: dict[str, Any] = {}
                for name in reference:
                    ranked: list[Any] = [None, None, None]
                    ranked[policy.rank] = own[name]
                    for rank, endpoint in enumerate(policy.endpoints):
                        if endpoint.role == config.role:
                            continue
                        ranked[rank] = decode_share(
                            libspu, responses[endpoint.role]["outputs"][name]
                        )
                    outputs[name] = reconstruct(libspu, runtime.io, ranked)  # type: ignore[arg-type]
                elapsed = round((time.monotonic() - started_run) * 1000, 3)
                entry = _verdict(program, outputs, reference, inputs, case=case["case"])
                entry["elapsed_ms"] = elapsed
                entry["share_bytes"] = sum(
                    len(json.dumps(payloads[role])) for role in payloads
                )
                entry["peers"] = [
                    {
                        "role": role,
                        "rtt_ms": responses[role].get("rtt_ms"),
                        "tls_version": responses[role].get("tls_version"),
                    }
                    for role in responses
                ]
                entries.append(entry)
                share_bytes += entry["share_bytes"]
                trace.append(
                    {
                        "program": program,
                        "case": case["case"],
                        "elapsed_ms": elapsed,
                        "share_bytes": entry["share_bytes"],
                    }
                )
                log(f"{program}/{case['case']} verdict={entry['verdict']}")
    finally:
        pool.shutdown(wait=True)
        for role, session in sessions.items():
            try:
                session.run_batch({"type": "shutdown"})
            except Exception:  # pragma: no cover - best effort shutdown
                log(f"shutdown of {role} failed")
        teardown_finished = runtime.stop()
        if not teardown_finished:
            log(f"{config.role}: the collective link teardown did not finish")

    transport_label, inside_enclave = runtime_label()
    failures = [entry for entry in entries if entry["verdict"] != "pass"]
    by_program: dict[str, dict[str, Any]] = {}
    for program in program_names:
        program_entries = [entry for entry in entries if entry["program"] == program]
        by_program[program] = {
            "cases": len(program_entries),
            "passed": sum(1 for entry in program_entries if entry["verdict"] == "pass"),
            "failed": sum(1 for entry in program_entries if entry["verdict"] != "pass"),
            "max_abs_error": max(
                (
                    entry.get("max_abs_error", entry.get("hidden", {}).get("max_abs_error", 0.0))
                    for entry in program_entries
                ),
                default=0.0,
            ),
            "overflow_count": sum(
                int(entry.get("overflow_count", 0))
                + int(entry.get("hidden", {}).get("overflow_count", 0))
                + int(entry.get("logits", {}).get("overflow_count", 0))
                for entry in program_entries
            ),
        }
    summary = {
        "run_id": config.run_id,
        "partition_id": config.partition_id,
        "programs": program_names,
        "seed": config.seed,
        "grid_digest": grid_digest,
        "block": {
            "sequence": config.block_config.sequence,
            "hidden_size": config.block_config.hidden_size,
            "num_heads": config.block_config.num_heads,
            "intermediate_size": config.block_config.intermediate_size,
            "vocab_size": config.block_config.vocab_size,
            "fractional_bits": config.block_config.fractional_bits,
        },
        "cases": len(entries),
        "passed": len(entries) - len(failures),
        "failed": len(failures),
        "by_program": by_program,
        "share_bytes": share_bytes,
        "verdicts": "passed" if not failures else "failed",
    }
    write_json(config.out_dir / "operator-errors.json", summary)
    write_json(config.out_dir / "case-results.json", {"cases": entries})
    write_json(
        config.out_dir / "communication-trace.json",
        {
            "run_id": config.run_id,
            "role": config.role,
            "partition_id": config.partition_id,
            "transport": transport_label,
            "inside_enclave": inside_enclave,
            "attestation_available": Path("/dev/attestation/quote").is_file(),
            "link": policy.to_dict(),
            "link_seconds": link_seconds,
            "share_bytes": share_bytes,
            "runs": trace,
            "note": (
                "Only byte counts, roles, fingerprints and timings are recorded; "
                "no share, key or plaintext input reaches the trace."
            ),
        },
    )
    write_json(
        config.out_dir / "node-status.json",
        {
            "run_id": config.run_id,
            "role": config.role,
            "verdicts": summary["verdicts"],
            "grid_digest": grid_digest,
            "cases": summary["cases"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "identity_sha256": runtime.identity_fingerprint["sha256"],
            "peer_certificates": peer_fingerprints,
            "teardown_finished": teardown_finished,
            "case_digest": sha256_bytes(
                json.dumps(entries, sort_keys=True).encode("utf-8")
            ),
        },
    )
    log(f"{SHUTDOWN_MARKER} {config.role}")
    return 0 if not failures else 1


def _reference(program: str, inputs: dict[str, Any], config: D5Config) -> dict[str, Any]:
    if program == "softmax":
        return {"probs": reference_softmax(inputs["scores"])}
    if program == "layernorm":
        return {"norm": reference_layernorm(inputs["h"], inputs["gamma"], inputs["beta"])}
    if program == "gelu":
        return {"y": reference_gelu(inputs["x"])}
    if program == "argmax":
        return {"index": [reference_argmax(inputs["logits"])]}
    if program == "block":
        return reference_block(inputs, config)
    raise NodeError(f"no reference for program {program!r}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D5 enclave SPU node")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"the node configuration could not be read: {exc}")
        return 2
    try:
        config = D5NodeConfig.from_document(document)
        return run_node(config)
    except (NodeError, SpuBackendError, ValueError) as exc:
        log(f"A122-D5-NODE-REFUSED {type(exc).__name__}: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

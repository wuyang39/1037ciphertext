"""D4 enclave node: one SPU party executing the six-operator program.

The node runs under ``gramine-sgx`` on each of the three instances. It owns two
channels:

* the SPU/YACL/BRPC link, whose TLS context is configured from the KAS-issued
  node certificate and never leaves the enclave, and
* a mutually authenticated share channel that carries this party's input share
  and output share. That channel is what lets P0 act as the data owner without
  handing another party a plaintext input.

P0 drives the grid. Every batch it splits ``x`` and ``y`` into three shares,
pushes one share to each peer, runs its own party, collects the peer output
shares, reconstructs, and compares against the plaintext reference of the test
vectors. P1 and P2 only ever see shares.

The startup path is fail-closed: a certificate whose SAN does not match the
configured role, a peer certificate that does not chain to the KAS CA, a
disabled TLS context, a negative BRPC verify depth, or a minimum version below
TLS 1.3 all abort before a socket is opened.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from infra.d4_vectors import batches, digest_vectors, load_vectors
from infra.evidence import sha256_bytes, write_json
from mpc.spu_backend.spu_link import (
    CLIENT_VERIFY_DEPTH,
    FXP_FRACTION_BITS,
    NodeIdentity,
    SERVER_VERIFY_DEPTH,
    SpuBackendError,
    SpuEndpoint,
    SpuLinkPolicy,
    SpuNodeRuntime,
    decode_share,
    encode_share,
    load_libspu,
    reconstruct,
    split_inputs,
    verify_peer_certificates,
)
from mpc.spu_backend.spu_ops import SPU_OPERATORS, DEFAULT_TOLERANCE, reference_outputs
from mpc.spu_backend.transport import (
    TLSChannelClosed,
    TLSChannelError,
    TLSFrameChannel,
    TLSFrameServer,
    TLSIdentity,
)


READY_MARKER = "A122-D4-NODE-READY"
SHUTDOWN_MARKER = "A122-D4-NODE-DONE"


class NodeError(RuntimeError):
    """The enclave node could not start or could not complete its grid."""


def _log(message: str) -> None:
    print(message, flush=True)


@dataclass(frozen=True)
class NodeConfig:
    """Everything one node needs, already validated by the orchestrator."""

    run_id: str
    role: str
    partition_id: str
    batch: int
    rows: int
    cols: int
    endpoints: tuple[SpuEndpoint, ...]
    identity: NodeIdentity
    peer_certificates: dict[str, Path]
    share_host: str
    share_port: int
    peer_share_channels: dict[str, tuple[str, int]]
    vectors_path: Path | None
    vector_count: int
    out_dir: Path
    present_client_certificate: bool = True
    enable_ssl: bool = True
    server_verify_depth: int = SERVER_VERIFY_DEPTH
    client_verify_depth: int = CLIENT_VERIFY_DEPTH
    fraction_bits: int = FXP_FRACTION_BITS
    tolerance: float = DEFAULT_TOLERANCE
    connect_retry_times: int = 120
    connect_retry_interval_ms: int = 500

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "NodeConfig":
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
            vectors_document = document.get("vectors") or {}
            return cls(
                run_id=str(document["run_id"]),
                role=str(document["role"]),
                partition_id=str(document["partition_id"]),
                batch=int(document["batch"]),
                rows=int(document["rows"]),
                cols=int(document["cols"]),
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
                vectors_path=(
                    Path(str(vectors_document["path"]))
                    if vectors_document.get("path")
                    else None
                ),
                vector_count=int(vectors_document.get("count", 0)),
                out_dir=Path(document["out_dir"]),
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
                fraction_bits=int(document.get("fraction_bits", FXP_FRACTION_BITS)),
                tolerance=float(document.get("tolerance", DEFAULT_TOLERANCE)),
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


def _encode(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _decode(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NodeError("the share channel received invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("type"), str):
        raise NodeError("the share channel message shape is invalid")
    return document


def _wait_for_port(host: str, port: int, *, timeout_seconds: float) -> None:
    import socket

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex((host, port)) == 0:
                return
        time.sleep(0.25)
    raise NodeError(f"peer share channel {host}:{port} never became reachable")


class PeerSession:
    """One TLS connection from P0 to a peer share channel."""

    def __init__(
        self,
        *,
        role: str,
        host: str,
        port: int,
        identity: TLSIdentity,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.role = role
        self.host = host
        self.port = port
        self.identity = identity
        self.timeout_seconds = timeout_seconds

    def run_batch(self, document: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        with TLSFrameChannel.connect(
            host=self.host,
            port=self.port,
            identity=self.identity,
            peer_role=self.role,
            timeout_seconds=self.timeout_seconds,
        ) as channel:
            if channel.tls_version != "TLSv1.3":
                raise NodeError(
                    f"the share channel to {self.role} negotiated "
                    f"{channel.tls_version!r}"
                )
            channel.send_frame(_encode(document))
            response = _decode(channel.receive_frame())
            response["tls_version"] = channel.tls_version
            response["peer_san"] = f"spiffe://a122/{self.role}"
        response["rtt_ms"] = round((time.monotonic() - started) * 1000, 3)
        return response


def _serve_share_channel(
    config: NodeConfig,
    runtime_holder: dict[str, Any],
    stop_event: threading.Event,
) -> TLSFrameServer:
    identity = config.share_identity()

    def handler(channel: TLSFrameChannel) -> None:
        last_error: str | None = None
        while not stop_event.is_set():
            try:
                request = _decode(channel.receive_frame())
            except TLSChannelClosed:
                # P0 opens one connection per request; a close between frames
                # is the end of that request, not a broken handler.
                return
            except (TLSChannelError, NodeError) as exc:
                last_error = str(exc)
                return
            message_type = request.get("type")
            if message_type == "shutdown":
                channel.send_frame(_encode({"type": "bye", "role": config.role}))
                stop_event.set()
                return
            if message_type == "ping":
                channel.send_frame(
                    _encode(
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
                    _encode({"type": "error", "role": config.role, "reason": "unknown"})
                )
                continue
            try:
                runtime = runtime_holder["runtime"]
                outputs = runtime.run(
                    x_share=decode_share(runtime.libspu, request["x_share"]),
                    y_share=decode_share(runtime.libspu, request["y_share"]),
                )
                response = {
                    "type": "result",
                    "role": config.role,
                    "batch_id": int(request["batch_id"]),
                    "tls_version": channel.tls_version,
                    "shares": {
                        name: encode_share(outputs[name]) for name in SPU_OPERATORS
                    },
                }
            except Exception as exc:  # pragma: no cover - reported to P0
                last_error = f"{type(exc).__name__}: {exc}"
                response = {
                    "type": "error",
                    "role": config.role,
                    "batch_id": int(request.get("batch_id", -1)),
                    "reason": "operator run failed",
                }
            channel.send_frame(_encode(response))
        if last_error:  # pragma: no cover - diagnostic only
            _log(f"{config.role}: share channel closed after {last_error}")

    server = TLSFrameServer(
        identity=identity,
        handler=handler,
        host=config.share_host,
        port=config.share_port,
    )
    server.start()
    return server


def _tensor_from_batch(
    batch: Sequence[dict[str, Any]],
    *,
    size: int,
    rows: int,
    cols: int,
) -> Any:
    import numpy

    padded = list(batch) + [batch[-1]] * (size - len(batch))
    x = numpy.array([entry["x"] for entry in padded], dtype=numpy.float64)
    y = numpy.array([entry["y"] for entry in padded], dtype=numpy.float64)
    if x.shape != (size, rows, cols) or y.shape != (size, rows, cols):
        raise NodeError("a vector does not match the configured matrix shape")
    return x, y


def _verdicts(
    actual: dict[str, Any],
    x: Any,
    y: Any,
    *,
    valid: int,
    tolerance: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import numpy

    expected = reference_outputs(x, y)
    results: list[dict[str, Any]] = []
    operator_failures = {name: 0 for name in SPU_OPERATORS}
    for index in range(valid):
        mismatched: list[str] = []
        deltas: dict[str, float] = {}
        for name in SPU_OPERATORS:
            got = numpy.asarray(actual[name], dtype=numpy.float64)[index]
            want = expected[name][index]
            if name == "compare":
                ok = numpy.array_equal(got.astype(bool), want.astype(bool))
                delta = 0.0 if ok else 1.0
            else:
                delta = float(numpy.max(numpy.abs(got - want)))
                ok = bool(
                    numpy.allclose(got, want, rtol=tolerance, atol=tolerance)
                )
            deltas[name] = round(delta, 9)
            if not ok:
                mismatched.append(name)
                operator_failures[name] += 1
        results.append(
            {
                "index": index,
                "verdict": "pass" if not mismatched else "fail",
                "mismatched_operators": mismatched,
                "max_abs_delta": deltas,
            }
        )
    summary = {
        "vectors": valid,
        "passed": sum(1 for entry in results if entry["verdict"] == "pass"),
        "failed": sum(1 for entry in results if entry["verdict"] != "pass"),
        "operator_failures": operator_failures,
    }
    return results, summary


def run_node(config: NodeConfig) -> int:
    config.out_dir.mkdir(parents=True, exist_ok=True)
    policy = config.policy()
    peer_fingerprints = verify_peer_certificates(
        policy,
        config.peer_certificates,
        ca_bundle_path=config.identity.ca_bundle_path,
    )
    libspu, _ = load_libspu()
    runtime = SpuNodeRuntime(
        libspu=libspu,
        policy=policy,
        identity=config.identity,
        batch=config.batch,
        rows=config.rows,
        cols=config.cols,
        fraction_bits=config.fraction_bits,
        present_client_certificate=config.present_client_certificate,
    )
    stop_event = threading.Event()
    holder: dict[str, Any] = {"runtime": runtime}
    server: TLSFrameServer | None = None
    if config.role != "P0":
        server = _serve_share_channel(config, holder, stop_event)

    started = time.monotonic()
    runtime.start()
    link_seconds = round(time.monotonic() - started, 3)
    _log(
        f"{READY_MARKER} "
        + json.dumps(
            {
                "run_id": config.run_id,
                "role": config.role,
                "partition_id": config.partition_id,
                "rank": policy.rank,
                "share_port": config.share_port if server is not None else None,
                "identity_sha256": runtime.identity_fingerprint["sha256"],
                "peer_certificates": peer_fingerprints,
                "tls": {
                    "min_version": policy.min_version,
                    "client_verify_depth": policy.client_verify_depth,
                    "server_verify_depth": policy.server_verify_depth,
                    "enable_ssl": policy.enable_ssl,
                    "require_client_certificate": policy.require_client_certificate,
                },
                "link_seconds": link_seconds,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )

    if config.role != "P0":
        # P1/P2 only relay shares; they never see a plaintext input.
        stop_event.wait(timeout=60 * 30)
        if server is not None:
            server.close()
            server.wait(timeout_seconds=2.0)
        runtime.stop()
        _log(f"{SHUTDOWN_MARKER} {config.role}")
        return 0

    if config.vectors_path is None:
        raise NodeError("P0 needs the vector grid")
    vectors = load_vectors(config.vectors_path)
    if config.vector_count and len(vectors) != config.vector_count:
        raise NodeError("the vector grid size does not match the configuration")
    for role in config.peer_roles:
        if role not in config.peer_share_channels:
            raise NodeError(f"no share channel configured for {role}")
        host, port = config.peer_share_channels[role]
        _wait_for_port(host, port, timeout_seconds=120.0)

    share_identity = config.share_identity()
    sessions = {
        role: PeerSession(
            role=role,
            host=config.peer_share_channels[role][0],
            port=config.peer_share_channels[role][1],
            identity=share_identity,
        )
        for role in config.peer_roles
    }
    trust: dict[str, Any] = {}
    trust_pool = ThreadPoolExecutor(max_workers=len(sessions))
    for role, session in sessions.items():
        trust[role] = trust_pool.submit(session.run_batch, {"type": "ping"})
    for role, future in trust.items():
        response = future.result(timeout=120.0)
        if response.get("type") != "pong":
            raise NodeError(f"peer {role} rejected the share-channel handshake")
        if response.get("tls_version") != "TLSv1.3":
            raise NodeError(f"peer {role} negotiated {response.get('tls_version')!r}")
    trust_pool.shutdown(wait=True)

    batch_list = list(batches(vectors, config.batch))
    link_bytes = 0
    batch_trace: list[dict[str, Any]] = []
    verdict_entries: list[dict[str, Any]] = []
    totals = {"passed": 0, "failed": 0}

    pool = ThreadPoolExecutor(max_workers=len(sessions))
    try:
        for batch_id, batch in enumerate(batch_list):
            x, y = _tensor_from_batch(
                batch, size=config.batch, rows=config.rows, cols=config.cols
            )
            x_shares, y_shares = split_inputs(libspu, runtime.io, x=x, y=y)
            # Each peer receives its own share; the sent bytes are counted, the
            # shares themselves never reach the evidence bundle.
            payloads: dict[str, dict[str, Any]] = {}
            for rank, endpoint in enumerate(policy.endpoints):
                if endpoint.role == config.role:
                    continue
                payloads[endpoint.role] = {
                    "type": "run",
                    "batch_id": batch_id,
                    "x_share": encode_share(x_shares[rank]),
                    "y_share": encode_share(y_shares[rank]),
                }
            started_batch = time.monotonic()
            futures = {
                role: pool.submit(sessions[role].run_batch, payloads[role])
                for role in sessions
            }
            own = runtime.run(
                x_share=x_shares[policy.rank],
                y_share=y_shares[policy.rank],
            )
            responses: dict[str, dict[str, Any]] = {}
            for role, future in futures.items():
                response = future.result(timeout=300.0)
                if response.get("type") != "result":
                    raise NodeError(f"peer {role} failed batch {batch_id}")
                responses[role] = response
            actual: dict[str, Any] = {}
            for name in SPU_OPERATORS:
                # The reconstruction expects shares in rank order.
                ranked: list[Any] = [None, None, None]
                ranked[policy.rank] = own[name]
                for rank, endpoint in enumerate(policy.endpoints):
                    if endpoint.role == config.role:
                        continue
                    ranked[rank] = decode_share(
                        libspu, responses[endpoint.role]["shares"][name]
                    )
                actual[name] = reconstruct(libspu, runtime.io, ranked)  # type: ignore[arg-type]
            results, summary = _verdicts(
                actual,
                x,
                y,
                valid=len(batch),
                tolerance=config.tolerance,
            )
            totals["passed"] += summary["passed"]
            totals["failed"] += summary["failed"]
            for entry in results:
                verdict_entries.append(
                    {
                        "index": batch[entry["index"]]["index"],
                        "kind": batch[entry["index"]]["kind"],
                        **entry,
                    }
                )
            share_bytes = sum(len(json.dumps(payloads[role])) for role in payloads)
            link_bytes += share_bytes
            batch_trace.append(
                {
                    "batch_id": batch_id,
                    "vectors": len(batch),
                    "elapsed_ms": round((time.monotonic() - started_batch) * 1000, 3),
                    "share_bytes": share_bytes,
                    "peers": [
                        {
                            "role": role,
                            "tls_version": responses[role].get("tls_version"),
                            "peer_san": responses[role].get("peer_san"),
                            "rtt_ms": responses[role].get("rtt_ms"),
                        }
                        for role in responses
                    ],
                }
            )
            _log(
                f"batch {batch_id + 1}/{len(batch_list)} "
                f"vectors={len(batch)} passed={summary['passed']} "
                f"failed={summary['failed']}"
            )
    finally:
        pool.shutdown(wait=True)
        # BRPC's barrier and link stop are collective, so the peers have to
        # learn that the grid is over before this side waits on them.
        for role, session in sessions.items():
            try:
                session.run_batch({"type": "shutdown"})
            except Exception:  # pragma: no cover - best effort shutdown
                _log(f"shutdown of {role} failed")
        runtime.stop()

    vector_document = {
        "run_id": config.run_id,
        "partition_id": config.partition_id,
        "operators": list(SPU_OPERATORS),
        "batch": config.batch,
        "rows": config.rows,
        "cols": config.cols,
        "fraction_bits": config.fraction_bits,
        "tolerance": config.tolerance,
        "grid_digest": digest_vectors(vectors),
        "count": len(vectors),
        "batches": len(batch_list),
        "summary": {
            **totals,
            "vector_operator_checks": len(vectors) * len(SPU_OPERATORS),
            "verdicts": "passed" if totals["failed"] == 0 else "failed",
        },
        "vectors": verdict_entries,
    }
    write_json(config.out_dir / "rss-vectors.json", vector_document)
    write_json(
        config.out_dir / "communication-trace.json",
        {
            "run_id": config.run_id,
            "partition_id": config.partition_id,
            "role": config.role,
            "transport": "SPU/YACL/BRPC over TLS 1.3 inside Gramine-SGX",
            "link": policy.to_dict(),
            "share_channel": {
                "host": config.share_host,
                "port": config.share_port,
                "tls_version": "TLSv1.3",
                "min_version": "TLS1.3",
            },
            "link_seconds": link_seconds,
            "share_bytes": link_bytes,
            "batches": batch_trace,
            "note": (
                "Only byte counts, roles, fingerprints, and timings are recorded; "
                "no share, key, or plaintext input reaches the trace."
            ),
        },
    )
    write_json(
        config.out_dir / "node-status.json",
        {
            "run_id": config.run_id,
            "role": config.role,
            "verdicts": vector_document["summary"]["verdicts"],
            "grid_digest": vector_document["grid_digest"],
            "identity_sha256": runtime.identity_fingerprint["sha256"],
            "peer_certificates": peer_fingerprints,
            "batch_share_digest": sha256_bytes(
                json.dumps(batch_trace, sort_keys=True).encode("utf-8")
            ),
        },
    )
    _log(f"{SHUTDOWN_MARKER} {config.role}")
    return 0 if totals["failed"] == 0 else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D4 enclave SPU node")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log(f"the node configuration could not be read: {exc}")
        return 2
    try:
        config = NodeConfig.from_document(document)
        return run_node(config)
    except (NodeError, SpuBackendError, ValueError) as exc:
        _log(f"A122-D4-NODE-REFUSED {type(exc).__name__}: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

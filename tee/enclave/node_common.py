"""Plumbing shared by the D4 and D5 enclave nodes.

Both nodes own the same two channels, so the code that talks to them lives
here once: the mutually authenticated TLS share channel one party uses to hand
another its input share and to read back an output share, and the small
helpers that classify where the process is really running. Only the operator
set the node drives differs, and that stays in the node module.
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any, Callable

from mpc.spu_backend.transport import (
    TLSChannelClosed,
    TLSChannelError,
    TLSFrameChannel,
    TLSFrameServer,
    TLSIdentity,
)


class NodeError(RuntimeError):
    """The enclave node could not start or could not complete its grid."""


def log(message: str) -> None:
    print(message, flush=True)


def encode_document(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decode_document(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NodeError("the share channel received invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("type"), str):
        raise NodeError("the share channel message shape is invalid")
    return document


def wait_for_port(host: str, port: int, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex((host, port)) == 0:
                return
        time.sleep(0.25)
    raise NodeError(f"peer share channel {host}:{port} never became reachable")


class PeerSession:
    """One TLS connection from the driver to a peer share channel."""

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
            channel.send_frame(encode_document(document))
            response = decode_document(channel.receive_frame())
            response["tls_version"] = channel.tls_version
            response["peer_san"] = f"spiffe://a122/{self.role}"
        response["rtt_ms"] = round((time.monotonic() - started) * 1000, 3)
        return response


def serve_share_channel(
    *,
    identity: TLSIdentity,
    host: str,
    port: int,
    handler: Callable[[TLSFrameChannel], None],
    threaded: bool = False,
    connection_timeout: float = 10.0,
) -> TLSFrameServer:
    server = TLSFrameServer(
        identity=identity,
        handler=handler,
        host=host,
        port=port,
        threaded=threaded,
        connection_timeout=connection_timeout,
    )
    server.start()
    return server


def runtime_label(
    attestation_root: Path = Path("/dev/attestation"),
) -> tuple[str, bool]:
    """Say where the node is really running.

    The trace must not claim more than it measured. The same module runs as a
    plain host process during the loopback acceptance and inside a Gramine
    enclave once the manifests are in play, so only the second case may say
    "enclave". Gramine exposes its attestation pseudo-files at
    ``/dev/attestation``, which is the marker used here.
    """
    inside_enclave = Path(attestation_root).is_dir()
    where = "inside a Gramine-SGX enclave" if inside_enclave else "in a host process"
    return f"SPU/YACL/BRPC over TLS 1.3 {where}", inside_enclave


__all__ = [
    "NodeError",
    "PeerSession",
    "decode_document",
    "encode_document",
    "log",
    "runtime_label",
    "serve_share_channel",
    "wait_for_port",
]

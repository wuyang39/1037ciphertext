"""Run a real localhost TCP/TLS three-node RSS integration demonstration."""

from __future__ import annotations

import argparse
import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from infra.evidence import build_record, write_json
from infra.local_pki import LocalPKI
from mpc.secure_ops.rss import RSSContext, SharedTensor
from mpc.spu_backend.transport import TLSFrameChannel, TLSFrameServer, TLSIdentity


class LocalNodeError(RuntimeError):
    """The local three-node demonstration failed."""


def _encode_message(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_message(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalNodeError("local node received invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("type"), str):
        raise LocalNodeError("local node message shape is invalid")
    return document


def _request(
    *,
    channel: TLSFrameChannel,
    document: dict[str, Any],
) -> dict[str, Any]:
    channel.send_frame(_encode_message(document))
    return _decode_message(channel.receive_frame())


def _node_handler(role: str):
    def handle(channel: TLSFrameChannel) -> None:
        request = _decode_message(channel.receive_frame())
        message_type = request["type"]
        if message_type == "ping":
            response = {
                "type": "pong",
                "role": role,
                "peer_role": channel.peer_role,
                "tls_version": channel.tls_version,
            }
        elif message_type == "rss_add":
            left = tuple(int(value) for value in request["left_share"])
            right = tuple(int(value) for value in request["right_share"])
            if len(left) != 1 or len(right) != 1:
                raise LocalNodeError("local RSS add expects scalar shares")
            response = {
                "type": "rss_add_result",
                "role": role,
                "peer_role": channel.peer_role,
                "sum_share": [(left[0] + right[0]) & ((1 << 64) - 1)],
            }
        else:
            raise LocalNodeError(f"unsupported local node message: {message_type}")
        channel.send_frame(_encode_message(response))

    return handle


def _sum_share(
    *,
    host: str,
    server: TLSFrameServer,
    identity: TLSIdentity,
    peer_role: str,
    left_share: tuple[int, ...],
    right_share: tuple[int, ...],
) -> tuple[int, ...]:
    with TLSFrameChannel.connect(
        host=host,
        port=server.address[1],
        identity=identity,
        peer_role=peer_role,
    ) as channel:
        if channel.tls_version != "TLSv1.3":
            raise LocalNodeError("local transport did not negotiate TLS 1.3")
        response = _request(
            channel=channel,
            document={
                "type": "rss_add",
                "left_share": list(left_share),
                "right_share": list(right_share),
            },
        )
        if response.get("type") != "rss_add_result":
            raise LocalNodeError("local RSS peer returned an unexpected response")
        return tuple(int(value) for value in response["sum_share"])


def _ping(
    *,
    host: str,
    server: TLSFrameServer,
    identity: TLSIdentity,
    peer_role: str,
) -> dict[str, Any]:
    with TLSFrameChannel.connect(
        host=host,
        port=server.address[1],
        identity=identity,
        peer_role=peer_role,
    ) as channel:
        response = _request(
            channel=channel,
            document={"type": "ping"},
        )
    if response.get("type") != "pong":
        raise LocalNodeError("local node ping failed")
    return response


def run_local_demo(
    *,
    host: str = "127.0.0.1",
    seed: int = 20261011,
    run_id: str = "local-three-node",
) -> dict[str, Any]:
    pki = LocalPKI()
    identities = {
        "P0": pki.identity("P0", allowed_peer_roles=("P1", "P2")),
        "P1": pki.identity("P1", allowed_peer_roles=("P0", "P2")),
        "P2": pki.identity("P2", allowed_peer_roles=("P0", "P1")),
    }
    servers: dict[str, TLSFrameServer] = {}
    with ExitStack() as stack:
        for role in ("P0", "P1", "P2"):
            server = TLSFrameServer(
                identity=identities[role],
                handler=_node_handler(role),
                host=host,
            ).start()
            stack.callback(server.close)
            servers[role] = server

        context = RSSContext(ring_bits=64, seed=seed, reveal_allowed=False)
        left_value = 17
        right_value = 25
        left = context.share(left_value)
        right = context.share(right_value)
        p0_sum = (
            left.shares[0][0] + right.shares[0][0]
        ) & context.mask
        p1_sum = _sum_share(
            host=host,
            server=servers["P1"],
            identity=identities["P0"],
            peer_role="P1",
            left_share=left.shares[1],
            right_share=right.shares[1],
        )
        p2_sum = _sum_share(
            host=host,
            server=servers["P2"],
            identity=identities["P0"],
            peer_role="P2",
            left_share=left.shares[2],
            right_share=right.shares[2],
        )
        p1_to_p2 = _ping(
            host=host,
            server=servers["P2"],
            identity=identities["P1"],
            peer_role="P2",
        )
        combined = SharedTensor(
            (
                (p0_sum,),
                tuple(p1_sum),
                tuple(p2_sum),
            ),
            (),
            context.ring_bits,
        )
        reconstructed = context.reconstruct_signed(combined)
        if reconstructed != left_value + right_value:
            raise LocalNodeError(
                f"local RSS addition mismatch: {reconstructed}"
            )
        for server in servers.values():
            server.close()
        for server in servers.values():
            server.wait(timeout_seconds=1.0)

    details = {
        "mode": "localhost-tcp-tls-three-node",
        "roles": ["P0", "P1", "P2"],
        "ports": {
            role: server.address[1] for role, server in servers.items()
        },
        "directed_links": [
            "P0->P1",
            "P0->P2",
            "P1->P2",
        ],
        "tls_version": p1_to_p2["tls_version"],
        "rss": {
            "ring": "Z_2_64",
            "left": left_value,
            "right": right_value,
            "expected": left_value + right_value,
            "reconstructed": reconstructed,
        },
        "claim_boundary": {
            "real_tcp_tls": True,
            "host_process_tls_termination": True,
            "enclave_internal_tls": False,
            "sgx_acceptance": False,
        },
    }
    return build_record(
        run_id=run_id,
        phase="D4-local",
        outcome="passed_local_software_integration",
        command="python -m infra.local_three_node",
        details=details,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--seed", type=int, default=20261011)
    parser.add_argument("--run-id", default="local-three-node")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    record = run_local_demo(host=args.host, seed=args.seed, run_id=args.run_id)
    if args.output:
        write_json(args.output, record)
    else:
        print(json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["LocalNodeError", "run_local_demo"]

"""Build the D5 run workspace: the PKI and one node configuration per role.

The D5 run reuses the D4 trust material: the same KAS CA signs the three role
certificates, and the same fail-closed policy applies to the SPU link, so the
workspace builder here only adds the block geometry and the case seed the D5
node needs. The tree is plain JSON and PEM so it can be copied between the
instances without a shared filesystem.

Usage::

    python -m infra.d5_workspace --mode provision \
        --root ~/a122-d5/three/workspace --run-id d5-3host-<stamp> \
        --cluster-file /tmp/<run-id>-cluster.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d4_pki import NodeCredentials, provision_cluster
from infra.d5_vectors import D5_SEED
from infra.evidence import write_json
from mpc.spu_backend.d5_program import D5Config
from mpc.spu_backend.spu_link import (
    CLIENT_VERIFY_DEPTH,
    SERVER_VERIFY_DEPTH,
)


ROLES: tuple[str, str, str] = ("P0", "P1", "P2")


class D5WorkspaceError(ValueError):
    """The D5 workspace could not be assembled."""


def _node_config(
    *,
    run_id: str,
    role: str,
    cluster: Mapping[str, Mapping[str, Any]],
    credentials: Mapping[str, NodeCredentials],
    root: Path,
    block: D5Config,
    seed: int,
    connect_retry_times: int = 120,
    connect_retry_interval_ms: int = 500,
) -> dict[str, Any]:
    identity = credentials[role]
    peers = [other for other in ROLES if other != role]
    return {
        "config_version": "a122-d5-node-v1",
        "run_id": run_id,
        "role": role,
        "partition_id": f"a122-d5-{run_id}",
        "endpoints": [
            {
                "role": other,
                "host": str(cluster[other]["host"]),
                "port": int(cluster[other]["brpc_port"]),
            }
            for other in ROLES
        ],
        "identity": {
            "role": role,
            "certificate": str(identity.certificate_path),
            "private_key": str(identity.private_key_path),
            "ca_bundle": str(identity.ca_bundle_path),
        },
        "peer_certificates": {
            other: str(credentials[other].certificate_path) for other in peers
        },
        "share_channel": {
            "host": str(cluster[role]["host"]),
            "port": int(cluster[role]["share_port"]),
        },
        "peer_share_channels": {
            other: {
                "host": str(cluster[other]["host"]),
                "port": int(cluster[other]["share_port"]),
            }
            for other in peers
        },
        "out_dir": str(root / "out" / role),
        "block": asdict(block),
        "seed": int(seed),
        "present_client_certificate": True,
        "enable_ssl": True,
        "server_verify_depth": SERVER_VERIFY_DEPTH,
        "client_verify_depth": CLIENT_VERIFY_DEPTH,
        "connect_retry_times": connect_retry_times,
        "connect_retry_interval_ms": connect_retry_interval_ms,
    }


def build_workspace(
    root: Path,
    *,
    run_id: str,
    cluster: Mapping[str, Mapping[str, Any]],
    block: D5Config | None = None,
    seed: int = D5_SEED,
    release_id: str = "a122-d5",
) -> dict[str, Any]:
    """Create the whole D5 workspace and return its manifest."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    missing = [role for role in ROLES if role not in cluster]
    if missing:
        raise D5WorkspaceError(
            "the cluster description is missing: " + ", ".join(missing)
        )
    block = block or D5Config()
    credentials = provision_cluster(root / "pki", roles=ROLES, release_id=release_id)
    configs = root / "configs"
    configs.mkdir(parents=True, exist_ok=True)
    for role in ROLES:
        write_json(
            configs / f"{role}.json",
            _node_config(
                run_id=run_id,
                role=role,
                cluster=cluster,
                credentials=credentials,
                root=root,
                block=block,
                seed=seed,
            ),
        )
    manifest = {
        "run_id": run_id,
        "workspace": str(root),
        "block": asdict(block),
        "seed": seed,
        "cluster": {
            role: {
                "host": str(cluster[role]["host"]),
                "brpc_port": int(cluster[role]["brpc_port"]),
                "share_port": int(cluster[role]["share_port"]),
            }
            for role in ROLES
        },
        "certificates": {
            role: {
                "certificate": str(credentials[role].certificate_path),
                "sha256_pem": credentials[role].certificate_sha256,
                "san_role": credentials[role].san_role,
                "lease_expires_utc": credentials[role].lease_expires_utc,
            }
            for role in ROLES
        },
        "ca_certificate": str(root / "pki" / "ca" / "ca-cert.pem"),
        "configs": {role: str(configs / f"{role}.json") for role in ROLES},
    }
    write_json(root / "workspace.json", manifest)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D5 workspace builder")
    parser.add_argument("--mode", choices=("provision",), default="provision")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--cluster-file", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=D5_SEED)
    parser.add_argument("--sequence", type=int, default=D5Config().sequence)
    parser.add_argument("--hidden-size", type=int, default=D5Config().hidden_size)
    parser.add_argument("--num-heads", type=int, default=D5Config().num_heads)
    parser.add_argument(
        "--intermediate-size", type=int, default=D5Config().intermediate_size
    )
    parser.add_argument("--vocab-size", type=int, default=D5Config().vocab_size)
    args = parser.parse_args(argv)
    cluster = json.loads(Path(args.cluster_file).read_text(encoding="utf-8"))
    block = D5Config(
        sequence=args.sequence,
        hidden_size=args.hidden_size,
        num_heads=args.num_heads,
        intermediate_size=args.intermediate_size,
        vocab_size=args.vocab_size,
    )
    manifest = build_workspace(
        args.root, run_id=args.run_id, cluster=cluster, block=block, seed=args.seed
    )
    print(json.dumps({"workspace": manifest["workspace"], "run_id": manifest["run_id"]}))
    return 0


__all__ = [
    "D5WorkspaceError",
    "ROLES",
    "build_workspace",
]


if __name__ == "__main__":
    raise SystemExit(main())

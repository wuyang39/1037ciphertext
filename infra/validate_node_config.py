"""Validate a frozen A1-22 node runtime config.

The JSON Schema in ``contracts/schemas/node_config.schema.json`` freezes the
shape.  This module enforces the parts a schema cannot express: the role to
port mapping, the exact peer set, and the SPIFFE SAN allowlist.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from contracts import validate_contract
from infra.evidence import sha256_bytes, write_json


CONFIG_VERSION = "a122-node-config-v1"
ROLES: tuple[str, str, str] = ("P0", "P1", "P2")

# Frozen ports. Node-to-node links are private-network only; health endpoints
# bind to localhost so a remote peer can never read node state.
SPU_PORTS = {"P0": 47100, "P1": 47101, "P2": 47102}
HEALTH_PORTS = {"P0": 47110, "P1": 47111, "P2": 47112}
KAS_PORT = 8443
AUDIT_PORT = 8444


class NodeConfigError(ValueError):
    """The node config violates the frozen deployment interface."""


def role_san(role: str) -> str:
    return f"spiffe://a122/{role}"


def validate_node_config(document: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one node config and return a short evidence summary."""
    validate_contract("node_config", document)

    role = document["node_role"]
    expected_peers = {peer for peer in ROLES if peer != role}

    listen_port = int(document["listen"]["port"])
    if listen_port != SPU_PORTS[role]:
        raise NodeConfigError(
            f"{role} must listen on the frozen SPU port {SPU_PORTS[role]}"
        )

    peers = document["peers"]
    peer_roles = [peer["role"] for peer in peers]
    if len(set(peer_roles)) != len(peer_roles):
        raise NodeConfigError("peer roles must be unique")
    if set(peer_roles) != expected_peers:
        raise NodeConfigError(
            f"{role} must declare exactly the peers {sorted(expected_peers)}"
        )

    for peer in peers:
        peer_role = peer["role"]
        if int(peer["port"]) != SPU_PORTS[peer_role]:
            raise NodeConfigError(
                f"peer {peer_role} must use the frozen SPU port {SPU_PORTS[peer_role]}"
            )
        if peer["san"] != role_san(peer_role):
            raise NodeConfigError(f"peer {peer_role} SAN must be {role_san(peer_role)}")

    allowlist = set(document["tls"]["role_san_allowlist"])
    expected_allowlist = {role_san(peer) for peer in expected_peers}
    if allowlist != expected_allowlist:
        raise NodeConfigError(
            "role_san_allowlist must contain exactly the peer roles, not self"
        )
    if role_san(role) in allowlist:
        raise NodeConfigError("a node must never allow its own SAN")

    if document["kas"]["base_url"].endswith("/"):
        raise NodeConfigError("kas.base_url must not end with a slash")

    return {
        "valid": True,
        "config_version": CONFIG_VERSION,
        "node_role": role,
        "listen_port": listen_port,
        "health_port": HEALTH_PORTS[role],
        "peer_roles": sorted(expected_peers),
        "share_epoch": int(document["share_epoch"]),
        "sha256": sha256_bytes(
            json.dumps(
                document,
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
            ).encode("utf-8")
        ),
    }


def load_node_config(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NodeConfigError("node config is not readable JSON") from exc
    if not isinstance(document, dict):
        raise NodeConfigError("node config must be a JSON object")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = validate_node_config(load_node_config(args.config))
    except (OSError, ValueError) as exc:
        print(f"node config validation failed: {exc}", file=sys.stderr)
        return 1
    if args.output:
        write_json(args.output, result)
    else:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUDIT_PORT",
    "CONFIG_VERSION",
    "HEALTH_PORTS",
    "KAS_PORT",
    "NodeConfigError",
    "ROLES",
    "SPU_PORTS",
    "load_node_config",
    "role_san",
    "validate_node_config",
]

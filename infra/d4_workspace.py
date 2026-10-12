"""Build the D4 run workspace: PKI, vector grid, and node configurations.

One workspace drives both the loopback pre-flight and the three-host
acceptance:

* ``pki/`` holds the KAS CA and the three role certificates,
* ``vectors.json`` is the shared grid every party agrees on,
* ``configs/<role>.json`` is the positive node configuration, and
* ``negative/`` holds the mutated configurations for the fail-closed cases.

The workspace is plain JSON and PEM so it can be copied between the instances
without a shared filesystem.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from infra.d4_pki import (
    NodeCredentials,
    issue_node_credentials,
    provision_cluster,
)
from infra.d4_vectors import (
    DEFAULT_COLS,
    DEFAULT_COUNT,
    DEFAULT_ROWS,
    DEFAULT_SEED,
    generate_vectors,
    write_vectors,
)
from infra.evidence import write_json
from mpc.spu_backend.spu_link import (
    CLIENT_VERIFY_DEPTH,
    SERVER_VERIFY_DEPTH,
    SpuEndpoint,
)


ROLES: tuple[str, str, str] = ("P0", "P1", "P2")
DEFAULT_BATCH = 64

NEGATIVE_CASES: tuple[str, ...] = (
    "plaintext",
    "wrong-ca",
    "wrong-san",
    "no-client-cert",
    "tls-disabled",
)
"""Fail-closed cases required by the D4 acceptance gate.

``plaintext`` probes the running listeners; the other four mutate a node
configuration and require the runtime or its peers to refuse the link.
"""

EXPECTED_REFUSALS: dict[str, str] = {
    "wrong-ca": "was not signed by the KAS CA",
    "wrong-san": "SAN does not match its role",
    "no-client-cert": "certificate",
    "tls-disabled": "must not run without TLS",
}


class WorkspaceError(ValueError):
    """The D4 workspace could not be assembled."""


@dataclass(frozen=True)
class ClusterNode:
    """One instance in the D4 cluster."""

    role: str
    host: str
    brpc_port: int
    share_port: int

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ClusterNode":
        try:
            role = str(document["role"])
            if role not in ROLES:
                raise WorkspaceError(f"unknown cluster role: {role}")
            return cls(
                role=role,
                host=str(document["host"]),
                brpc_port=int(document.get("brpc_port", 47100 + ROLES.index(role))),
                share_port=int(document.get("share_port", 47200 + ROLES.index(role))),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspaceError(f"the cluster node document is invalid: {exc}") from exc

    def endpoint(self) -> SpuEndpoint:
        return SpuEndpoint(role=self.role, host=self.host, port=self.brpc_port)


def _node_config(
    *,
    run_id: str,
    node: ClusterNode,
    nodes: Mapping[str, ClusterNode],
    credentials: Mapping[str, NodeCredentials],
    work_root: Path,
    vectors_path: Path | None,
    vector_count: int,
    batch: int,
    rows: int,
    cols: int,
    peer_certificates: Mapping[str, Path] | None = None,
    present_client_certificate: bool = True,
    enable_ssl: bool = True,
    connect_retry_times: int = 120,
    connect_retry_interval_ms: int = 500,
) -> dict[str, Any]:
    identity = credentials[node.role]
    peers = {
        role: nodes[role] for role in ROLES if role != node.role
    }
    document: dict[str, Any] = {
        "config_version": "a122-d4-node-v1",
        "run_id": run_id,
        "role": node.role,
        "partition_id": f"a122-d4-{run_id}",
        "batch": batch,
        "rows": rows,
        "cols": cols,
        "endpoints": [
            {
                "role": role,
                "host": nodes[role].host,
                "port": nodes[role].brpc_port,
            }
            for role in ROLES
        ],
        "identity": {
            "role": node.role,
            "certificate": str(identity.certificate_path),
            "private_key": str(identity.private_key_path),
            "ca_bundle": str(identity.ca_bundle_path),
        },
        "peer_certificates": {
            role: str(
                (peer_certificates or {}).get(
                    role, credentials[role].certificate_path
                )
            )
            for role in peers
        },
        "share_channel": {"host": node.host, "port": node.share_port},
        "peer_share_channels": {
            role: {"host": peers[role].host, "port": peers[role].share_port}
            for role in peers
        },
        "vectors": (
            {"path": str(vectors_path), "count": vector_count}
            if vectors_path is not None
            else None
        ),
        "out_dir": str(work_root / "out" / node.role),
        "present_client_certificate": present_client_certificate,
        "enable_ssl": enable_ssl,
        "server_verify_depth": SERVER_VERIFY_DEPTH,
        "client_verify_depth": CLIENT_VERIFY_DEPTH,
        "connect_retry_times": connect_retry_times,
        "connect_retry_interval_ms": connect_retry_interval_ms,
    }
    return document


def build_workspace(
    root: Path,
    *,
    run_id: str,
    cluster: Mapping[str, Mapping[str, Any]],
    vector_count: int = DEFAULT_COUNT,
    batch: int = DEFAULT_BATCH,
    rows: int = DEFAULT_ROWS,
    cols: int = DEFAULT_COLS,
    seed: int = DEFAULT_SEED,
    release_id: str = "a122-d4",
) -> dict[str, Any]:
    """Create the whole workspace and return its manifest."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    missing = [role for role in ROLES if role not in cluster]
    if missing:
        raise WorkspaceError(
            "the cluster description is missing: " + ", ".join(missing)
        )
    nodes = {
        role: ClusterNode.from_document({**dict(cluster[role]), "role": role})
        for role in ROLES
    }

    credentials = provision_cluster(
        root / "pki",
        roles=ROLES,
        release_id=release_id,
    )
    foreign_key, foreign_certificate = _foreign_authority(root)
    foreign_leaf = issue_node_credentials(
        ca_key_path=foreign_key,
        ca_certificate_path=foreign_certificate,
        role="P2",
        out_dir=root / "negative" / "wrong-ca",
        release_id=release_id,
    )
    wrong_san_leaf = issue_node_credentials(
        ca_key_path=root / "pki" / "ca" / "ca-key.pem",
        ca_certificate_path=root / "pki" / "ca" / "ca-cert.pem",
        role="P2",
        san_role="P1",
        out_dir=root / "negative" / "wrong-san",
        release_id=release_id,
    )

    vectors = generate_vectors(
        count=vector_count, rows=rows, cols=cols, seed=seed
    )
    vectors_path = root / "vectors.json"
    grid_digest = write_vectors(vectors_path, vectors)

    configs_root = root / "configs"
    configs_root.mkdir(parents=True, exist_ok=True)
    for role in ROLES:
        document = _node_config(
            run_id=run_id,
            node=nodes[role],
            nodes=nodes,
            credentials=credentials,
            work_root=root,
            vectors_path=vectors_path if role == "P0" else None,
            vector_count=vector_count,
            batch=batch,
            rows=rows,
            cols=cols,
        )
        write_json(configs_root / f"{role}.json", document)

    negative_root = root / "negative"
    _write_negative_configs(
        negative_root=negative_root,
        run_id=run_id,
        nodes=nodes,
        credentials=credentials,
        work_root=root,
        vector_count=vector_count,
        batch=batch,
        rows=rows,
        cols=cols,
        vectors_path=vectors_path,
        foreign_leaf_certificate=foreign_leaf.certificate_path,
        wrong_san_certificate=wrong_san_leaf.certificate_path,
    )

    manifest = {
        "run_id": run_id,
        "workspace": str(root),
        "vector_count": vector_count,
        "grid_digest": grid_digest,
        "batch": batch,
        "rows": rows,
        "cols": cols,
        "seed": seed,
        "cluster": {
            role: {
                "host": nodes[role].host,
                "brpc_port": nodes[role].brpc_port,
                "share_port": nodes[role].share_port,
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
        "vectors": str(vectors_path),
        "configs": {role: str(configs_root / f"{role}.json") for role in ROLES},
        "negative_configs": {
            case: str(negative_root / f"{case}.json")
            for case in NEGATIVE_CASES
            if case != "plaintext"
        },
    }
    write_json(root / "workspace.json", manifest)
    return manifest


def _foreign_authority(root: Path) -> tuple[Path, Path]:
    from infra.d4_pki import provision_negative_authority

    return provision_negative_authority(root)


def loopback_cluster(
    *,
    host: str = "127.0.0.1",
    brpc_base: int = 47100,
    share_base: int = 47200,
) -> dict[str, dict[str, Any]]:
    """Describe the single-host layout used for the pre-flight and negatives."""
    return {
        role: {
            "host": host,
            "brpc_port": brpc_base + index,
            "share_port": share_base + index,
        }
        for index, role in enumerate(ROLES)
    }


def _write_negative_configs(
    *,
    negative_root: Path,
    run_id: str,
    nodes: Mapping[str, ClusterNode],
    credentials: Mapping[str, NodeCredentials],
    work_root: Path,
    vector_count: int,
    batch: int,
    rows: int,
    cols: int,
    vectors_path: Path,
    foreign_leaf_certificate: Path,
    wrong_san_certificate: Path,
) -> None:
    negative_root.mkdir(parents=True, exist_ok=True)
    base = dict(
        run_id=run_id,
        nodes=nodes,
        credentials=credentials,
        work_root=work_root / "negative",
        vector_count=vector_count,
        batch=batch,
        rows=rows,
        cols=cols,
    )
    write_json(
        negative_root / "wrong-ca.json",
        _node_config(
            node=nodes["P0"],
            vectors_path=vectors_path,
            peer_certificates={"P1": credentials["P1"].certificate_path,
                               "P2": foreign_leaf_certificate},
            connect_retry_times=8,
            **base,
        ),
    )
    write_json(
        negative_root / "wrong-san.json",
        _node_config(
            node=nodes["P0"],
            vectors_path=vectors_path,
            peer_certificates={"P1": credentials["P1"].certificate_path,
                               "P2": wrong_san_certificate},
            connect_retry_times=8,
            **base,
        ),
    )
    write_json(
        negative_root / "no-client-cert.json",
        _node_config(
            node=nodes["P0"],
            vectors_path=vectors_path,
            present_client_certificate=False,
            connect_retry_times=6,
            **base,
        ),
    )
    write_json(
        negative_root / "tls-disabled.json",
        _node_config(
            node=nodes["P0"],
            vectors_path=vectors_path,
            enable_ssl=False,
            connect_retry_times=6,
            **base,
        ),
    )


def load_workspace(root: Path) -> dict[str, Any]:
    path = Path(root) / "workspace.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"the workspace manifest is unreadable: {exc}") from exc


__all__ = [
    "DEFAULT_BATCH",
    "EXPECTED_REFUSALS",
    "NEGATIVE_CASES",
    "ROLES",
    "ClusterNode",
    "WorkspaceError",
    "build_workspace",
    "load_workspace",
    "loopback_cluster",
]

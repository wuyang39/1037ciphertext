"""Build the D6 run workspace: identities, plan, tokenizer and model shares.

D6 needs four identities rather than three, because the client is a party to
the protocol even though it is not an SPU party: it has its own share-channel
certificate and its own SM2 certificate. Both are issued here.

The model is split the way a real deployment splits one: a dealer produces the
three additive shares in one place, writes each party's slice to its own file,
and every node is handed exactly one of them. The staged slices are what the
driver is responsible for distributing and for removing afterwards, and the
driver records that it did.

The slices live under ``<workspace>/shares`` so one tarball carries the whole
run, and so the enclave manifest's trusted workspace pins the exact shares the
node loads rather than leaving the model outside the measurement.

Only the SM2 CA's *public* key reaches a node config. The private half, and the
KAS ticket signing key, stay on the side that plays KAS, so a node cannot mint
the very credentials it is asked to verify.

Usage::

    python -m infra.d6_workspace --mode provision \
        --root ~/a122-d6/three --run-id d6-3host-<stamp> \
        --cluster-file /tmp/<run-id>-cluster.json \
        --session-root /dev/shm/a122-d6/<run-id>
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from client.tokenizer import WordTokenizer
from contracts.d6_session import ModelManifest, SessionPlan
from crypto.certificates import SM2CertificateAuthority
from crypto.sm2 import SM2KeyPair
from infra.d4_pki import NodeCredentials, provision_cluster
from infra.d6_vectors import (
    D6_GEOMETRY,
    D6_LENGTH_BOUND,
    D6_MAX_NEW_TOKENS,
    D6_SEED,
    WEIGHT_TENSORS,
    build_weights,
)
from infra.evidence import write_json
from mpc.spu_backend.spu_link import CLIENT_VERIFY_DEPTH, SERVER_VERIFY_DEPTH


ROLES: tuple[str, str, str] = ("P0", "P1", "P2")
CLIENT = "C"
CLIENT_TTL_HOURS = 24
NODE_TTL_HOURS = 24
DEFAULT_SESSION_BASE = "/dev/shm/a122-d6"


class D6WorkspaceError(ValueError):
    """The D6 workspace could not be assembled."""


def _node_config(
    *,
    run_id: str,
    role: str,
    cluster: Mapping[str, Mapping[str, Any]],
    credentials: Mapping[str, NodeCredentials],
    root: Path,
    session_root: str,
    plan: SessionPlan,
    manifest: ModelManifest,
    node_key: SM2KeyPair,
    node_certificate: Any,
    kas_public_key: str,
    authority_public_key: str,
    weights_path: Path,
    connect_retry_times: int = 120,
    connect_retry_interval_ms: int = 500,
) -> dict[str, Any]:
    identity = credentials[role]
    peers = [other for other in ROLES if other != role]
    return {
        "config_version": "a122-d6-node-v1",
        "run_id": run_id,
        "role": role,
        "partition_id": f"a122-d6-{run_id}",
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
        "out_dir": str(root / "out" / role),
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "weights": str(weights_path),
        "sm2_identity": {
            "private_key": node_key.private_key,
            "public_key": node_key.public_key,
        },
        "sm2_certificate": node_certificate.to_dict(),
        "kas_public_key": kas_public_key,
        "client_authority_public_key": authority_public_key,
        "session_dir": f"{session_root.rstrip('/')}/{role}",
        "seed": D6_SEED,
        "present_client_certificate": True,
        "enable_ssl": True,
        "server_verify_depth": SERVER_VERIFY_DEPTH,
        "client_verify_depth": CLIENT_VERIFY_DEPTH,
        "connect_retry_times": connect_retry_times,
        "connect_retry_interval_ms": connect_retry_interval_ms,
        "spill_session_state": True,
    }


def _client_config(
    *,
    run_id: str,
    cluster: Mapping[str, Mapping[str, Any]],
    client: NodeCredentials,
    plan: SessionPlan,
    manifest: ModelManifest,
    tokenizer: WordTokenizer,
    node_public_keys: Mapping[str, str],
    kas_public_key: str,
    authority_public_key: str,
    root: Path,
) -> dict[str, Any]:
    return {
        "config_version": "a122-d6-client-v1",
        "run_id": run_id,
        "role": CLIENT,
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "tokenizer": tokenizer.to_dict(),
        "nodes": {
            role: {
                "share_host": str(cluster[role]["host"]),
                "share_port": int(cluster[role]["share_port"]),
                "identity_public_key": node_public_keys[role],
            }
            for role in ROLES
        },
        "identity": {
            "role": CLIENT,
            "certificate": str(client.certificate_path),
            "private_key": str(client.private_key_path),
            "ca_bundle": str(client.ca_bundle_path),
        },
        "kas_public_key": kas_public_key,
        "client_authority_public_key": authority_public_key,
        "out_dir": str(root / "out" / CLIENT),
    }


def build_workspace(
    root: Path,
    *,
    run_id: str,
    cluster: Mapping[str, Mapping[str, Any]],
    seed: int = D6_SEED,
    release_id: str = "a122-d6",
    max_new_tokens: int = D6_MAX_NEW_TOKENS,
    session_root: str | None = None,
    tokenizer: WordTokenizer | None = None,
    splitter: Callable[[Any], Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Create the whole D6 workspace and return its manifest.

    ``splitter`` is the only part that needs the SPU runtime; a test can pass
    its own and exercise everything else.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    session_root = (session_root or f"{DEFAULT_SESSION_BASE}/{run_id}").rstrip("/")
    missing = [role for role in ROLES if role not in cluster]
    if missing:
        raise D6WorkspaceError(
            "the cluster description is missing: " + ", ".join(missing)
        )
    tokenizer = tokenizer or WordTokenizer()
    manifest = ModelManifest(
        model_version="tiny-decoder-d6-v1",
        weight_seed=int(seed),
        sequence=D6_GEOMETRY["sequence"],
        hidden_size=D6_GEOMETRY["hidden_size"],
        num_heads=D6_GEOMETRY["num_heads"],
        intermediate_size=D6_GEOMETRY["intermediate_size"],
        vocab_size=tokenizer.vocab_size,
        tokenizer_digest=tokenizer.vocabulary_digest,
        fractional_bits=D6_GEOMETRY["fractional_bits"],
    )
    plan = SessionPlan.for_manifest(
        manifest,
        release_id=release_id,
        share_epoch=1,
        max_new_tokens=int(max_new_tokens),
        length_bound=D6_LENGTH_BOUND,
    )
    credentials = provision_cluster(
        root / "pki", roles=(*ROLES, CLIENT), release_id=release_id
    )
    authority_key = SM2KeyPair.generate()
    authority = SM2CertificateAuthority(authority_key)
    kas_key = SM2KeyPair.generate()
    now = dt.datetime.now(dt.timezone.utc)
    node_keys = {role: SM2KeyPair.generate() for role in ROLES}
    node_certificates = {
        role: authority.issue(
            role=role,
            release_id=release_id,
            public_key=node_keys[role].public_key,
            now=now,
            ttl=dt.timedelta(hours=NODE_TTL_HOURS),
        )
        for role in ROLES
    }

    weights = build_weights(manifest.weight_seed)
    if splitter is None:  # pragma: no cover - needs the SPU runtime
        from mpc.spu_backend.sharing import make_splitter
        from mpc.spu_backend.spu_link import load_libspu, make_io, runtime_config

        libspu, _ = load_libspu()
        splitter = make_splitter(
            libspu, make_io(libspu, runtime_config(libspu, fraction_bits=manifest.fractional_bits))
        )
    shares_root = root / "shares"
    shares_root.mkdir(parents=True, exist_ok=True)
    share_paths: dict[str, Path] = {}
    for role in ROLES:
        share_paths[role] = shares_root / f"{role}.json"
    bundles: dict[str, dict[str, str]] = {role: {} for role in ROLES}
    for name, _kind in WEIGHT_TENSORS:
        parts = list(splitter(weights[name]))
        if len(parts) != len(ROLES):
            raise D6WorkspaceError("the splitter did not return three shares")
        for index, role in enumerate(ROLES):
            bundles[role][name] = parts[index]
    for role in ROLES:
        write_json(
            share_paths[role],
            {
                "run_id": run_id,
                "role": role,
                "tensors": bundles[role],
            },
        )

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
                session_root=session_root,
                plan=plan,
                manifest=manifest,
                node_key=node_keys[role],
                node_certificate=node_certificates[role],
                kas_public_key=kas_key.public_key,
                authority_public_key=authority.public_key,
                weights_path=share_paths[role],
            ),
        )
    client_config_path = configs / f"{CLIENT}.json"
    write_json(
        client_config_path,
        _client_config(
            run_id=run_id,
            cluster=cluster,
            client=credentials[CLIENT],
            plan=plan,
            manifest=manifest,
            tokenizer=tokenizer,
            node_public_keys={role: node_keys[role].public_key for role in ROLES},
            kas_public_key=kas_key.public_key,
            authority_public_key=authority.public_key,
            root=root,
        ),
    )
    # The KAS and CA private halves stay on the operator side; a node config
    # only ever carries their public keys.
    write_json(
        root / "kas.json",
        {
            "run_id": run_id,
            "kas_signing_private_key": kas_key.private_key,
            "kas_public_key": kas_key.public_key,
            "client_authority_private_key": authority_key.private_key,
            "client_authority_public_key": authority.public_key,
            "client_transport": {
                "certificate": str(credentials[CLIENT].certificate_path),
                "private_key": str(credentials[CLIENT].private_key_path),
                "ca_bundle": str(credentials[CLIENT].ca_bundle_path),
            },
        },
    )
    manifest_document = {
        "run_id": run_id,
        "workspace": str(root),
        "session_root": session_root,
        "session_dirs": {
            role: f"{session_root}/{role}" for role in ROLES
        },
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "tokenizer": tokenizer.to_dict(),
        "cluster": {
            role: {
                "host": str(cluster[role]["host"]),
                "brpc_port": int(cluster[role]["brpc_port"]),
                "share_port": int(cluster[role]["share_port"]),
            }
            for role in ROLES
        },
        "transport_certificates": {
            role: {
                "certificate": str(credentials[role].certificate_path),
                "sha256_pem": credentials[role].certificate_sha256,
                "san_role": credentials[role].san_role,
            }
            for role in (*ROLES, CLIENT)
        },
        "sm2_public_keys": {
            "nodes": {role: node_keys[role].public_key for role in ROLES},
            "client_authority": authority.public_key,
            "kas": kas_key.public_key,
        },
        "shares": {role: str(path) for role, path in share_paths.items()},
        "configs": {
            **{role: str(configs / f"{role}.json") for role in ROLES},
            CLIENT: str(client_config_path),
        },
        "weights": {name: list(weights[name].shape) for name, _ in WEIGHT_TENSORS},
    }
    write_json(root / "workspace.json", manifest_document)
    return manifest_document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D6 workspace builder")
    parser.add_argument("--mode", choices=("provision",), default="provision")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--cluster-file", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=D6_SEED)
    parser.add_argument("--max-new-tokens", type=int, default=D6_MAX_NEW_TOKENS)
    parser.add_argument("--session-root", default=None)
    args = parser.parse_args(argv)
    cluster = json.loads(Path(args.cluster_file).read_text(encoding="utf-8"))
    manifest = build_workspace(
        args.root,
        run_id=args.run_id,
        cluster=cluster,
        seed=args.seed,
        max_new_tokens=args.max_new_tokens,
        session_root=args.session_root,
    )
    print(
        json.dumps(
            {
                "workspace": manifest["workspace"],
                "run_id": manifest["run_id"],
                "model_manifest_hash": manifest["plan"]["model_manifest_hash"],
                "session_root": manifest["session_root"],
            }
        )
    )
    return 0


__all__ = ["D6WorkspaceError", "ROLES", "build_workspace"]


if __name__ == "__main__":
    raise SystemExit(main())

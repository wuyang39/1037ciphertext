"""Build the D7 run workspace: identities, plan, exported model and GPT-2 shares.

D7's model is not drawn from a seed, so the dealer cannot regenerate it at the
node. It reads the export the operator produced -- the same bundle whose
tensors the float reference is computed from -- and splits exactly those
tensors, so the arithmetic the enclaves run and the arithmetic the reference
describes are the same tensors by construction rather than by agreement.

The digests the session binds come straight out of that export: the bundle's
own model hash, the frozen tokenizer's hash, the candidate vocabulary's hash
and the calibrated precision plan's hash. A node therefore refuses a session
whose model, tokenizer, candidate table or precision plan is not the one this
workspace described, before any MPC entry point is reached.

Usage::

    python -m infra.d7_workspace --mode provision \
        --root ~/a122-d7/three/workspace --run-id d7-enclave-3host-<stamp> \
        --export-dir ~/a122-d7/export --tokenizer-dir ~/a122-d7/tokenizer \
        --prompt "the cipher key is secret" \
        --cluster-file /tmp/<run-id>-cluster.json \
        --session-root /dev/shm/a122-d7/<run-id>
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from client.gpt2_bpe import load_bpe
from contracts.d7_session import (
    D7_NODE_CONFIG_VERSION,
    D7ModelManifest,
    D7SessionPlan,
)
from crypto.certificates import SM2CertificateAuthority
from crypto.sm2 import SM2KeyPair
from infra.d4_pki import NodeCredentials, provision_cluster
from contracts import canonical_hash
from infra.d7_vectors import (
    D7_CANDIDATE_SIZE,
    D7_LENGTH_BOUND,
    D7_MAX_NEW_TOKENS,
    validate_weight_shapes,
)
from infra.evidence import sha256_file, write_json
from model.export import load_model_bundle, tensor_from_bundle
from model.gpt2 import (
    candidate_token_ids,
    candidate_vocabulary_digest,
    load_config,
    tokenizer_sha256,
)
from mpc.spu_backend.d7_program import D7Config
from mpc.spu_backend.spu_link import CLIENT_VERIFY_DEPTH, SERVER_VERIFY_DEPTH


ROLES: tuple[str, str, str] = ("P0", "P1", "P2")
CLIENT = "C"
CLIENT_TTL_HOURS = 24
NODE_TTL_HOURS = 24
DEFAULT_SESSION_BASE = "/dev/shm/a122-d7"
DEFAULT_RELEASE_ID = "a122-d7"


class D7WorkspaceError(ValueError):
    """The D7 workspace could not be assembled."""


def load_export(export_dir: Path) -> dict[str, Any]:
    """Read one exported GPT-2 run and bind every digest the session carries.

    Nothing here recomputes a hash the export already recorded: the point of
    the export is that its own digests were produced when the frozen source was
    verified, so the workspace copies them and refuses to touch a file whose
    bytes no longer match.
    """
    export_dir = Path(export_dir)
    try:
        run = json.loads((export_dir / "run.json").read_text(encoding="utf-8"))
        freeze = json.loads(
            (export_dir / "source-freeze.json").read_text(encoding="utf-8")
        )
        model_manifest = json.loads(
            (export_dir / "model-manifest.json").read_text(encoding="utf-8")
        )
        precision_plan = json.loads(
            (export_dir / "precision_plan.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise D7WorkspaceError(f"the exported run is unreadable: {exc}") from exc
    bundle = load_model_bundle(export_dir / "model" / "model.json")
    weights = {
        tensor.name: tensor_from_bundle(bundle, tensor.name)
        for tensor in bundle.tensors
    }
    return {
        "directory": str(export_dir),
        "run": run,
        "freeze": freeze,
        "model_manifest": model_manifest,
        "precision_plan": precision_plan,
        "bundle": bundle,
        "weights": weights,
    }


def build_manifest(
    exported: Mapping[str, Any],
    *,
    tokenizer_dir: Path,
    required_tokens: Sequence[int],
) -> tuple[D7ModelManifest, Sequence[int]]:
    """Pin the exported run, and refuse one whose files disagree with it."""
    run = exported["run"]
    freeze = exported["freeze"]
    recorded = exported["model_manifest"]
    bundle = exported["bundle"]
    model_version = str(run["model_version"])
    config = load_config(tokenizer_dir)
    candidates = candidate_token_ids(
        D7_CANDIDATE_SIZE,
        required=[int(value) for value in required_tokens],
        vocab_size=config.vocab_size,
    )
    if list(candidates) != [int(value) for value in run["candidate_tokens"]]:
        raise D7WorkspaceError(
            "the exported candidate vocabulary is not the one the rule selects"
        )
    if int(run["vocab_size"]) != len(candidates):
        raise D7WorkspaceError("the exported vocabulary size does not match")
    if list(run["candidate_tokens"]) != sorted(set(run["candidate_tokens"])):
        raise D7WorkspaceError("the exported candidate vocabulary is not ascending")
    # Every digest is checked against the bytes that are really here, so the
    # session cannot be pinned to an export whose files have since moved.
    tokenizer_digest = tokenizer_sha256(tokenizer_dir)
    if tokenizer_digest != recorded.get("tokenizer_hash"):
        raise D7WorkspaceError("the tokenizer is not the one the export froze")
    if bundle.model_hash != recorded.get("model_hash"):
        raise D7WorkspaceError("the bundle is not the one the export recorded")
    if canonical_hash(exported["precision_plan"]) != recorded.get(
        "precision_plan_hash"
    ):
        raise D7WorkspaceError("the precision plan is not the one the export wrote")
    if not freeze.get("verified"):
        raise D7WorkspaceError(
            "the export was not produced from a verified frozen source"
        )
    unverified = [
        record.get("name")
        for record in freeze.get("files") or []
        if not record.get("verified")
    ]
    if unverified or len(freeze.get("files") or []) != 6:
        raise D7WorkspaceError(
            "the frozen-source record is incomplete: " + ", ".join(map(str, unverified))
        )
    manifest = D7ModelManifest(
        model_version=model_version,
        model_hash=bundle.model_hash,
        tokenizer_hash=tokenizer_digest,
        candidate_vocabulary_hash=candidate_vocabulary_digest(candidates),
        export_precision_plan_hash=canonical_hash(exported["precision_plan"]),
        sequence=int(run["sequence"]),
        layers=int(run["layers"]),
        hidden_size=config.n_embd,
        num_heads=config.n_head,
        intermediate_size=config.intermediate_size,
        vocab_size=len(candidates),
        fractional_bits=int(run["fractional_bits"]),
    )
    return manifest, candidates


def _node_config(
    *,
    run_id: str,
    role: str,
    cluster: Mapping[str, Mapping[str, Any]],
    credentials: Mapping[str, NodeCredentials],
    root: Path,
    session_root: str,
    plan: D7SessionPlan,
    manifest: D7ModelManifest,
    node_key: SM2KeyPair,
    node_certificate: Any,
    kas_public_key: str,
    authority_public_key: str,
    weights_path: Path,
) -> dict[str, Any]:
    identity = credentials[role]
    peers = [other for other in ROLES if other != role]
    return {
        "config_version": D7_NODE_CONFIG_VERSION,
        "run_id": run_id,
        "role": role,
        "partition_id": f"a122-d7-{run_id}",
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
        "seed": 0,
        "present_client_certificate": True,
        "enable_ssl": True,
        "server_verify_depth": SERVER_VERIFY_DEPTH,
        "client_verify_depth": CLIENT_VERIFY_DEPTH,
        "connect_retry_times": 240,
        "connect_retry_interval_ms": 1000,
        "spill_session_state": True,
    }


def _client_config(
    *,
    run_id: str,
    cluster: Mapping[str, Mapping[str, Any]],
    client: NodeCredentials,
    client_dir: Path,
    plan: D7SessionPlan,
    manifest: D7ModelManifest,
    exported: Mapping[str, Any],
    tokenizer_dir: Path,
    node_public_keys: Mapping[str, str],
    kas_public_key: str,
    authority_public_key: str,
    root: Path,
) -> dict[str, Any]:
    return {
        "config_version": "a122-d7-client-v1",
        "run_id": run_id,
        "role": CLIENT,
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "export": {
            "directory": str(exported["directory"]),
            "model_hash": manifest.model_hash,
            "precision_plan_hash": plan.precision_plan_hash,
            "export_precision_plan_hash": manifest.export_precision_plan_hash,
            "candidate_tokens": [
                int(value) for value in exported["run"]["candidate_tokens"]
            ],
            "source_freeze_file": "source-freeze.json",
            "source_freeze_sha256": sha256_file(
                Path(exported["directory"]) / "source-freeze.json"
            ),
        },
        "tokenizer": {
            "directory": str(tokenizer_dir),
            "sha256": manifest.tokenizer_hash,
        },
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
            # The client's own material lives outside the node workspace on
            # purpose: the nodes measure that tree, and the KAS signing key it
            # would otherwise carry could mint the very credentials the nodes
            # are asked to verify.
            "certificate": str(client_dir / "C-cert.pem"),
            "private_key": str(client_dir / "C-key.pem"),
            "ca_bundle": str(client_dir / "C-ca-bundle.pem"),
        },
        "kas_file": str(client_dir / "kas.json"),
        "provisioned_certificate": {
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
    export_dir: Path,
    tokenizer_dir: Path,
    prompt: str,
    max_new_tokens: int = D7_MAX_NEW_TOKENS,
    session_root: str | None = None,
    client_dir: Path | None = None,
    release_id: str = DEFAULT_RELEASE_ID,
    share_epoch: int = 1,
    length_bound: int = D7_LENGTH_BOUND,
    splitter: Callable[[Any], Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Create the whole D7 workspace and return its manifest.

    ``splitter`` is the only part that needs the SPU runtime; a test can pass
    its own and exercise everything else.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    session_root = (session_root or f"{DEFAULT_SESSION_BASE}/{run_id}").rstrip("/")
    client_dir = Path(client_dir) if client_dir is not None else root / "client"
    missing = [role for role in ROLES if role not in cluster]
    if missing:
        raise D7WorkspaceError(
            "the cluster description is missing: " + ", ".join(missing)
        )
    bpe = load_bpe(tokenizer_dir)
    prompt_ids = bpe.encode(prompt)
    exported = load_export(Path(export_dir))
    manifest, candidate_tokens = build_manifest(
        exported,
        tokenizer_dir=Path(tokenizer_dir),
        required_tokens=prompt_ids,
    )
    geometry = D7Config(
        sequence=manifest.sequence,
        layers=manifest.layers,
        hidden_size=manifest.hidden_size,
        num_heads=manifest.num_heads,
        intermediate_size=manifest.intermediate_size,
        vocab_size=manifest.vocab_size,
        fractional_bits=manifest.fractional_bits,
    )
    weights = dict(exported["weights"])
    validate_weight_shapes(weights, geometry)
    plan = D7SessionPlan.for_manifest(
        manifest,
        release_id=release_id,
        share_epoch=share_epoch,
        max_new_tokens=int(max_new_tokens),
        length_bound=int(length_bound),
        prompt_tokens=len(prompt_ids),
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

    if splitter is None:  # pragma: no cover - needs the SPU runtime
        from mpc.spu_backend.sharing import make_splitter
        from mpc.spu_backend.spu_link import load_libspu, make_io, runtime_config

        libspu, _ = load_libspu()
        splitter = make_splitter(
            libspu,
            make_io(
                libspu,
                runtime_config(libspu, fraction_bits=manifest.fractional_bits),
            ),
        )
    shares_root = root / "shares"
    shares_root.mkdir(parents=True, exist_ok=True)
    share_paths = {role: shares_root / f"{role}.json" for role in ROLES}
    bundles: dict[str, dict[str, str]] = {role: {} for role in ROLES}
    for name, values in weights.items():
        parts = list(splitter(values))
        if len(parts) != len(ROLES):
            raise D7WorkspaceError("the splitter did not return three shares")
        for index, role in enumerate(ROLES):
            bundles[role][name] = parts[index]
    for role in ROLES:
        write_json(
            share_paths[role],
            {"run_id": run_id, "role": role, "tensors": bundles[role]},
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
            client_dir=client_dir,
            plan=plan,
            manifest=manifest,
            exported=exported,
            tokenizer_dir=Path(tokenizer_dir),
            node_public_keys={role: node_keys[role].public_key for role in ROLES},
            kas_public_key=kas_key.public_key,
            authority_public_key=authority.public_key,
            root=root,
        ),
    )
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
        "session_dirs": {role: f"{session_root}/{role}" for role in ROLES},
        "plan": plan.to_dict(),
        "model": manifest.to_dict(),
        "prompt_tokens": list(prompt_ids),
        "candidate_tokens": list(candidate_tokens),
        "export": {
            "directory": str(exported["directory"]),
            "model_version": manifest.model_version,
            "model_hash": manifest.model_hash,
            "tokenizer_hash": manifest.tokenizer_hash,
            "candidate_vocabulary_hash": manifest.candidate_vocabulary_hash,
            "precision_plan_hash": plan.precision_plan_hash,
            "export_precision_plan_hash": manifest.export_precision_plan_hash,
            "source_freeze": exported["freeze"],
        },
        "tokenizer_directory": str(tokenizer_dir),
        "client_directory": str(client_dir),
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
        "weights": {name: list(values.shape) for name, values in weights.items()},
    }
    write_json(root / "workspace.json", manifest_document)
    return manifest_document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 workspace builder")
    parser.add_argument("--mode", choices=("provision",), default="provision")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--tokenizer-dir", required=True, type=Path)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--cluster-file", required=True, type=Path)
    parser.add_argument("--max-new-tokens", type=int, default=D7_MAX_NEW_TOKENS)
    parser.add_argument("--session-root", default=None)
    parser.add_argument("--client-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    cluster = json.loads(Path(args.cluster_file).read_text(encoding="utf-8"))
    manifest = build_workspace(
        args.root,
        run_id=args.run_id,
        cluster=cluster,
        export_dir=args.export_dir,
        tokenizer_dir=args.tokenizer_dir,
        prompt=args.prompt,
        max_new_tokens=args.max_new_tokens,
        session_root=args.session_root,
        client_dir=args.client_dir,
    )
    print(
        json.dumps(
            {
                "workspace": manifest["workspace"],
                "run_id": manifest["run_id"],
                "model_manifest_hash": manifest["plan"]["model_manifest_hash"],
                "model_hash": manifest["model"]["model_hash"],
                "candidate_size": len(manifest["candidate_tokens"]),
                "prompt_tokens": manifest["prompt_tokens"],
                "session_root": manifest["session_root"],
            }
        )
    )
    return 0


__all__ = [
    "DEFAULT_RELEASE_ID",
    "D7WorkspaceError",
    "ROLES",
    "build_manifest",
    "build_workspace",
    "load_export",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())

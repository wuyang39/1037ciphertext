"""Build and verify a deterministic local model-share package."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Mapping

from contracts import canonical_hash
from infra.evidence import sha256_file, write_json
from model.export import (
    ModelBundle,
    export_model,
    tensor_from_bundle,
    write_model_bundle,
)
from model.quantization import build_precision_plan, quantize_tensor
from model.share_import import (
    ModelShare,
    reconstruct_model_payload,
    split_model_payload,
)
from model.tiny_decoder import TinyDecoder, TinyDecoderConfig
from tee.storage import MockEncryptedFileSystem, StorageKey


class ModelPackageError(ValueError):
    """A local model package could not be built or verified."""


def _pack_quantized_bundle(
    bundle: ModelBundle,
    *,
    fractional_bits: int,
) -> tuple[bytes, dict[str, Any]]:
    payload = bytearray()
    tensors: list[dict[str, Any]] = []
    dyadic_tensors = {}
    for tensor in bundle.tensors:
        values = tensor_from_bundle(bundle, tensor.name)
        quantized = quantize_tensor(
            tensor.name,
            values,
            fractional_bits=fractional_bits,
        )
        dyadic_tensors[tensor.name] = quantized
        offset = len(payload)
        raw = b"".join(struct.pack("<q", value) for value in quantized.values)
        payload.extend(raw)
        tensors.append(
            {
                "name": tensor.name,
                "shape": list(tensor.shape),
                "offset": offset,
                "length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "fractional_bits": fractional_bits,
            }
        )
    return bytes(payload), {
        "tensors": tensors,
        "precision_plan": build_precision_plan(
            dyadic_tensors,
            plan_id=f"{bundle.model_version}-dyadic-plan",
            error_thresholds={
                "max_abs_error": 2.0 ** -(fractional_bits - 1),
            },
        ),
    }


def _local_key(seed: str, role: str) -> StorageKey:
    key = hashlib.sha256(
        b"A1-22:local-package-key:v1\0"
        + seed.encode("utf-8")
        + b"\0"
        + role.encode("ascii")
    ).digest()
    return StorageKey(key_id=hashlib.sha256(key).hexdigest(), key=key)


def build_local_model_package(
    bundle: ModelBundle,
    *,
    output_dir: Path,
    share_epoch: int,
    fractional_bits: int = 12,
    share_seed: int = 20261011,
    storage_keys: Mapping[str, StorageKey] | None = None,
    encrypt_with_local_seed: str | None = None,
) -> dict[str, Any]:
    """Write model, plan, raw shares, optional encrypted shares, and manifest."""
    if share_epoch < 0:
        raise ModelPackageError("share_epoch must be non-negative")
    if storage_keys is not None and encrypt_with_local_seed is not None:
        raise ModelPackageError("use either storage_keys or a local development seed")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_dir = output_dir / "model"
    shares_dir = output_dir / "shares"
    encrypted_dir = output_dir / "encrypted-shares"
    shares_dir.mkdir(parents=True, exist_ok=True)

    write_model_bundle(bundle, model_dir)
    quantized_payload, quantized = _pack_quantized_bundle(
        bundle,
        fractional_bits=fractional_bits,
    )
    quantized_path = output_dir / "quantized-tensors.bin"
    quantized_path.write_bytes(quantized_payload)
    plan = quantized["precision_plan"]
    plan_path = output_dir / "precision_plan.json"
    write_json(plan_path, plan)

    shares = split_model_payload(
        quantized_payload,
        model_hash=bundle.model_hash,
        share_epoch=share_epoch,
        seed=share_seed,
    )
    share_paths: dict[str, Path] = {}
    for share in shares:
        path = shares_dir / f"{share.role}.bin"
        path.write_bytes(share.payload)
        share_paths[share.role] = path

    encrypted_paths: dict[str, Path] = {}
    keys: Mapping[str, StorageKey] | None = storage_keys
    if encrypt_with_local_seed is not None:
        keys = {
            role: _local_key(encrypt_with_local_seed, role)
            for role in ("P0", "P1", "P2")
        }
    if keys is not None:
        if set(keys) != {"P0", "P1", "P2"}:
            raise ModelPackageError("storage_keys must contain P0, P1, and P2")
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        storage = MockEncryptedFileSystem(
            encrypted_dir,
            master_key=hashlib.sha256(
                b"A1-22:local-package-master:v1\0"
                + bundle.model_hash.encode("ascii")
            ).digest(),
        )
        for share in shares:
            storage.seal_material(
                material_id=share.role,
                model_version=bundle.model_version,
                share_epoch=share_epoch,
                purpose="model-store",
                plaintext=share.payload,
                sealing_key=keys[share.role],
            )
            encrypted_paths[share.role] = encrypted_dir / f"{share.role}.enc"

    manifest = {
        "format": "a122-local-model-package-v1",
        "model_version": bundle.model_version,
        "model_hash": bundle.model_hash,
        "precision_plan_hash": canonical_hash(plan),
        "share_epoch": share_epoch,
        "fractional_bits": fractional_bits,
        "files": {
            "model_manifest": "model/model.json",
            "model_payload": "model/tensors.bin",
            "quantized_payload": quantized_path.name,
            "precision_plan": plan_path.name,
            "shares": {
                role: path.relative_to(output_dir).as_posix()
                for role, path in sorted(share_paths.items())
            },
            "encrypted_shares": {
                role: path.relative_to(output_dir).as_posix()
                for role, path in sorted(encrypted_paths.items())
            },
        },
        "file_hashes": {
            path.relative_to(output_dir).as_posix(): sha256_file(path)
            for path in sorted(output_dir.rglob("*"))
            if path.is_file()
        },
        "claim_boundary": {
            "local_model_package": True,
            "production_model": False,
            "production_keys": False,
            "sgx_acceptance": False,
        },
    }
    manifest_path = output_dir / "package-manifest.json"
    write_json(manifest_path, manifest)
    return {
        "output_dir": str(output_dir.resolve()),
        "manifest": manifest_path.relative_to(output_dir).as_posix(),
        "model_hash": bundle.model_hash,
        "precision_plan_hash": manifest["precision_plan_hash"],
        "share_epoch": share_epoch,
        "share_count": len(shares),
        "encrypted_share_count": len(encrypted_paths),
    }


def build_tiny_model(*, seed: int = 19) -> TinyDecoder:
    return TinyDecoder(
        TinyDecoderConfig(
            vocab_size=32,
            hidden_size=16,
            num_layers=2,
            num_heads=4,
            intermediate_size=32,
            max_seq_len=16,
        ),
        seed=seed,
    )


def verify_local_model_package(output_dir: Path) -> dict[str, Any]:
    """Verify package hashes, precision plan, and three-share reconstruction."""
    output_dir = Path(output_dir)
    manifest_path = output_dir / "package-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelPackageError("package manifest is missing or invalid") from exc
    if manifest.get("format") != "a122-local-model-package-v1":
        raise ModelPackageError("package format is not supported")
    expected_hashes = manifest.get("file_hashes")
    if not isinstance(expected_hashes, dict):
        raise ModelPackageError("package file hashes are invalid")
    actual_paths = {
        path.relative_to(output_dir).as_posix()
        for path in output_dir.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual_paths != set(expected_hashes):
        raise ModelPackageError("package file set does not match its manifest")
    for relative, expected in expected_hashes.items():
        path = output_dir / str(relative)
        if sha256_file(path) != expected:
            raise ModelPackageError(f"package hash mismatch: {relative}")
    try:
        share_paths = manifest["files"]["shares"]
        shares = tuple(
            ModelShare(
                role=role,
                model_hash=str(manifest["model_hash"]),
                share_epoch=int(manifest["share_epoch"]),
                payload=(output_dir / str(share_paths[role])).read_bytes(),
            )
            for role in ("P0", "P1", "P2")
        )
        reconstructed = reconstruct_model_payload(shares)
        quantized = (output_dir / str(manifest["files"]["quantized_payload"])).read_bytes()
        if reconstructed != quantized:
            raise ModelPackageError("model shares do not reconstruct the payload")
        plan = json.loads(
            (output_dir / str(manifest["files"]["precision_plan"])).read_text(
                encoding="utf-8"
            )
        )
        if canonical_hash(plan) != manifest.get("precision_plan_hash"):
            raise ModelPackageError("precision plan hash mismatch")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        if isinstance(exc, ModelPackageError):
            raise
        raise ModelPackageError("package reconstruction failed") from exc
    return {
        "valid": True,
        "file_count": len(expected_hashes),
        "model_hash": manifest["model_hash"],
        "precision_plan_hash": manifest["precision_plan_hash"],
        "share_epoch": manifest["share_epoch"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--model-version", default="tiny-local-v1")
    parser.add_argument("--share-epoch", type=int, default=1)
    parser.add_argument("--fractional-bits", type=int, default=12)
    parser.add_argument("--share-seed", type=int, default=20261011)
    parser.add_argument(
        "--encrypt-local",
        action="store_true",
        help="create throwaway encrypted shares; the key is intentionally discarded",
    )
    parser.add_argument("--local-key-seed", default="local-package-demo")
    args = parser.parse_args()
    if args.verify:
        try:
            result = verify_local_model_package(args.output)
        except (OSError, ValueError) as exc:
            print(f"model package verification failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    bundle = export_model(build_tiny_model(), model_version=args.model_version)
    try:
        result = build_local_model_package(
            bundle,
            output_dir=args.output,
            share_epoch=args.share_epoch,
            fractional_bits=args.fractional_bits,
            share_seed=args.share_seed,
            encrypt_with_local_seed=(
                args.local_key_seed if args.encrypt_local else None
            ),
        )
    except (OSError, ValueError) as exc:
        print(f"model package build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ModelPackageError",
    "build_local_model_package",
    "build_tiny_model",
    "verify_local_model_package",
]

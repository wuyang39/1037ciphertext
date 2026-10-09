"""Deterministic Torch state-dict export for model-manifest tooling."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import torch

from contracts import canonical_hash


class ModelExportError(ValueError):
    """A model bundle is incomplete, malformed, or does not match its digest."""


@dataclass(frozen=True)
class TensorManifest:
    name: str
    shape: tuple[int, ...]
    dtype: str
    offset: int
    length: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "shape": list(self.shape),
            "dtype": self.dtype,
            "offset": self.offset,
            "length": self.length,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ModelBundle:
    model_version: str
    model_hash: str
    tensors: tuple[TensorManifest, ...]
    payload: bytes

    def manifest_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "model_hash": self.model_hash,
            "tensors": [tensor.to_dict() for tensor in self.tensors],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.manifest_dict(),
            "payload_hex": self.payload.hex(),
        }


def _tensor_bytes(parameter: torch.Tensor) -> bytes:
    array = parameter.detach().cpu().contiguous().numpy()
    if array.dtype.byteorder == ">":
        array = array.astype(array.dtype.newbyteorder("<"), copy=False)
    return array.tobytes(order="C")


def export_state_dict(
    state_dict: Mapping[str, torch.Tensor],
    *,
    model_version: str,
) -> ModelBundle:
    """Serialize tensors in stable name order into a deterministic bundle."""
    if not model_version:
        raise ModelExportError("model_version must not be empty")
    payload = bytearray()
    tensors: list[TensorManifest] = []
    for name in sorted(state_dict):
        parameter = state_dict[name]
        if not isinstance(parameter, torch.Tensor):
            raise ModelExportError(f"{name} is not a Torch tensor")
        raw = _tensor_bytes(parameter)
        offset = len(payload)
        payload.extend(raw)
        tensors.append(
            TensorManifest(
                name=name,
                shape=tuple(parameter.shape),
                dtype=str(parameter.dtype).replace("torch.", ""),
                offset=offset,
                length=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    manifest = {
        "model_version": model_version,
        "tensors": [tensor.to_dict() for tensor in tensors],
    }
    model_hash = canonical_hash(manifest)
    return ModelBundle(
        model_version=model_version,
        model_hash=model_hash,
        tensors=tuple(tensors),
        payload=bytes(payload),
    )


def export_model(
    model: torch.nn.Module,
    *,
    model_version: str,
) -> ModelBundle:
    return export_state_dict(model.state_dict(), model_version=model_version)


def write_model_bundle(bundle: ModelBundle, output_dir: Path) -> Path:
    """Write a deterministic model bundle as JSON plus a raw payload."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_path = output_dir / "tensors.bin"
    payload_path.write_bytes(bundle.payload)
    manifest_path = output_dir / "model.json"
    manifest_path.write_text(
        json.dumps(
            bundle.manifest_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return manifest_path


def load_model_bundle(manifest_path: Path) -> ModelBundle:
    """Load and re-verify a bundle before any tensor reaches a Worker."""
    manifest_path = Path(manifest_path)
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelExportError("model manifest is not readable JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "model_version",
        "model_hash",
        "tensors",
    }:
        raise ModelExportError("model manifest has unexpected fields")
    payload_path = manifest_path.parent / "tensors.bin"
    try:
        payload = payload_path.read_bytes()
    except OSError as exc:
        raise ModelExportError("model payload is missing") from exc
    tensors = tuple(
        TensorManifest(
            name=value["name"],
            shape=tuple(value["shape"]),
            dtype=value["dtype"],
            offset=int(value["offset"]),
            length=int(value["length"]),
            sha256=value["sha256"],
        )
        for value in document["tensors"]
    )
    canonical_manifest = {
        "model_version": document["model_version"],
        "tensors": [tensor.to_dict() for tensor in tensors],
    }
    if canonical_hash(canonical_manifest) != document["model_hash"]:
        raise ModelExportError("model manifest hash mismatch")
    for tensor in tensors:
        raw = payload[tensor.offset : tensor.offset + tensor.length]
        if hashlib.sha256(raw).hexdigest() != tensor.sha256:
            raise ModelExportError(f"tensor payload mismatch: {tensor.name}")
    return ModelBundle(
        model_version=document["model_version"],
        model_hash=document["model_hash"],
        tensors=tensors,
        payload=payload,
    )


def tensor_from_bundle(
    bundle: ModelBundle,
    name: str,
) -> np.ndarray:
    """Return one tensor after verifying its slice hash."""
    for tensor in bundle.tensors:
        if tensor.name == name:
            raw = bundle.payload[tensor.offset : tensor.offset + tensor.length]
            if hashlib.sha256(raw).hexdigest() != tensor.sha256:
                raise ModelExportError(f"tensor payload mismatch: {name}")
            dtype = np.dtype(tensor.dtype)
            return np.frombuffer(raw, dtype=dtype).reshape(tensor.shape).copy()
    raise ModelExportError(f"tensor is not present: {name}")


__all__ = [
    "ModelBundle",
    "ModelExportError",
    "TensorManifest",
    "export_model",
    "export_state_dict",
    "load_model_bundle",
    "tensor_from_bundle",
    "write_model_bundle",
]

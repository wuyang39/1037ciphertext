"""Deterministic state-dict export for model-manifest tooling.

The exporter is deliberately framework-agnostic: it accepts anything that
behaves like a Torch tensor and anything that is already an array, and nothing
here imports a framework. The enclave venv that builds a model package carries
numpy and SPU but no torch, and a *dealer* that needed one to serialize a
weight set would be a dealer that cannot run where the model is packaged.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

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


def _tensor_bytes(parameter: Any) -> bytes:
    if hasattr(parameter, "detach"):  # a Torch tensor, without importing torch
        parameter = parameter.detach().cpu().contiguous().numpy()
    array = np.ascontiguousarray(np.asarray(parameter))
    if array.dtype.byteorder == ">":
        array = array.astype(array.dtype.newbyteorder("<"), copy=False)
    return array.tobytes(order="C")


def export_state_dict(
    state_dict: Mapping[str, Any],
    *,
    model_version: str,
) -> ModelBundle:
    """Serialize tensors in stable name order into a deterministic bundle."""
    return export_arrays(state_dict, model_version=model_version)


def export_arrays(
    tensors: Mapping[str, Any],
    *,
    model_version: str,
) -> ModelBundle:
    """Serialize arrays or Torch tensors in stable name order."""
    if not model_version:
        raise ModelExportError("model_version must not be empty")
    payload = bytearray()
    manifest_tensors: list[TensorManifest] = []
    for name in sorted(tensors):
        parameter = tensors[name]
        if not hasattr(parameter, "shape"):
            raise ModelExportError(f"{name} is not a tensor")
        raw = _tensor_bytes(parameter)
        offset = len(payload)
        payload.extend(raw)
        manifest_tensors.append(
            TensorManifest(
                name=name,
                shape=tuple(int(size) for size in parameter.shape),
                dtype=_dtype_name(parameter),
                offset=offset,
                length=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    manifest = {
        "model_version": model_version,
        "tensors": [tensor.to_dict() for tensor in manifest_tensors],
    }
    model_hash = canonical_hash(manifest)
    return ModelBundle(
        model_version=model_version,
        model_hash=model_hash,
        tensors=tuple(manifest_tensors),
        payload=bytes(payload),
    )


def _dtype_name(parameter: Any) -> str:
    """The numpy spelling of a tensor's element type, for either input kind."""
    dtype = getattr(parameter, "dtype", None)
    if isinstance(dtype, np.dtype):
        return dtype.name
    return str(dtype).replace("torch.", "")


def export_model(
    model: Any,
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


def export_gpt2_run(
    *,
    source_directory: Path | str,
    output_directory: Path | str,
    model_version: str,
    layers: int,
    sequence: int,
    candidate_size: int,
    prompt: str | None = None,
    error_bound: float = 2.0 ** -19,
    license_path: Path | str | None = None,
) -> dict[str, Any]:
    """Export one real-GPT-2 run: freeze, bundle, graph, plan and manifest.

    This is the D7 pipeline's front door. It re-verifies the frozen source,
    slices the checkpoint into the tensor set the enclave program consumes,
    serializes that set deterministically, calibrates a dyadic precision plan
    against a requested absolute weight error, and binds the three digests --
    model, tokenizer, precision plan -- into one model manifest. Nothing is
    shared, encrypted or run here; that is the package builder's job.
    """
    from client.gpt2_bpe import load_bpe
    from infra.d7_vectors import build_run, load_run_weights
    from model.calibration import calibrate_tensors
    from model.graph import convert_gpt2_graph
    from model.gpt2 import load_config, require_gpt2_source, tokenizer_sha256

    source = Path(source_directory)
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    freeze = require_gpt2_source(source)
    config = load_config(source)
    required: tuple[int, ...] = ()
    if prompt is not None:
        required = tuple(load_bpe(source).encode(prompt))
    run = build_run(
        config,
        model_version=model_version,
        sequence=sequence,
        layers=layers,
        candidate_size=candidate_size,
        required_tokens=required,
    )
    weights = load_run_weights(source, config, run)
    bundle = export_arrays(weights, model_version=model_version)
    model_dir = output / "model"
    write_model_bundle(bundle, model_dir)
    graph = convert_gpt2_graph(
        num_layers=run.layers,
        hidden_size=config.n_embd,
        num_heads=config.n_head,
        intermediate_size=config.intermediate_size,
        vocab_size=run.vocab_size,
    )
    plan, records = calibrate_tensors(
        weights,
        plan_id=f"{model_version}-dyadic-plan",
        error_bound=float(error_bound),
    )
    from contracts import canonical_hash
    from infra.evidence import sha256_file, write_json

    license_digest = None
    if license_path is not None:
        license_digest = sha256_file(Path(license_path))
    freeze_document = {
        **freeze,
        "tokenizer_file": "tokenizer.json",
        "tokenizer_sha256": tokenizer_sha256(source),
        "license_file": str(license_path) if license_path else None,
        "license_sha256": license_digest,
        "run": run.to_dict(),
    }
    write_json(output / "source-freeze.json", freeze_document)
    write_json(output / "run.json", run.to_dict())
    write_json(output / "graph.json", graph.to_dict())
    write_json(output / "precision_plan.json", plan)
    write_json(
        output / "calibration.json",
        {
            "plan_id": plan["plan_id"],
            "error_bound": float(error_bound),
            "tensors": [record.to_dict() for record in records],
            "tensor_count": len(records),
            "elements": sum(record.elements for record in records),
            "worst_max_abs_error": max(record.max_abs_error for record in records),
            "narrowest_fractional_bits": min(
                record.fractional_bits for record in records
            ),
        },
    )
    manifest = {
        "model_hash": bundle.model_hash,
        "tokenizer_hash": freeze_document["tokenizer_sha256"],
        "precision_plan_hash": canonical_hash(plan),
        "model_version": model_version,
        "operator_version": "a122-gpt2-mhlo-v1",
    }
    from model.manifests import ModelManifest

    validated = ModelManifest.from_dict(manifest)
    write_json(output / "model-manifest.json", validated.to_dict())
    write_json(
        output / "graph-digest.json",
        {"graph_version": graph.graph_version, "graph_digest": graph.digest()},
    )
    return {
        "output_dir": str(output.resolve()),
        "model_version": model_version,
        "model_hash": bundle.model_hash,
        "manifest_hash": validated.digest(),
        "tokenizer_hash": freeze_document["tokenizer_sha256"],
        "precision_plan_hash": manifest["precision_plan_hash"],
        "graph_digest": graph.digest(),
        "layers": run.layers,
        "sequence": run.sequence,
        "vocab_size": run.vocab_size,
        "tensor_count": len(bundle.tensors),
        "elements": sum(int(np.prod(tensor.shape)) for tensor in bundle.tensors),
    }


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="A1-22 model export")
    parser.add_argument("--source", type=Path, help="frozen GPT-2 directory")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--model-version", default="gpt2-small-d7-v1")
    parser.add_argument("--layers", type=int, default=12)
    parser.add_argument("--sequence", type=int, default=8)
    parser.add_argument("--candidates", type=int, default=1024)
    parser.add_argument("--prompt", default=None)
    parser.add_argument("--error-bound", type=float, default=2.0 ** -19)
    parser.add_argument("--license", type=Path, default=None)
    parser.add_argument(
        "--tiny",
        action="store_true",
        help="export the synthetic Tiny decoder instead of the frozen GPT-2",
    )
    args = parser.parse_args(argv)
    if args.tiny:
        from infra.build_model_package import build_tiny_model

        bundle = export_model(build_tiny_model(), model_version=args.model_version)
        write_model_bundle(bundle, Path(args.out) / "model")
        print(
            json.dumps(
                {"model_hash": bundle.model_hash, "tensors": len(bundle.tensors)},
                sort_keys=True,
            )
        )
        return 0
    if args.source is None:
        print("either --source or --tiny is required", file=sys.stderr)
        return 2
    try:
        result = export_gpt2_run(
            source_directory=args.source,
            output_directory=args.out,
            model_version=args.model_version,
            layers=args.layers,
            sequence=args.sequence,
            candidate_size=args.candidates,
            prompt=args.prompt,
            error_bound=args.error_bound,
            license_path=args.license,
        )
    except (OSError, ValueError) as exc:
        print(f"model export failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


__all__ = [
    "ModelBundle",
    "ModelExportError",
    "TensorManifest",
    "export_arrays",
    "export_model",
    "export_gpt2_run",
    "export_state_dict",
    "load_model_bundle",
    "main",
    "tensor_from_bundle",
    "write_model_bundle",
]


if __name__ == "__main__":
    raise SystemExit(main())

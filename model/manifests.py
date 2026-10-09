"""Validated model and precision manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from contracts import canonical_hash, validate_contract
from crypto import SM2KeyPair, verify_sm2


@dataclass(frozen=True)
class ModelManifest:
    model_hash: str
    tokenizer_hash: str
    precision_plan_hash: str
    model_version: str
    operator_version: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelManifest":
        validate_contract("model_manifest", value)
        return cls(**value)

    def to_dict(self) -> dict[str, str]:
        return {
            "model_hash": self.model_hash,
            "tokenizer_hash": self.tokenizer_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "model_version": self.model_version,
            "operator_version": self.operator_version,
        }

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


@dataclass(frozen=True)
class PrecisionPlan:
    plan_id: str
    ring: str
    tensor_layout: str
    scales: dict[str, int]
    approximations: dict[str, str]
    error_thresholds: dict[str, float]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PrecisionPlan":
        validate_contract("precision_plan", value)
        return cls(
            plan_id=value["plan_id"],
            ring=value["ring"],
            tensor_layout=value["tensor_layout"],
            scales=dict(value["scales"]),
            approximations=dict(value["approximations"]),
            error_thresholds=dict(value["error_thresholds"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "ring": self.ring,
            "tensor_layout": self.tensor_layout,
            "scales": self.scales,
            "approximations": self.approximations,
            "error_thresholds": self.error_thresholds,
        }

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


def verify_manifest_signature(
    manifest: Mapping[str, Any],
    signature: bytes,
    public_key: str,
) -> bool:
    """Verify an SM2 signature over a manifest's canonical bytes."""
    from contracts import canonical_bytes

    return verify_sm2(signature, canonical_bytes(manifest), public_key)


def sign_manifest(
    key_pair: SM2KeyPair,
    manifest: Mapping[str, Any],
    *,
    random_hex: str | None = None,
) -> bytes:
    """Sign canonical manifest bytes for tests and release tooling."""
    from contracts import canonical_bytes

    return key_pair.sign(canonical_bytes(manifest), random_hex=random_hex)

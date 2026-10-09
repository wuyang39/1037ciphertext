"""Deterministic dyadic quantization and precision-plan helpers."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np

from contracts import canonical_hash, validate_contract


class QuantizationError(ValueError):
    """A tensor cannot be represented by the requested dyadic format."""


@dataclass(frozen=True)
class DyadicTensor:
    name: str
    fractional_bits: int
    values: tuple[int, ...]
    shape: tuple[int, ...]

    @property
    def scale(self) -> int:
        return 1 << self.fractional_bits

    def dequantize(self) -> np.ndarray:
        return np.asarray(self.values, dtype=np.float64).reshape(self.shape) / self.scale


def _round_half_away(value: np.ndarray) -> np.ndarray:
    return np.where(value >= 0, np.floor(value + 0.5), np.ceil(value - 0.5))


def quantize_tensor(
    name: str,
    value: Sequence[float] | np.ndarray,
    *,
    fractional_bits: int,
    clip_min: float | None = None,
    clip_max: float | None = None,
) -> DyadicTensor:
    """Quantize with an explicit dyadic scale and deterministic rounding."""
    if fractional_bits < 0 or fractional_bits > 30:
        raise QuantizationError("fractional_bits must be in [0, 30]")
    array = np.asarray(value, dtype=np.float64)
    if not np.all(np.isfinite(array)):
        raise QuantizationError("tensor contains a non-finite value")
    if clip_min is not None:
        array = np.maximum(array, clip_min)
    if clip_max is not None:
        array = np.minimum(array, clip_max)
    scale = 1 << fractional_bits
    quantized = _round_half_away(array * scale).astype(np.int64)
    if np.any(quantized > 2**63 - 1) or np.any(quantized < -(2**63)):
        raise QuantizationError("quantized tensor exceeds int64")
    return DyadicTensor(
        name=name,
        fractional_bits=fractional_bits,
        values=tuple(int(item) for item in quantized.reshape(-1)),
        shape=tuple(array.shape),
    )


def build_precision_plan(
    tensors: Mapping[str, DyadicTensor],
    *,
    plan_id: str,
    ring: str = "Z_2_64",
    tensor_layout: str = "row-major",
    approximations: Mapping[str, str] | None = None,
    error_thresholds: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Build a manifest-schema-compatible precision plan."""
    plan = {
        "plan_id": plan_id,
        "ring": ring,
        "tensor_layout": tensor_layout,
        "scales": {
            name: tensor.fractional_bits for name, tensor in sorted(tensors.items())
        },
        "approximations": dict(approximations or {}),
        "error_thresholds": dict(error_thresholds or {"max_abs_error": 0.0}),
    }
    validate_contract("precision_plan", plan)
    return plan


def precision_plan_hash(plan: Mapping[str, Any]) -> str:
    return canonical_hash(plan)


__all__ = [
    "DyadicTensor",
    "QuantizationError",
    "build_precision_plan",
    "precision_plan_hash",
    "quantize_tensor",
]

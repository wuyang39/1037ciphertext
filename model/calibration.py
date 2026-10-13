"""Dyadic quantization calibration for the real GPT-2 weight set.

Two things are measured here and both end up in the precision plan's evidence.
Per tensor, the smallest fractional width that holds the tensor inside a
requested absolute error, plus the error that width actually produces. Per
layer, the error the quantized weights put into that layer's *output*, which is
the number that matters: a weight matrix can be quantized coarsely and still
land inside the range the next operator was measured for, or be quantized
finely and still move the hidden state because the layer amplifies it.

The plan keeps one scale per tensor, which is what ``precision_plan`` in the
contracts already describes, so a calibrated plan is the same shape of document
as the fixed one D5 and D6 ran and needs no new contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np

from model.quantization import DyadicTensor, build_precision_plan, quantize_tensor


MIN_FRACTIONAL_BITS = 8
MAX_FRACTIONAL_BITS = 30
INT64_HEADROOM_BITS = 2
"""Quantized values must stay this far below 2**63 so sums cannot wrap."""


class CalibrationError(ValueError):
    """A tensor cannot be calibrated into the requested precision."""


@dataclass(frozen=True)
class TensorCalibration:
    """What one tensor cost at the width the plan chose for it."""

    name: str
    shape: tuple[int, ...]
    fractional_bits: int
    max_abs_value: float
    max_abs_error: float
    mean_abs_error: float
    error_bound: float
    elements: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "shape": list(self.shape),
            "fractional_bits": self.fractional_bits,
            "max_abs_value": self.max_abs_value,
            "max_abs_error": self.max_abs_error,
            "mean_abs_error": self.mean_abs_error,
            "error_bound": self.error_bound,
            "elements": self.elements,
        }


def widest_safe_bits(peak: float) -> int:
    """The largest dyadic width that keeps ``peak`` clear of the int64 edge."""
    if peak <= 0.0:
        return MAX_FRACTIONAL_BITS
    headroom = np.log2(float(2 ** (63 - INT64_HEADROOM_BITS)) / float(peak))
    return int(max(MIN_FRACTIONAL_BITS, min(MAX_FRACTIONAL_BITS, np.floor(headroom))))


def calibrate_tensor(
    name: str,
    values: np.ndarray,
    *,
    error_bound: float,
    minimum_bits: int = MIN_FRACTIONAL_BITS,
    maximum_bits: int = MAX_FRACTIONAL_BITS,
) -> TensorCalibration:
    """Pick the narrowest width whose own rounding error stays inside ``bound``."""
    array = np.asarray(values, dtype=np.float64)
    if not np.all(np.isfinite(array)):
        raise CalibrationError(f"{name} contains a non-finite value")
    peak = float(np.abs(array).max()) if array.size else 0.0
    ceiling = min(maximum_bits, widest_safe_bits(peak))
    if ceiling < max(minimum_bits, 0):
        raise CalibrationError(f"{name} cannot be represented in the fixed-point ring")
    for bits in range(max(minimum_bits, 0), ceiling + 1):
        quantized = quantize_tensor(name, array, fractional_bits=bits)
        delta = np.abs(quantized.dequantize() - array)
        observed = float(delta.max()) if delta.size else 0.0
        if observed <= error_bound:
            return TensorCalibration(
                name=name,
                shape=tuple(array.shape),
                fractional_bits=bits,
                max_abs_value=peak,
                max_abs_error=observed,
                mean_abs_error=float(delta.mean()) if delta.size else 0.0,
                error_bound=float(error_bound),
                elements=int(array.size),
            )
    raise CalibrationError(
        f"{name} cannot meet {error_bound} within {ceiling} fractional bits"
    )


def calibrate_tensors(
    tensors: Mapping[str, np.ndarray],
    *,
    plan_id: str,
    error_bound: float,
    minimum_bits: int = MIN_FRACTIONAL_BITS,
    maximum_bits: int = MAX_FRACTIONAL_BITS,
) -> tuple[dict[str, Any], tuple[TensorCalibration, ...]]:
    """Calibrate every tensor and return the plan plus its per-tensor record."""
    records: list[TensorCalibration] = []
    quantized: dict[str, DyadicTensor] = {}
    for name in sorted(tensors):
        record = calibrate_tensor(
            name,
            tensors[name],
            error_bound=error_bound,
            minimum_bits=minimum_bits,
            maximum_bits=maximum_bits,
        )
        records.append(record)
        quantized[name] = quantize_tensor(
            name, tensors[name], fractional_bits=record.fractional_bits
        )
    plan = build_precision_plan(
        quantized,
        plan_id=plan_id,
        approximations={"gelu": "tanh", "attention": "softmax-max-shift"},
        error_thresholds={
            "max_abs_error": float(error_bound),
            "weight_max_abs_error": max(record.max_abs_error for record in records),
        },
    )
    return plan, tuple(records)


def dequantize(tensor: DyadicTensor) -> np.ndarray:
    return tensor.dequantize()


def quantize_all(
    tensors: Mapping[str, np.ndarray],
    scales: Mapping[str, int],
) -> dict[str, DyadicTensor]:
    """Quantize every tensor at the width its plan entry names."""
    missing = sorted(set(tensors) - set(scales))
    if missing:
        raise CalibrationError("the plan is missing: " + ", ".join(missing))
    return {
        name: quantize_tensor(name, value, fractional_bits=int(scales[name]))
        for name, value in tensors.items()
    }


@dataclass(frozen=True)
class LayerCalibration:
    """The error the quantized weights put into one layer's output."""

    stage: str
    max_abs_error: float
    mean_abs_error: float
    reference_max_abs: float
    relative_error: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "max_abs_error": self.max_abs_error,
            "mean_abs_error": self.mean_abs_error,
            "reference_max_abs": self.reference_max_abs,
            "relative_error": self.relative_error,
        }


def _stats(stage: str, actual: np.ndarray, expected: np.ndarray) -> LayerCalibration:
    delta = np.abs(np.asarray(actual, dtype=np.float64) - np.asarray(expected, dtype=np.float64))
    peak = float(np.abs(np.asarray(expected, dtype=np.float64)).max())
    return LayerCalibration(
        stage=stage,
        max_abs_error=float(delta.max()) if delta.size else 0.0,
        mean_abs_error=float(delta.mean()) if delta.size else 0.0,
        reference_max_abs=peak,
        relative_error=float(delta.max() / peak) if peak > 0.0 else 0.0,
    )


def layer_error_report(
    *,
    exact: Mapping[str, np.ndarray],
    quantized: Mapping[str, np.ndarray],
) -> tuple[LayerCalibration, ...]:
    """Compare the stage activations of an exact and a quantized weight set.

    Both mappings come from the same instrumented forward pass under the same
    stage names, so the report is a plain comparison rather than a second
    implementation of the model.
    """
    missing = sorted(set(exact) - set(quantized))
    if missing:
        raise CalibrationError("the quantized run is missing: " + ", ".join(missing))
    records: list[LayerCalibration] = []
    for stage in sorted(exact):
        records.append(_stats(stage, quantized[stage], exact[stage]))
    return tuple(records)


__all__ = [
    "INT64_HEADROOM_BITS",
    "MAX_FRACTIONAL_BITS",
    "MIN_FRACTIONAL_BITS",
    "CalibrationError",
    "LayerCalibration",
    "TensorCalibration",
    "calibrate_tensor",
    "calibrate_tensors",
    "dequantize",
    "layer_error_report",
    "quantize_all",
    "widest_safe_bits",
]

"""Versioned polynomial and iterative approximations for D8 profiles."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Sequence


class ApproximationError(ValueError):
    """An approximation input is outside its registered range."""


@dataclass(frozen=True)
class ApproximationSpec:
    name: str
    minimum: float
    maximum: float
    coefficients: tuple[float, ...] = ()
    iterations: int = 0
    max_abs_error: float = 0.0

    def __post_init__(self) -> None:
        if self.minimum > self.maximum:
            raise ValueError("approximation range is inverted")
        if self.iterations < 0:
            raise ValueError("iterations must be non-negative")

    def check(self, value: float) -> None:
        if not self.minimum <= value <= self.maximum:
            raise ApproximationError(
                f"{self.name} input {value} is outside "
                f"[{self.minimum}, {self.maximum}]"
            )


SOFTMAX_PIECEWISE = ApproximationSpec(
    name="softmax_piecewise_v1",
    minimum=-32.0,
    maximum=32.0,
    coefficients=(1.0,),
    iterations=0,
    max_abs_error=1e-4,
)
GELU_PIECEWISE = ApproximationSpec(
    name="gelu_piecewise_v1",
    minimum=-8.0,
    maximum=8.0,
    coefficients=(0.5, 0.7978845608028654, 0.044715),
    iterations=0,
    max_abs_error=2e-3,
)
RSQRT_GOLDSCHMIDT = ApproximationSpec(
    name="rsqrt_goldschmidt_v1",
    minimum=1e-6,
    maximum=1e6,
    iterations=3,
    max_abs_error=1e-5,
)


def softmax_piecewise(
    values: Sequence[float],
    *,
    spec: ApproximationSpec = SOFTMAX_PIECEWISE,
) -> list[float]:
    if not values:
        raise ApproximationError("softmax input must not be empty")
    checked = [float(value) for value in values]
    for value in checked:
        if value < spec.minimum or value > spec.maximum:
            raise ApproximationError("softmax input is outside its range")
    maximum = max(checked)
    exponentials = [math.exp(value - maximum) for value in checked]
    denominator = sum(exponentials)
    return [value / denominator for value in exponentials]


def gelu_piecewise(
    value: float,
    *,
    spec: ApproximationSpec = GELU_PIECEWISE,
) -> float:
    spec.check(float(value))
    x = float(value)
    c0, c1, c2 = spec.coefficients
    return c0 * x * (1.0 + math.tanh(c1 * (x + c2 * x**3)))


def rsqrt_goldschmidt(
    value: float,
    *,
    spec: ApproximationSpec = RSQRT_GOLDSCHMIDT,
    initial: float | None = None,
) -> float:
    spec.check(float(value))
    if value <= 0:
        raise ApproximationError("rsqrt input must be positive")
    estimate = initial if initial is not None else 1.0 / math.sqrt(value)
    for _ in range(spec.iterations):
        estimate = estimate * (1.5 - 0.5 * value * estimate * estimate)
    return estimate


APPROXIMATION_REGISTRY: dict[str, Callable[..., float | list[float]]] = {
    "softmax_piecewise": softmax_piecewise,
    "gelu_piecewise": gelu_piecewise,
    "rsqrt_goldschmidt": rsqrt_goldschmidt,
}


__all__ = [
    "APPROXIMATION_REGISTRY",
    "ApproximationError",
    "ApproximationSpec",
    "GELU_PIECEWISE",
    "RSQRT_GOLDSCHMIDT",
    "SOFTMAX_PIECEWISE",
    "gelu_piecewise",
    "rsqrt_goldschmidt",
    "softmax_piecewise",
]

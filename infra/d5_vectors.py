"""Deterministic D5 inputs and their plaintext references.

The D5 acceptance runs four non-linear operators and one whole decoder block
on synthetic cases. Each case is generated from a fixed seed so the node, the
driver and a reader with numpy can rebuild the same tensors, and every
reference is the exact function the MHLO program asks SPU to evaluate: the
shifted Softmax, the masked causal attention, the tanh GELU and the first-index
Argmax. The only mismatch left is the fixed-point protocol error, which is what
the per-operator table records.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Callable, Iterable, Mapping, Sequence

from mpc.spu_backend.d5_program import (
    GELU_TANH_C1,
    GELU_TANH_C2,
    LAYERNORM_EPSILON,
    D5Config,
)


D5_SEED = 20261013

# Registered per-operator ceilings. A case that exceeds its ceiling fails the
# run; the numbers are the ones the local reference and the first enclave run
# both cleared, with room for the fixed-point rounding the protocol adds.
SOFTMAX_TOLERANCE = 5e-3
LAYERNORM_TOLERANCE = 5e-3
GELU_TOLERANCE = 1e-2
BLOCK_HIDDEN_TOLERANCE = 2e-2
BLOCK_LOGITS_TOLERANCE = 2e-2
BLOCK_APPROX_TOLERANCE = 2e-2
"""GELU tanh form against the exact erf form, recorded but not a failure."""

ARGMAX_TOLERANCE = 0.0


def _numpy() -> Any:
    import numpy

    return numpy


def _generator(seed: int) -> Any:
    return _numpy().random.default_rng(seed)


def reference_softmax(scores: Any) -> Any:
    numpy = _numpy()
    values = numpy.asarray(scores, dtype=numpy.float64)
    shifted = values - values.max(axis=-1, keepdims=True)
    exponentials = numpy.exp(shifted)
    return exponentials / exponentials.sum(axis=-1, keepdims=True)


def reference_layernorm(h: Any, gamma: Any, beta: Any) -> Any:
    numpy = _numpy()
    values = numpy.asarray(h, dtype=numpy.float64)
    mean = values.mean(axis=-1, keepdims=True)
    variance = values.var(axis=-1, keepdims=True)
    normalized = (values - mean) / numpy.sqrt(variance + LAYERNORM_EPSILON)
    return normalized * numpy.asarray(gamma, dtype=numpy.float64) + numpy.asarray(
        beta, dtype=numpy.float64
    )


def reference_gelu(x: Any) -> Any:
    numpy = _numpy()
    values = numpy.asarray(x, dtype=numpy.float64)
    return 0.5 * values * (
        1.0 + numpy.tanh(GELU_TANH_C1 * (values + GELU_TANH_C2 * values**3))
    )


def reference_gelu_erf(x: Any) -> Any:
    """The exact GELU, used to report the tanh approximation's own error."""
    import math as _math

    numpy = _numpy()
    values = numpy.asarray(x, dtype=numpy.float64)
    erf = numpy.vectorize(_math.erf)
    return 0.5 * values * (1.0 + erf(values / _math.sqrt(2.0)))


def reference_argmax(logits: Any) -> float:
    numpy = _numpy()
    return float(int(numpy.argmax(numpy.asarray(logits, dtype=numpy.float64))))


def reference_block(inputs: dict[str, Any], config: D5Config) -> dict[str, Any]:
    """The float reference for the MHLO block, head and Argmax."""
    numpy = _numpy()
    seq = config.sequence
    d = config.hidden_size
    heads = config.num_heads
    head = config.head_size

    def linear(x: Any, weight: str, bias: str) -> Any:
        return x @ inputs[weight] + inputs[bias]

    h = numpy.asarray(inputs["h"], dtype=numpy.float64)
    normalized = reference_layernorm(h, inputs["ln1_weight"], inputs["ln1_bias"])
    query = linear(normalized, "wq", "bq")
    key = linear(normalized, "wk", "bk")
    value = linear(normalized, "wv", "bv")

    def split(matrix: Any, permutation: Sequence[int]) -> Any:
        return matrix.reshape(seq, heads, head).transpose(*permutation)

    query_heads = split(query, (1, 0, 2))
    key_heads = split(key, (1, 2, 0))
    value_heads = split(value, (1, 0, 2))
    # ``key_heads`` is already (heads, head, sequence), so the contraction is a
    # plain batched matmul against (heads, sequence, head).
    scores = query_heads @ key_heads / math.sqrt(head)
    mask = numpy.tril(numpy.ones((seq, seq)))
    exponentials = numpy.exp(scores - scores.max(axis=-1, keepdims=True)) * mask
    probabilities = exponentials / exponentials.sum(axis=-1, keepdims=True)
    attended = probabilities @ value_heads
    merged = attended.transpose(1, 0, 2).reshape(seq, d)
    projected = linear(merged, "attention_out_weight", "attention_out_bias")
    residual = h + projected
    normalized_2 = reference_layernorm(
        residual, inputs["ln2_weight"], inputs["ln2_bias"]
    )
    expanded = linear(normalized_2, "ffn_in_weight", "ffn_in_bias")
    activated = reference_gelu(expanded)
    ffn = activated @ inputs["ffn_out_weight"] + inputs["ffn_out_bias"]
    hidden = residual + ffn
    normalized_final = reference_layernorm(
        hidden, inputs["ln_f_weight"], inputs["ln_f_bias"]
    )
    logits = normalized_final @ inputs["lm_weight"] + inputs["lm_bias"]
    return {
        "hidden": hidden,
        "logits": logits,
        "token": numpy.array([reference_argmax(logits[-1])]),
    }


def softmax_cases(config: D5Config) -> list[dict[str, Any]]:
    numpy = _numpy()
    generator = _generator(D5_SEED + 1)
    rows, cols = config.sequence, config.sequence
    cases: list[dict[str, Any]] = [
        {"case": "small", "scores": generator.standard_normal((rows, cols)) * 0.5},
        {"case": "wide_range", "scores": generator.standard_normal((rows, cols)) * 12.0},
        {
            "case": "ramp",
            "scores": numpy.tile(numpy.linspace(-6.0, 6.0, cols), (rows, 1)),
        },
        {
            "case": "near_ties",
            "scores": numpy.tile(
                numpy.linspace(-1.0, 1.0, cols) * 1e-3, (rows, 1)
            ),
        },
    ]
    for index in range(4):
        cases.append(
            {
                "case": f"random-{index:02d}",
                "scores": generator.standard_normal((rows, cols)) * 3.0,
            }
        )
    return cases


def layernorm_cases(config: D5Config) -> list[dict[str, Any]]:
    generator = _generator(D5_SEED + 2)
    rows, cols = config.sequence, config.hidden_size
    cases: list[dict[str, Any]] = []
    for index in range(6):
        scale = 0.2 + 2.0 * index
        cases.append(
            {
                "case": f"scale-{index:02d}",
                "h": generator.standard_normal((rows, cols)) * scale,
                "gamma": 0.5 + generator.random(cols),
                "beta": generator.standard_normal(cols) * 0.2,
            }
        )
    cases.append(
        {
            # A variance below roughly 1e-4 is outside the FM64 fxp18 working
            # range: the 2^-18 resolution is 3.8e-6, so a variance that small
            # is measured in the protocol's own rounding noise. This case stays
            # one order of magnitude above that floor.
            "case": "small_variance",
            "h": generator.standard_normal((rows, cols)) * 1e-1,
            "gamma": generator.random(cols) + 0.5,
            "beta": generator.standard_normal(cols) * 0.1,
        }
    )
    return cases


def gelu_cases(config: D5Config) -> list[dict[str, Any]]:
    numpy = _numpy()
    generator = _generator(D5_SEED + 3)
    rows, cols = config.sequence, config.hidden_size
    cases: list[dict[str, Any]] = [
        {
            "case": "unit_range",
            "x": numpy.linspace(-6.0, 6.0, rows * cols).reshape(rows, cols),
        },
        {
            "case": "tail",
            "x": numpy.linspace(-40.0, 40.0, rows * cols).reshape(rows, cols),
        },
    ]
    for index in range(4):
        cases.append(
            {
                "case": f"random-{index:02d}",
                "x": generator.standard_normal((rows, cols)) * (1.0 + index),
            }
        )
    return cases


def argmax_cases(config: D5Config) -> list[dict[str, Any]]:
    numpy = _numpy()
    generator = _generator(D5_SEED + 4)
    vocab = config.vocab_size
    cases: list[dict[str, Any]] = [
        {
            "case": "unique",
            "logits": numpy.zeros(vocab) + numpy.arange(vocab) * 0.5,
        },
        {
            "case": "first_of_ties",
            "logits": numpy.zeros(vocab),
        },
        {
            "case": "last_position",
            "logits": numpy.concatenate([numpy.zeros(vocab - 1), [50.0]]),
        },
        {
            "case": "all_negative",
            "logits": -numpy.abs(generator.standard_normal(vocab)),
        },
    ]
    for index in range(4):
        cases.append(
            {
                "case": f"random-{index:02d}",
                "logits": generator.standard_normal(vocab) * (1.0 + index),
            }
        )
    return cases


_BLOCK_SHAPES: dict[str, tuple[int, ...]] | None = None


def _block_case_shapes(config: D5Config) -> dict[str, tuple[int, ...]]:
    global _BLOCK_SHAPES
    if _BLOCK_SHAPES is None:
        from mpc.spu_backend.d5_program import build_block_program

        program = build_block_program(config)
        _BLOCK_SHAPES = {spec.name: spec.shape for spec in program.inputs}
    return _BLOCK_SHAPES


def block_cases(config: D5Config) -> list[dict[str, Any]]:
    """Block cases drawn in the Tiny Decoder's own operating range.

    The weights use the Kaiming-uniform bound PyTorch's ``Linear`` uses
    (``1/sqrt(fan_in)``). Scaling every weight up instead would drive the
    attention scores into saturation, where the float reference itself is ill
    conditioned and a softmax that agrees to 1e-3 still moves the residual, so
    it would measure the test vector rather than the protocol.
    """
    generator = _generator(D5_SEED + 5)
    shapes = _block_case_shapes(config)

    def bound(name: str) -> float:
        shape = shapes[name]
        fan_in = shape[0] if len(shape) == 2 else shapes["h"][1]
        return 1.0 / math.sqrt(float(fan_in))

    def weights(scale: float) -> dict[str, Any]:
        inputs: dict[str, Any] = {}
        for name, shape in shapes.items():
            limit = bound(name) * scale
            inputs[name] = generator.uniform(-limit, limit, shape)
        return inputs

    cases: list[dict[str, Any]] = []
    for index in range(8):
        # Vary how far the hidden state starts from the origin; the weights
        # stay in the model's range.
        hidden_scale = 0.25 + 0.25 * index
        inputs = weights(1.0)
        inputs["h"] = generator.standard_normal(shapes["h"]) * hidden_scale
        cases.append({"case": f"random-{index:02d}", **inputs})
    wide = weights(1.5)
    wide["h"] = generator.standard_normal(shapes["h"]) * 3.0
    cases.append({"case": "wide_range", **wide})
    return cases


def case_inputs(case: Mapping[str, Any]) -> dict[str, Any]:
    """The tensor inputs of one generated case, without its label."""
    return {name: value for name, value in case.items() if name != "case"}


def digest_grid(grid: dict[str, Any]) -> str:
    """A stable digest of every generated input, for the evidence bundle."""
    numpy = _numpy()

    def encode(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: encode(child) for key, child in sorted(value.items())}
        if isinstance(value, list):
            return [encode(child) for child in value]
        if hasattr(value, "tolist"):
            array = numpy.asarray(value, dtype=numpy.float64)
            return {
                "shape": list(array.shape),
                "sha256": hashlib.sha256(
                    numpy.ascontiguousarray(array).tobytes()
                ).hexdigest(),
            }
        return value

    payload = json.dumps(encode(grid), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


CASE_BUILDERS: dict[str, Callable[[D5Config], list[dict[str, Any]]]] = {
    "softmax": softmax_cases,
    "layernorm": layernorm_cases,
    "gelu": gelu_cases,
    "argmax": argmax_cases,
    "block": block_cases,
}


def build_grid(config: D5Config) -> dict[str, list[dict[str, Any]]]:
    return {name: builder(config) for name, builder in CASE_BUILDERS.items()}


__all__ = [
    "ARGMAX_TOLERANCE",
    "BLOCK_APPROX_TOLERANCE",
    "BLOCK_HIDDEN_TOLERANCE",
    "BLOCK_LOGITS_TOLERANCE",
    "CASE_BUILDERS",
    "D5_SEED",
    "GELU_TOLERANCE",
    "LAYERNORM_TOLERANCE",
    "SOFTMAX_TOLERANCE",
    "argmax_cases",
    "block_cases",
    "build_grid",
    "case_inputs",
    "digest_grid",
    "gelu_cases",
    "layernorm_cases",
    "reference_argmax",
    "reference_block",
    "reference_gelu",
    "reference_gelu_erf",
    "reference_layernorm",
    "reference_softmax",
    "softmax_cases",
]

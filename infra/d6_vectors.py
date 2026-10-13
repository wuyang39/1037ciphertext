"""Deterministic inputs and float references for the D6 decoding loop.

The tiny decoder D6 runs is not a downloaded model; it is drawn from a pinned
seed so the dealer that shares it out, the node that holds one share and the
operator's reference implementation all describe the very same tensors. The
relation to D5 is deliberate: the block, the LayerNorm epsilon, the GELU tanh
form and the fixed-point precision are the ones D5 measured, so D6 only adds
the embedding table the autoregressive loop needs and the one-hot history the
client owns.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

from mpc.spu_backend.d5_program import D5Config


D6_SEED = 20261013
# Geometry of the toy decoder the D6 acceptance runs. The vocabulary matches
# the pinned tokenizer in :mod:`client.tokenizer`.
D6_GEOMETRY: dict[str, int] = {
    "sequence": 8,
    "hidden_size": 16,
    "num_heads": 2,
    "intermediate_size": 32,
    "vocab_size": 152,
    "fractional_bits": 18,
}
D6_MAX_NEW_TOKENS = 3
D6_LENGTH_BOUND = 1 << 20

# The order tensors are drawn in. It is part of the manifest: drawing the same
# seed in another order would silently describe another model.
WEIGHT_TENSORS: tuple[tuple[str, str], ...] = (
    ("embedding", "vocab_hidden"),
    ("ln1_weight", "hidden"),
    ("ln1_bias", "hidden"),
    ("wq", "square"),
    ("wk", "square"),
    ("wv", "square"),
    ("bq", "hidden"),
    ("bk", "hidden"),
    ("bv", "hidden"),
    ("attention_out_weight", "square"),
    ("attention_out_bias", "hidden"),
    ("ln2_weight", "hidden"),
    ("ln2_bias", "hidden"),
    ("ffn_in_weight", "expand"),
    ("ffn_in_bias", "intermediate"),
    ("ffn_out_weight", "contract"),
    ("ffn_out_bias", "hidden"),
    ("ln_f_weight", "hidden"),
    ("ln_f_bias", "hidden"),
    ("lm_weight", "head"),
    ("lm_bias", "vocab"),
)


def _numpy() -> Any:
    import numpy

    return numpy


def tensor_shape(kind: str, geometry: Mapping[str, int]) -> tuple[int, ...]:
    seq = int(geometry["sequence"])
    d = int(geometry["hidden_size"])
    inter = int(geometry["intermediate_size"])
    vocab = int(geometry["vocab_size"])
    table = {
        "vocab_hidden": (vocab, d),
        "matrix": (seq, d),
        "hidden": (d,),
        "square": (d, d),
        "expand": (d, inter),
        "intermediate": (inter,),
        "contract": (inter, d),
        "head": (d, vocab),
        "vocab": (vocab,),
    }
    try:
        return table[kind]
    except KeyError as exc:  # pragma: no cover - the table is fixed
        raise ValueError(f"unknown tensor kind {kind!r}") from exc


def build_weights(
    seed: int = D6_SEED,
    geometry: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Draw every tensor of the toy decoder in the pinned order."""
    numpy = _numpy()
    geometry = dict(geometry or D6_GEOMETRY)
    d = int(geometry["hidden_size"])
    generator = numpy.random.default_rng(seed)
    scale = 0.6 / math.sqrt(d)
    weights: dict[str, Any] = {}
    for name, kind in WEIGHT_TENSORS:
        shape = tensor_shape(kind, geometry)
        if name.endswith("_weight") and name in {"ln1_weight", "ln2_weight", "ln_f_weight"}:
            # A LayerNorm gain centred on one keeps the block in the range the
            # fixed-point protocol was measured for.
            weights[name] = numpy.ones(shape, dtype=numpy.float64)
            continue
        if name.endswith("_bias"):
            weights[name] = numpy.zeros(shape, dtype=numpy.float64)
            continue
        weights[name] = numpy.round(
            generator.uniform(-scale, scale, size=shape), 6
        ).astype(numpy.float64)
    return weights


def build_history_one_hot(
    tokens: Sequence[int],
    *,
    sequence: int,
    vocab_size: int,
    pad_token: int = 0,
) -> Any:
    """Right-align a token history and pad the front with the pad token.

    The D5 block always reports the next token from its last row, so the most
    recent token has to sit there. Padding with a real token id rather than
    zeros keeps the attention rows finite without needing a second mask; the
    default is the tokenizer's pad id, and the client and this reference must
    agree on it or they describe different inputs.
    """
    numpy = _numpy()
    if len(tokens) > sequence:
        raise ValueError("the token history does not fit the context window")
    matrix = numpy.zeros((sequence, vocab_size), dtype=numpy.float64)
    offset = sequence - len(tokens)
    for index in range(sequence):
        token = pad_token if index < offset else int(tokens[index - offset])
        if not 0 <= token < vocab_size:
            raise ValueError("the token history leaves the vocabulary")
        matrix[index, token] = 1.0
    return matrix


def reference_step(
    tokens: Sequence[int],
    weights: Mapping[str, Any],
    geometry: Mapping[str, int] | None = None,
    *,
    pad_token: int = 0,
) -> dict[str, Any]:
    """The float next-token reference for one decoding step.

    It mirrors the fused program exactly: the embedding lookup happens first,
    then the D5 block reference runs on the same tensors.
    """
    numpy = _numpy()
    geometry = dict(geometry or D6_GEOMETRY)
    from infra.d5_vectors import reference_block

    config = D5Config(
        sequence=int(geometry["sequence"]),
        hidden_size=int(geometry["hidden_size"]),
        num_heads=int(geometry["num_heads"]),
        intermediate_size=int(geometry["intermediate_size"]),
        vocab_size=int(geometry["vocab_size"]),
        fractional_bits=int(geometry["fractional_bits"]),
    )
    one_hot = build_history_one_hot(
        tokens,
        sequence=config.sequence,
        vocab_size=config.vocab_size,
        pad_token=pad_token,
    )
    inputs: dict[str, Any] = dict(weights)
    inputs["h"] = one_hot @ numpy.asarray(weights["embedding"], dtype=numpy.float64)
    return reference_block(inputs, config)


def error_stats(actual: Any, expected: Any) -> dict[str, Any]:
    """Absolute error of one reconstructed tensor against the float reference."""
    numpy = _numpy()
    got = numpy.asarray(actual, dtype=numpy.float64)
    want = numpy.asarray(expected, dtype=numpy.float64)
    if got.shape != want.shape:
        return {"shape_mismatch": True, "got": list(got.shape), "want": list(want.shape)}
    delta = numpy.abs(got - want)
    return {
        "shape_mismatch": False,
        "max_abs_error": float(delta.max()) if delta.size else 0.0,
        "mean_abs_error": float(delta.mean()) if delta.size else 0.0,
    }


__all__ = [
    "D6_GEOMETRY",
    "D6_LENGTH_BOUND",
    "D6_MAX_NEW_TOKENS",
    "D6_SEED",
    "WEIGHT_TENSORS",
    "build_history_one_hot",
    "build_weights",
    "error_stats",
    "reference_step",
    "tensor_shape",
]

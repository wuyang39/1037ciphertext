"""D7 run geometry, the flat weight set, and the float reference it must match.

The reference here is written to mirror :func:`mpc.spu_backend.d7_program.
build_gpt2_program` operator for operator, the way D5's and D6's references
mirror theirs: the shifted Softmax, the causal mask applied to the
exponentials, the tanh GELU, the residual adds, the final LayerNorm, the head
matmul and the first-index Argmax. Whatever the enclaves return is compared
against this function, so a mismatch is a protocol or binding error rather than
a difference between two readings of the same maths.

None of this touches a framework: the module stays importable inside the
enclave venv, which carries numpy and SPU but no torch.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from infra.d5_vectors import (
    reference_argmax,
    reference_gelu,
    reference_layernorm,
)
from model.gpt2 import (
    Gpt2Config,
    candidate_token_ids,
    load_gpt2_weights,
    open_frozen_store,
    weight_tensor_names,
)
from mpc.spu_backend.d7_program import D7Config, program_inputs


D7_CANDIDATE_SIZE = 1024
"""How many of the most-merged byte pairs the secure Argmax ranks by default."""

D7_MAX_NEW_TOKENS = 3
D7_LENGTH_BOUND = 1 << 20


class D7VectorError(ValueError):
    """A D7 case, weight set or geometry is inconsistent."""


@dataclass(frozen=True)
class D7Run:
    """Everything one D7 run binds to before a single share is split."""

    model_version: str
    sequence: int
    layers: int
    candidate_tokens: tuple[int, ...]
    fractional_bits: int

    @property
    def vocab_size(self) -> int:
        return len(self.candidate_tokens)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "sequence": self.sequence,
            "layers": self.layers,
            "candidate_tokens": list(self.candidate_tokens),
            "vocab_size": self.vocab_size,
            "fractional_bits": self.fractional_bits,
        }


def build_run(
    config: Gpt2Config,
    *,
    model_version: str,
    sequence: int,
    layers: int,
    candidate_size: int = D7_CANDIDATE_SIZE,
    required_tokens: Sequence[int] = (),
    fractional_bits: int = 18,
) -> D7Run:
    """Pin the geometry one run uses, on the frozen model's own numbers."""
    if not 1 <= sequence <= config.n_positions:
        raise D7VectorError("the sequence leaves the position table")
    if not 1 <= layers <= config.n_layer:
        raise D7VectorError("the layer range leaves the frozen model")
    candidates = candidate_token_ids(
        candidate_size,
        required=required_tokens,
        vocab_size=config.vocab_size,
    )
    if len(candidates) > config.vocab_size:
        raise D7VectorError("the candidate set is larger than the vocabulary")
    return D7Run(
        model_version=model_version,
        sequence=sequence,
        layers=layers,
        candidate_tokens=candidates,
        fractional_bits=fractional_bits,
    )


def program_geometry(run: D7Run, config: Gpt2Config) -> D7Config:
    return D7Config(
        sequence=run.sequence,
        layers=run.layers,
        hidden_size=config.n_embd,
        num_heads=config.n_head,
        intermediate_size=config.intermediate_size,
        vocab_size=run.vocab_size,
        fractional_bits=run.fractional_bits,
    )


def load_run_weights(
    source_directory: Path | str,
    config: Gpt2Config,
    run: D7Run,
) -> dict[str, np.ndarray]:
    """Slice the frozen checkpoint into the flat weight set for one run."""
    store = open_frozen_store(source_directory)
    weights = load_gpt2_weights(
        store,
        config,
        layers=run.layers,
        token_ids=run.candidate_tokens,
        sequence=run.sequence,
    )
    validate_weight_shapes(weights, program_geometry(run, config))
    return weights


def validate_weight_shapes(
    weights: Mapping[str, np.ndarray],
    config: D7Config,
) -> None:
    """Refuse a weight set whose tensors do not fit the program interface."""
    shapes = {spec.name: spec.shape for spec in program_inputs(config)}
    expected = {
        name: shapes[name]
        for name in weight_tensor_names(config.layers)
    }
    missing = sorted(set(expected) - set(weights))
    extra = sorted(set(weights) - set(expected))
    if missing or extra:
        raise D7VectorError(
            "the weight set does not match the program: "
            f"missing {missing}, unexpected {extra}"
        )
    for name, shape in expected.items():
        if tuple(weights[name].shape) != tuple(shape):
            raise D7VectorError(
                f"{name} has shape {tuple(weights[name].shape)}, expected {tuple(shape)}"
            )


def candidate_lookup(run: D7Run) -> dict[int, int]:
    """GPT-2 token id -> the position the secure Argmax ranks it at."""
    return {token: index for index, token in enumerate(run.candidate_tokens)}


def encode_prompt(run: D7Run, token_ids: Sequence[int]) -> list[int]:
    """Map real GPT-2 token ids onto the candidate vocabulary."""
    lookup = candidate_lookup(run)
    encoded: list[int] = []
    for token in token_ids:
        try:
            encoded.append(lookup[int(token)])
        except KeyError as exc:
            raise D7VectorError(
                f"prompt token {token} is outside the candidate vocabulary"
            ) from exc
    return encoded


def decode_index(run: D7Run, index: int) -> int:
    if not 0 <= index < run.vocab_size:
        raise D7VectorError(f"candidate index {index} leaves the vocabulary")
    return run.candidate_tokens[index]


def build_history_one_hot(
    indices: Sequence[int],
    *,
    sequence: int,
    vocab_size: int,
    pad_index: int = 0,
) -> np.ndarray:
    """Left-align a history of candidate indices in the context window.

    A causal decoder reads position ``r`` from rows ``0..r``, so the prompt sits
    at the start of the window exactly as it would in the released model and the
    unused rows behind it cannot be attended to from any real row. That is what
    lets one fixed window width serve every step of a session: step ``k``
    predicts from row ``length - 1`` of the same window rather than from a
    re-padded one.
    """
    if len(indices) > sequence:
        raise D7VectorError("the token history does not fit the context window")
    matrix = np.zeros((sequence, vocab_size), dtype=np.float64)
    for position in range(sequence):
        if position >= len(indices):
            index = pad_index
        else:
            index = int(indices[position])
        if not 0 <= index < vocab_size:
            raise D7VectorError("the token history leaves the candidate vocabulary")
        matrix[position, index] = 1.0
    return matrix


def reference_hidden(
    weights: Mapping[str, np.ndarray],
    config: D7Config,
    *,
    collected: dict[str, np.ndarray] | None = None,
) -> np.ndarray:
    """The hidden state after every block, before the final LayerNorm.

    ``collected``, when given, receives the hidden state after each block and
    after the final LayerNorm, under stable stage names. The calibration run
    uses it to compare an exact weight set against a quantized one without a
    second copy of the forward pass existing anywhere.
    """
    seq, d, heads, head = (
        config.sequence,
        config.hidden_size,
        config.num_heads,
        config.head_size,
    )
    current = np.asarray(weights["_history"], dtype=np.float64)
    for index in range(config.layers):
        prefix = f"layer_{index}."

        def weight(suffix: str) -> np.ndarray:
            return np.asarray(weights[prefix + suffix], dtype=np.float64)

        normalized = reference_layernorm(
            current, weight("ln_1.weight"), weight("ln_1.bias")
        )
        query = normalized @ weight("attn.q.weight") + weight("attn.q.bias")
        key = normalized @ weight("attn.k.weight") + weight("attn.k.bias")
        value = normalized @ weight("attn.v.weight") + weight("attn.v.bias")
        query_heads = query.reshape(seq, heads, head).transpose(1, 0, 2)
        key_heads = key.reshape(seq, heads, head).transpose(1, 2, 0)
        value_heads = value.reshape(seq, heads, head).transpose(1, 0, 2)
        scores = query_heads @ key_heads / math.sqrt(head)
        mask = np.tril(np.ones((seq, seq), dtype=np.float64))
        exponentials = np.exp(scores - scores.max(axis=-1, keepdims=True)) * mask
        probabilities = exponentials / exponentials.sum(axis=-1, keepdims=True)
        attended = probabilities @ value_heads
        merged = attended.transpose(1, 0, 2).reshape(seq, d)
        projected = (
            merged @ weight("attn.proj.weight") + weight("attn.proj.bias")
        )
        residual = current + projected
        normalized_2 = reference_layernorm(
            residual, weight("ln_2.weight"), weight("ln_2.bias")
        )
        expanded = normalized_2 @ weight("mlp.fc.weight") + weight("mlp.fc.bias")
        activated = reference_gelu(expanded)
        ffn = activated @ weight("mlp.proj.weight") + weight("mlp.proj.bias")
        current = residual + ffn
        if collected is not None:
            collected[f"layer_{index}"] = current
    return current


def reference_step(
    indices: Sequence[int],
    weights: Mapping[str, np.ndarray],
    config: D7Config,
    *,
    pad_index: int = 0,
    decode_row: int | None = None,
) -> dict[str, Any]:
    """The float next-token reference for one decoding step."""
    if not indices:
        raise D7VectorError("a decoding step needs at least one token of history")
    row = len(indices) - 1 if decode_row is None else int(decode_row)
    if not 0 <= row < len(indices) or row >= config.sequence:
        raise D7VectorError("decode_row does not name a real position of the history")
    one_hot = build_history_one_hot(
        indices,
        sequence=config.sequence,
        vocab_size=config.vocab_size,
        pad_index=pad_index,
    )
    inputs = dict(weights)
    inputs["_history"] = (
        one_hot @ np.asarray(weights["token_embedding.weight"], dtype=np.float64)
        + np.asarray(weights["position_embedding.weight"], dtype=np.float64)
    )
    hidden = reference_hidden(inputs, config)
    normalized = reference_layernorm(
        hidden,
        np.asarray(inputs["ln_f.weight"], dtype=np.float64),
        np.asarray(inputs["ln_f.bias"], dtype=np.float64),
    )
    logits = normalized @ np.asarray(inputs["lm_head.weight"], dtype=np.float64) + (
        np.asarray(inputs["lm_head.bias"], dtype=np.float64)
    )
    return {
        "hidden": hidden,
        "logits": logits,
        "decode_row": row,
        "token": np.array([reference_argmax(logits[row])]),
    }


def error_stats(actual: Any, expected: Any) -> dict[str, Any]:
    """Absolute error of one reconstructed tensor against the float reference."""
    got = np.asarray(actual, dtype=np.float64)
    want = np.asarray(expected, dtype=np.float64)
    if got.shape != want.shape:
        return {
            "shape_mismatch": True,
            "got": list(got.shape),
            "want": list(want.shape),
        }
    delta = np.abs(got - want)
    return {
        "shape_mismatch": False,
        "max_abs_error": float(delta.max()) if delta.size else 0.0,
        "mean_abs_error": float(delta.mean()) if delta.size else 0.0,
    }


def expected_tensor_names(run: D7Run) -> tuple[str, ...]:
    return weight_tensor_names(run.layers)


__all__ = [
    "D7_CANDIDATE_SIZE",
    "D7_LENGTH_BOUND",
    "D7_MAX_NEW_TOKENS",
    "D7Run",
    "D7VectorError",
    "build_history_one_hot",
    "build_run",
    "candidate_lookup",
    "decode_index",
    "encode_prompt",
    "error_stats",
    "expected_tensor_names",
    "load_run_weights",
    "program_geometry",
    "reference_hidden",
    "reference_step",
    "validate_weight_shapes",
]

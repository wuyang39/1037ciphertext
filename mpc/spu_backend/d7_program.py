"""The real GPT-2 decoder, expressed for the same SPU runtime D5 measured.

D5 built one Tiny Decoder block; D6 fused a private embedding lookup in front
of it. D7 keeps every operator and every shape rule the two of them proved and
stacks the block ``layers`` times on the official checkpoint's own geometry, so
the program that runs in the enclave is the GPT-2 computation rather than a
stand-in for it.

Two things differ from the released model, and both are inputs rather than
edits to the arithmetic:

* the output head ranks a *candidate* set of token ids instead of all 50257,
  because the secure Argmax and the head matmul are the two places where the
  full vocabulary does not fit the enclave budget. The candidate ids are part
  of the model manifest, so both sides rank the same list;
* the position table is the leading ``sequence`` rows, which is what a causal
  decoder uses for a context of that length.

The block structure itself is GPT-2's: pre-LayerNorm, fused-then-split query,
key and value projections, scaled causal attention, a residual add, then the
four-times-wide MLP with the tanh GELU, another residual add. The weights are
the real tensors, sliced by :mod:`model.gpt2` and shared out by the dealer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from mpc.spu_backend.d5_program import (
    FXP_FRACTION_BITS,
    SpuProgram,
    TensorSpec,
    D5ProgramError,
    _Emitter,
    _broadcast,
    _dims,
    _emit_gelu,
    _emit_layernorm,
    _emit_linear,
    _function,
    _literal,
    _mask_literal,
    _reduce,
    _type_of,
)


class D7ProgramError(ValueError):
    """A GPT-2 program cannot be built for the requested geometry."""


@dataclass(frozen=True)
class D7Config:
    """The geometry one GPT-2 program is built for."""

    sequence: int = 8
    layers: int = 12
    hidden_size: int = 768
    num_heads: int = 12
    intermediate_size: int = 3072
    vocab_size: int = 1024
    fractional_bits: int = FXP_FRACTION_BITS

    def __post_init__(self) -> None:
        if self.hidden_size % self.num_heads:
            raise D7ProgramError("hidden_size must be divisible by num_heads")
        for field in (
            "sequence",
            "layers",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "vocab_size",
        ):
            if int(getattr(self, field)) <= 0:
                raise D7ProgramError(f"{field} must be positive")

    @property
    def head_size(self) -> int:
        return self.hidden_size // self.num_heads


def ir_name(tensor: str) -> str:
    """The SSA name one manifest tensor is bound to inside the program."""
    return "%" + "".join(
        character if character.isalnum() else "_" for character in tensor
    )


def program_inputs(config: D7Config) -> tuple[TensorSpec, ...]:
    """The typed interface of the GPT-2 program, in manifest order."""
    seq, d, inter, vocab = (
        config.sequence,
        config.hidden_size,
        config.intermediate_size,
        config.vocab_size,
    )
    specs: list[TensorSpec] = [
        TensorSpec("history", (seq, vocab)),
        TensorSpec("token_embedding.weight", (vocab, d)),
        TensorSpec("position_embedding.weight", (seq, d)),
    ]
    for index in range(config.layers):
        layer = f"layer_{index}."
        specs.extend(
            [
                TensorSpec(layer + "ln_1.weight", (d,)),
                TensorSpec(layer + "ln_1.bias", (d,)),
                TensorSpec(layer + "attn.q.weight", (d, d)),
                TensorSpec(layer + "attn.q.bias", (d,)),
                TensorSpec(layer + "attn.k.weight", (d, d)),
                TensorSpec(layer + "attn.k.bias", (d,)),
                TensorSpec(layer + "attn.v.weight", (d, d)),
                TensorSpec(layer + "attn.v.bias", (d,)),
                TensorSpec(layer + "attn.proj.weight", (d, d)),
                TensorSpec(layer + "attn.proj.bias", (d,)),
                TensorSpec(layer + "ln_2.weight", (d,)),
                TensorSpec(layer + "ln_2.bias", (d,)),
                TensorSpec(layer + "mlp.fc.weight", (d, inter)),
                TensorSpec(layer + "mlp.fc.bias", (inter,)),
                TensorSpec(layer + "mlp.proj.weight", (inter, d)),
                TensorSpec(layer + "mlp.proj.bias", (d,)),
            ]
        )
    specs.extend(
        [
            TensorSpec("ln_f.weight", (d,)),
            TensorSpec("ln_f.bias", (d,)),
            TensorSpec("lm_head.weight", (d, vocab)),
            TensorSpec("lm_head.bias", (vocab,)),
        ]
    )
    return tuple(specs)


def _emit_block(
    emitter: _Emitter,
    config: D7Config,
    *,
    current: str,
    prefix: str,
) -> str:
    """One GPT-2 block, emitted exactly as the D5 block emits its own."""
    seq, d, heads, head, inter = (
        config.sequence,
        config.hidden_size,
        config.num_heads,
        config.head_size,
        config.intermediate_size,
    )
    matrix = _type_of((seq, d))
    split = _type_of((seq, heads, head))
    per_head = _type_of((heads, seq, head))
    keys = _type_of((heads, head, seq))
    scores_type = _type_of((heads, seq, seq))
    heads_seq = _type_of((heads, seq))
    mask_type = _type_of((seq, seq))
    hidden = _type_of((d,))
    intermediate = _type_of((inter,))
    expanded_type = _type_of((seq, inter))

    def name(suffix: str) -> str:
        return ir_name(f"{prefix}.{suffix}")

    normalized_1 = _emit_layernorm(
        emitter,
        current,
        matrix,
        seq,
        d,
        name("ln_1.weight"),
        name("ln_1.bias"),
    )
    query = _emit_linear(
        emitter,
        normalized_1,
        matrix,
        name("attn.q.weight"),
        _type_of((d, d)),
        name("attn.q.bias"),
        hidden,
        matrix,
        [1],
    )
    key = _emit_linear(
        emitter,
        normalized_1,
        matrix,
        name("attn.k.weight"),
        _type_of((d, d)),
        name("attn.k.bias"),
        hidden,
        matrix,
        [1],
    )
    value = _emit_linear(
        emitter,
        normalized_1,
        matrix,
        name("attn.v.weight"),
        _type_of((d, d)),
        name("attn.v.bias"),
        hidden,
        matrix,
        [1],
    )

    def to_heads(operand: str, permutation: Sequence[int], target: str) -> str:
        reshaped = emitter.assign(
            "rs", f"mhlo.reshape {operand} : ({matrix}) -> {split}"
        )
        return emitter.assign(
            "tp",
            f"\"mhlo.transpose\"({reshaped}) {{permutation = {_dims(permutation)} : "
            f"tensor<3xi64>}} : ({split}) -> {target}",
        )

    query_heads = to_heads(query, [1, 0, 2], per_head)
    key_heads = to_heads(key, [1, 2, 0], keys)
    value_heads = to_heads(value, [1, 0, 2], per_head)
    scores = emitter.assign(
        "sc",
        f"\"mhlo.dot_general\"({query_heads}, {key_heads}) {{dot_dimension_numbers = "
        f"#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        f"lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>}} : "
        f"({per_head}, {keys}) -> {scores_type}",
    )
    scale = emitter.assign(
        "sl",
        f"mhlo.constant dense<{_literal(1.0 / math.sqrt(head))}> : {scores_type}",
    )
    scaled_scores = emitter.assign(
        "ss", f"mhlo.multiply {scores}, {scale} : {scores_type}"
    )
    row_max = _reduce(
        emitter, scaled_scores, scores_type, heads_seq, -1e9, "mhlo.maximum", 2
    )
    row_max_b = _broadcast(emitter, row_max, heads_seq, scores_type, [0, 1])
    shifted = emitter.assign(
        "sh", f"mhlo.subtract {scaled_scores}, {row_max_b} : {scores_type}"
    )
    exponentials = emitter.assign(
        "ex", f"mhlo.exponential {shifted} : {scores_type}"
    )
    mask = emitter.assign(
        "mk", f"mhlo.constant dense<{_mask_literal(seq)}> : {mask_type}"
    )
    mask_b = _broadcast(emitter, mask, mask_type, scores_type, [1, 2])
    masked = emitter.assign(
        "me", f"mhlo.multiply {exponentials}, {mask_b} : {scores_type}"
    )
    denominator = _reduce(emitter, masked, scores_type, heads_seq, 0.0, "mhlo.add", 2)
    denominator_b = _broadcast(emitter, denominator, heads_seq, scores_type, [0, 1])
    probabilities = emitter.assign(
        "pr", f"mhlo.divide {masked}, {denominator_b} : {scores_type}"
    )
    attended = emitter.assign(
        "at",
        f"\"mhlo.dot_general\"({probabilities}, {value_heads}) {{dot_dimension_numbers = "
        f"#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        f"lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>}} : "
        f"({scores_type}, {per_head}) -> {per_head}",
    )
    restored = emitter.assign(
        "rr",
        f"\"mhlo.transpose\"({attended}) {{permutation = {_dims([1, 0, 2])} : "
        f"tensor<3xi64>}} : ({per_head}) -> {split}",
    )
    merged = emitter.assign("mg", f"mhlo.reshape {restored} : ({split}) -> {matrix}")
    projected = _emit_linear(
        emitter,
        merged,
        matrix,
        name("attn.proj.weight"),
        _type_of((d, d)),
        name("attn.proj.bias"),
        hidden,
        matrix,
        [1],
    )
    residual = emitter.assign("rz", f"mhlo.add {current}, {projected} : {matrix}")
    normalized_2 = _emit_layernorm(
        emitter,
        residual,
        matrix,
        seq,
        d,
        name("ln_2.weight"),
        name("ln_2.bias"),
    )
    expanded = _emit_linear(
        emitter,
        normalized_2,
        matrix,
        name("mlp.fc.weight"),
        _type_of((d, inter)),
        name("mlp.fc.bias"),
        intermediate,
        expanded_type,
        [1],
    )
    activated = _emit_gelu(emitter, expanded, expanded_type)
    ffn = _emit_linear(
        emitter,
        activated,
        expanded_type,
        name("mlp.proj.weight"),
        _type_of((inter, d)),
        name("mlp.proj.bias"),
        hidden,
        matrix,
        [1],
    )
    return emitter.assign("ho", f"mhlo.add {residual}, {ffn} : {matrix}")


def build_gpt2_program(config: D7Config, *, decode_row: int | None = None) -> SpuProgram:
    """The whole decoding step: private embedding, every block, head, Argmax.

    ``decode_row`` is the context position the step predicts from. A prompt is
    left-aligned at the start of the window and everything behind it is masked
    out of every real row by the causal mask, so reading the last row of a
    full-width window and reading row ``length - 1`` of a window that is only
    partly used are the same computation; the second one lets one fixed window
    width serve every step of a session. Only the logits at ``decode_row`` reach
    the Argmax, so the unused rows cannot influence the token.
    """
    row = config.sequence - 1 if decode_row is None else int(decode_row)
    if not 0 <= row < config.sequence:
        raise D7ProgramError("decode_row leaves the context window")
    seq, d, vocab = config.sequence, config.hidden_size, config.vocab_size
    matrix = _type_of((seq, d))
    one_hot = _type_of((seq, vocab))
    table = _type_of((vocab, d))
    head_table = _type_of((d, vocab))
    vocab_vector = _type_of((vocab,))
    logits_table = _type_of((seq, vocab))
    one = "tensor<1xf64>"

    emitter = _Emitter()
    # The token lookup and the position add are the only arithmetic before the
    # blocks. Both operands are secret: the client's one-hot history and the
    # model's two tables, so no token id or position ever reaches a party.
    embedded = emitter.assign(
        "em",
        f"\"mhlo.dot_general\"(%history, {ir_name('token_embedding.weight')}) "
        f"{{dot_dimension_numbers = #mhlo.dot<lhs_contracting_dimensions = [1], "
        f"rhs_contracting_dimensions = [0]>}} : ({one_hot}, {table}) -> {matrix}",
    )
    current = emitter.assign(
        "ps",
        f"mhlo.add {embedded}, {ir_name('position_embedding.weight')} : {matrix}",
    )
    for index in range(config.layers):
        current = _emit_block(
            emitter, config, current=current, prefix=f"layer_{index}"
        )
    normalized_final = _emit_layernorm(
        emitter,
        current,
        matrix,
        seq,
        d,
        ir_name("ln_f.weight"),
        ir_name("ln_f.bias"),
    )
    logits = _emit_linear(
        emitter,
        normalized_final,
        matrix,
        ir_name("lm_head.weight"),
        head_table,
        ir_name("lm_head.bias"),
        vocab_vector,
        logits_table,
        [1],
    )
    last_row = emitter.assign(
        "lr",
        f"\"mhlo.slice\"({logits}) {{start_indices = dense<[{row}, 0]> : tensor<2xi64>, "
        f"limit_indices = dense<[{row + 1}, {vocab}]> : tensor<2xi64>, "
        f"strides = dense<[1, 1]> : tensor<2xi64>}} : ({logits_table}) -> "
        f"tensor<1x{vocab}xf64>",
    )
    logits_vector = emitter.assign(
        "lv", f"mhlo.reshape {last_row} : (tensor<1x{vocab}xf64>) -> {vocab_vector}"
    )
    maximum = _reduce(
        emitter, logits_vector, vocab_vector, "tensor<f64>", -1e9, "mhlo.maximum", 0
    )
    maximum_b = _broadcast(emitter, maximum, "tensor<f64>", vocab_vector, [])
    is_max = emitter.assign(
        "mx",
        f"mhlo.compare GE, {logits_vector}, {maximum_b} : "
        f"({vocab_vector}, {vocab_vector}) -> tensor<{vocab}xi1>",
    )
    indices = emitter.assign(
        "ix",
        "mhlo.constant dense<["
        + ", ".join(_literal(index) for index in range(vocab))
        + f"]> : {vocab_vector}",
    )
    sentinel = emitter.assign(
        "sn", f"mhlo.constant dense<{_literal(vocab)}> : {vocab_vector}"
    )
    candidates = emitter.assign(
        "cd",
        f"\"mhlo.select\"({is_max}, {indices}, {sentinel}) : "
        f"(tensor<{vocab}xi1>, {vocab_vector}, {vocab_vector}) -> {vocab_vector}",
    )
    chosen = _reduce(
        emitter, candidates, vocab_vector, "tensor<f64>", 1e9, "mhlo.minimum", 0
    )
    token = emitter.assign(
        "tk",
        f"\"mhlo.broadcast_in_dim\"({chosen}) {{broadcast_dimensions = dense<> : "
        f"tensor<0xi64>}} : (tensor<f64>) -> {one}",
    )
    outputs = (
        TensorSpec("hidden", (seq, d)),
        TensorSpec("logits", (seq, vocab)),
        TensorSpec("token", (1,)),
    )
    inputs = program_inputs(config)
    return SpuProgram(
        name="gpt2-step",
        text=_function(emitter, inputs, outputs, [current, logits, token]),
        inputs=inputs,
        outputs=outputs,
    )


__all__ = [
    "D5ProgramError",
    "D7Config",
    "D7ProgramError",
    "build_gpt2_program",
    "ir_name",
    "program_inputs",
]

"""Secure-operation reference for the Tiny Decoder block.

Linear algebra is represented by RSS shares over a fixed-point ring. The
non-linear functions below use a deliberately explicit simulation reveal so
that local alignment tests can compare against the float model. Production
enclave code must replace these functions with the corresponding secure
protocol implementations.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Iterable, Sequence

from model.fixed_point import FixedPointFormat, RoundingMode, encode_fixed
from model.fixed_point import to_signed

from .fixed_point_adapter import FixedPointAdapter
from .provider import (
    SecureNonlinearProvider,
    SimulationRevealProvider,
)
from .rss import RSSContext, RSSProtocolError, SharedTensor


DEFAULT_FRACTIONAL_BITS = 16
DEFAULT_RING_BITS = 64
GELU_SQRT_TWO_OVER_PI = math.sqrt(2.0 / math.pi)


def _shape(value: Any) -> tuple[int, ...]:
    if isinstance(value, list):
        if not value:
            return (0,)
        child_shapes = [_shape(child) for child in value]
        if any(child != child_shapes[0] for child in child_shapes[1:]):
            raise ValueError("matrix is not rectangular")
        return (len(value), *child_shapes[0])
    return ()


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, list):
        result: list[Any] = []
        for child in value:
            result.extend(_flatten(child))
        return result
    return [value]


def _nest(flat: Sequence[Any], shape: Sequence[int]) -> Any:
    if not shape:
        return flat[0]
    if len(shape) == 1:
        return list(flat[: shape[0]])
    stride = math.prod(shape[1:])
    return [
        _nest(flat[index * stride : (index + 1) * stride], shape[1:])
        for index in range(shape[0])
    ]


def _fixed_format(fractional_bits: int, ring_bits: int) -> FixedPointFormat:
    return FixedPointFormat(
        fractional_bits=fractional_bits,
        bits=ring_bits,
        signed=True,
    )


def _encode_value(value: Any, fractional_bits: int, ring_bits: int) -> Any:
    format = _fixed_format(fractional_bits, ring_bits)
    if isinstance(value, list):
        return [_encode_value(child, fractional_bits, ring_bits) for child in value]
    return encode_fixed(value, format)


class FixedSecureOps:
    """Fixed-point RSS operations for one transformer block."""

    def __init__(
        self,
        context: RSSContext,
        *,
        fractional_bits: int = DEFAULT_FRACTIONAL_BITS,
        nonlinear_provider: SecureNonlinearProvider | None = None,
    ) -> None:
        if fractional_bits < 1 or fractional_bits >= context.ring_bits:
            raise ValueError("fractional_bits must be inside the RSS ring")
        self.context = context
        self.fractional_bits = fractional_bits
        self.format = _fixed_format(fractional_bits, context.ring_bits)
        self.adapter = FixedPointAdapter(self.format, context)
        self.nonlinear_provider = (
            nonlinear_provider
            if nonlinear_provider is not None
            else SimulationRevealProvider()
        )

    def share_value(self, value: Any) -> SharedTensor:
        """Share a rational value after deterministic fixed-point encoding."""
        return self.context.share(
            _encode_value(value, self.fractional_bits, self.context.ring_bits)
        )

    def decode(self, shared: SharedTensor, *, signed: bool = True) -> Any:
        if shared.ring_bits != self.context.ring_bits:
            raise RSSProtocolError("shared tensor ring does not match")
        raw = self.context.reconstruct(shared)
        return self._decode_raw(raw, signed=signed)

    def _decode_raw(self, raw: Any, *, signed: bool) -> Any:
        if isinstance(raw, list):
            return [self._decode_raw(child, signed=signed) for child in raw]
        value = (
            to_signed(int(raw), self.format)
            if signed
            else int(raw) & self.format.mask
        )
        return Fraction(value, self.format.scale)

    def _encode_raw_value(self, value: Any) -> Any:
        return _encode_value(value, self.fractional_bits, self.context.ring_bits)

    def _share_raw(self, value: Any) -> SharedTensor:
        return self.context.share(value)

    def _linear_raw(
        self,
        input_shared: SharedTensor,
        weights: Sequence[Sequence[float]],
        bias: Sequence[float] | None = None,
    ) -> SharedTensor:
        if input_shared.shape[-1] != len(weights):
            raise RSSProtocolError("linear input width does not match weights")
        if any(len(row) != len(weights[0]) for row in weights):
            raise RSSProtocolError("linear weight matrix is not rectangular")
        weight_shared = self.share_value([list(row) for row in weights])
        product = self.context.matmul(input_shared, weight_shared)
        output = self.context.truncate(
            product,
            shift_bits=self.fractional_bits,
        )
        if bias is not None:
            if len(bias) != len(weights[0]):
                raise RSSProtocolError("linear bias has the wrong width")
            output = self._add_bias(output, bias)
        return output

    def _add_bias(
        self,
        input_shared: SharedTensor,
        bias: Sequence[float],
    ) -> SharedTensor:
        rows, columns = input_shared.shape
        bias_shared = self.share_value(list(bias))
        expanded = self._broadcast_rows(bias_shared, rows)
        return self.context.add(input_shared, expanded)

    def _broadcast_rows(
        self,
        row_shared: SharedTensor,
        rows: int,
    ) -> SharedTensor:
        if len(row_shared.shape) != 1 or row_shared.shape[0] == 0:
            raise RSSProtocolError("broadcast source must be a non-empty vector")
        repeated = tuple(
            share * rows
            for share in row_shared.shares
        )
        return SharedTensor(
            shares=repeated,
            shape=(rows, row_shared.shape[0]),
            ring_bits=self.context.ring_bits,
        )

    def _nonlinear(self, input_shared: SharedTensor, transform: Any, name: str) -> SharedTensor:
        return self.nonlinear_provider.evaluate(
            name=name,
            input_shared=input_shared,
            context=self.context,
            decode=self.decode,
            encode=self.share_value,
            transform=transform,
            parameters={
                "scale": self.format.scale,
                "fractional_bits": self.fractional_bits,
            },
        )

    def embedding(
        self,
        token_shared: SharedTensor,
        embedding_matrix: Sequence[Sequence[float]],
    ) -> SharedTensor:
        """Select a row with shared token equality instead of clear embedding."""
        if token_shared.shape != ():
            raise RSSProtocolError("secure embedding token must be a scalar share")
        if not embedding_matrix or any(
            len(row) != len(embedding_matrix[0]) for row in embedding_matrix
        ):
            raise RSSProtocolError("embedding matrix is not rectangular")
        result = self.share_value([0.0] * len(embedding_matrix[0]))
        for token_id, row in enumerate(embedding_matrix):
            token_ge_row = self.context.compare(
                token_shared,
                self.context.share(token_id),
                operation="secure_embedding/Idx2v",
            )
            row_ge_token = self.context.compare(
                self.context.share(token_id),
                token_shared,
                operation="secure_embedding/Idx2v",
            )
            mask = self.context.mul(token_ge_row, row_ge_token)
            selected = self.context.scalar_mul(
                self.share_value(list(row)),
                self.context.reconstruct(mask),
            )
            result = self.context.add(result, selected)
        return result

    def causal_attention(
        self,
        hidden: SharedTensor,
        *,
        num_heads: int,
        weights_qkv: Sequence[Sequence[float]],
        bias_qkv: Sequence[float],
    ) -> SharedTensor:
        """Run QKV, causal QK^T, stable softmax, and A*V for one block."""
        if len(hidden.shape) != 2:
            raise RSSProtocolError("attention input must be [sequence, hidden]")
        sequence, hidden_size = hidden.shape
        if hidden_size % num_heads:
            raise RSSProtocolError("hidden size must be divisible by heads")
        head_size = hidden_size // num_heads
        qkv = self._linear_raw(hidden, weights_qkv, bias_qkv)
        query = self._column_slice(qkv, 0, hidden_size)
        key = self._column_slice(qkv, hidden_size, hidden_size)
        value = self._column_slice(qkv, 2 * hidden_size, hidden_size)

        query_rows = self._reshape_heads(query, num_heads)
        key_rows = self._reshape_heads(key, num_heads)
        value_rows = self._reshape_heads(value, num_heads)
        outputs: list[SharedTensor] = []
        for head in range(num_heads):
            scores = self.context.matmul(
                query_rows[head],
                self._transpose(key_rows[head]),
            )
            scores = self.context.truncate(
                scores,
                shift_bits=self.fractional_bits,
            )
            scale_factor = int(
                round((1.0 / math.sqrt(head_size)) * self.format.scale)
            )
            scores = self.context.scalar_mul(
                scores,
                scale_factor,
            )
            scores = self._apply_causal_mask(scores)
            probabilities = self.softmax(scores)
            head_output = self.context.matmul(probabilities, value_rows[head])
            outputs.append(
                self.context.truncate(
                    head_output,
                    shift_bits=self.fractional_bits,
                )
            )
        merged = self._merge_heads(outputs, num_heads, head_size)
        return merged

    def _column_slice(
        self,
        tensor: SharedTensor,
        start: int,
        width: int,
    ) -> SharedTensor:
        rows, columns = tensor.shape
        if start < 0 or width < 0 or start + width > columns:
            raise RSSProtocolError("column slice is out of bounds")
        shares = []
        for party in tensor.shares:
            values: list[int] = []
            for row in range(rows):
                base = row * columns + start
                values.extend(party[base : base + width])
            shares.append(tuple(values))
        return SharedTensor(tuple(shares), (rows, width), self.context.ring_bits)

    def _reshape_heads(
        self,
        tensor: SharedTensor,
        num_heads: int,
    ) -> list[SharedTensor]:
        rows, columns = tensor.shape
        head_size = columns // num_heads
        heads: list[SharedTensor] = []
        for head in range(num_heads):
            shares = []
            for party in tensor.shares:
                values: list[int] = []
                for row in range(rows):
                    base = row * columns + head * head_size
                    values.extend(party[base : base + head_size])
                shares.append(tuple(values))
            heads.append(
                SharedTensor(tuple(shares), (rows, head_size), self.context.ring_bits)
            )
        return heads

    def _transpose(self, tensor: SharedTensor) -> SharedTensor:
        rows, columns = tensor.shape
        shares = []
        for party in tensor.shares:
            values = [0] * (rows * columns)
            for row in range(rows):
                for column in range(columns):
                    values[column * rows + row] = party[row * columns + column]
            shares.append(tuple(values))
        return SharedTensor(tuple(shares), (columns, rows), self.context.ring_bits)

    def _merge_heads(
        self,
        heads: Sequence[SharedTensor],
        num_heads: int,
        head_size: int,
    ) -> SharedTensor:
        rows = heads[0].shape[0]
        shares = []
        for party_index in range(3):
            values: list[int] = []
            for row in range(rows):
                for head in range(num_heads):
                    base = row * head_size
                    values.extend(heads[head].shares[party_index][base : base + head_size])
            shares.append(tuple(values))
        return SharedTensor(tuple(shares), (rows, num_heads * head_size), self.context.ring_bits)

    def _apply_causal_mask(self, scores: SharedTensor) -> SharedTensor:
        if not self.context.reveal_allowed:
            raise RSSProtocolError("causal mask requires a secure masking protocol")
        raw = self.context.reconstruct_signed(scores)
        masked = []
        for row, values in enumerate(raw):
            masked.append(
                [
                    value if column <= row else -(10**9) * self.format.scale
                    for column, value in enumerate(values)
                ]
            )
        return self.context.share(masked)

    def softmax(self, scores: SharedTensor) -> SharedTensor:
        def transform(rows: Any) -> Any:
            vector_input = bool(rows) and not isinstance(rows[0], list)
            if vector_input:
                rows = [rows]
            output = []
            for row in rows:
                values = [float(value) for value in row]
                maximum = max(values)
                exponentials = [math.exp(value - maximum) for value in values]
                denominator = sum(exponentials)
                output.append([value / denominator for value in exponentials])
            return output[0] if vector_input else output

        return self._nonlinear(scores, transform, "softmax")

    def layer_norm(
        self,
        input_shared: SharedTensor,
        gamma: Sequence[float],
        beta: Sequence[float],
        *,
        epsilon: float = 1e-5,
    ) -> SharedTensor:
        if len(input_shared.shape) != 2:
            raise RSSProtocolError("LayerNorm input must be two-dimensional")
        if len(gamma) != input_shared.shape[1] or len(beta) != input_shared.shape[1]:
            raise RSSProtocolError("LayerNorm parameter width mismatch")

        def transform(rows: Any) -> Any:
            output = []
            for row in rows:
                values = [float(value) for value in row]
                mean = sum(values) / len(values)
                variance = sum((value - mean) ** 2 for value in values) / len(values)
                inverse = 1.0 / math.sqrt(variance + epsilon)
                output.append(
                    [
                        (value - mean) * inverse * float(scale) + float(offset)
                        for value, scale, offset in zip(values, gamma, beta)
                    ]
                )
            return output

        return self._nonlinear(input_shared, transform, "layernorm")

    def gelu(self, input_shared: SharedTensor) -> SharedTensor:
        def transform(value: Any) -> Any:
            if isinstance(value, list):
                return [transform(child) for child in value]
            number = float(value)
            return 0.5 * number * (1.0 + math.erf(number / math.sqrt(2.0)))

        return self._nonlinear(input_shared, transform, "gelu")

    def ffn(
        self,
        input_shared: SharedTensor,
        *,
        weights_in: Sequence[Sequence[float]],
        bias_in: Sequence[float],
        weights_out: Sequence[Sequence[float]],
        bias_out: Sequence[float],
    ) -> SharedTensor:
        hidden = self._linear_raw(input_shared, weights_in, bias_in)
        return self._linear_raw(self.gelu(hidden), weights_out, bias_out)

    def block(
        self,
        hidden: SharedTensor,
        *,
        parameters: dict[str, Any],
    ) -> SharedTensor:
        """Execute one pre-norm Tiny Decoder block in the documented order."""
        normalized = self.layer_norm(
            hidden,
            parameters["ln_1_weight"],
            parameters["ln_1_bias"],
        )
        attended = self.causal_attention(
            normalized,
            num_heads=parameters["num_heads"],
            weights_qkv=parameters["qkv_weight"],
            bias_qkv=parameters["qkv_bias"],
        )
        projected = self._linear_raw(
            attended,
            parameters["attention_out_weight"],
            parameters["attention_out_bias"],
        )
        residual = self.context.add(hidden, projected)
        normalized = self.layer_norm(
            residual,
            parameters["ln_2_weight"],
            parameters["ln_2_bias"],
        )
        ffn_output = self.ffn(
            normalized,
            weights_in=parameters["ffn_in_weight"],
            bias_in=parameters["ffn_in_bias"],
            weights_out=parameters["ffn_out_weight"],
            bias_out=parameters["ffn_out_bias"],
        )
        return self.context.add(residual, ffn_output)

    def argmax(self, logits: SharedTensor) -> int:
        if len(logits.shape) != 1:
            raise RSSProtocolError("secure_argmax expects a vector")
        if not self.context.reveal_allowed:
            raise RSSProtocolError("secure_argmax output reconstruction is disabled")
        values = self.decode(logits)
        return max(range(len(values)), key=lambda index: float(values[index]))

    def trace_dicts(self) -> list[dict[str, Any]]:
        return [trace.to_dict() for trace in self.context.traces]


def gelu_float(value: float) -> float:
    return 0.5 * value * (1.0 + math.erf(value / math.sqrt(2.0)))


__all__ = [
    "DEFAULT_FRACTIONAL_BITS",
    "DEFAULT_RING_BITS",
    "FixedSecureOps",
    "gelu_float",
]

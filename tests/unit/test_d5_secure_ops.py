from __future__ import annotations

import math

import torch

from mpc.secure_ops.rss import RSSContext
from mpc.secure_ops.transformer import FixedSecureOps


def test_secure_linear_embedding_and_nonlinear_traces() -> None:
    context = RSSContext(ring_bits=64, seed=5)
    ops = FixedSecureOps(context, fractional_bits=16)
    x = ops.share_value([[0.5, -1.5]])
    output = ops._linear_raw(
        x,
        [[1.0, 2.0], [3.0, 4.0]],
        [0.25, -0.5],
    )
    decoded = ops.decode(output)
    assert abs(float(decoded[0][0]) + 3.75) < 0.001
    assert abs(float(decoded[0][1]) + 5.5) < 0.001

    token = context.share(2)
    embedding = ops.embedding(
        token,
        [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]],
    )
    assert [float(value) for value in ops.decode(embedding)] == [5.0, 6.0]

    probabilities = ops.softmax(ops.share_value([1.0, 2.0, 3.0]))
    decoded_probabilities = [float(value) for value in ops.decode(probabilities)]
    assert abs(sum(decoded_probabilities) - 1.0) < 0.001
    assert any(
        trace["simulated_reveal"]
        for trace in ops.trace_dicts()
        if trace["operation"] == "softmax"
    )
    assert all(
        set(trace) == {
            "operation",
            "shape",
            "ring",
            "scale",
            "range",
            "rounds",
            "bytes",
            "elapsed_ms",
            "simulated_reveal",
        }
        for trace in ops.trace_dicts()
    )


def test_secure_block_matches_float_block_reference() -> None:
    context = RSSContext(ring_bits=64, seed=11)
    ops = FixedSecureOps(context, fractional_bits=16)
    hidden = [[0.125, -0.25, 0.5, -0.75]]
    parameters = {
        "num_heads": 2,
        "ln_1_weight": [1.0, 0.9, 1.1, 1.0],
        "ln_1_bias": [0.0, 0.1, -0.1, 0.0],
        "qkv_weight": [
            [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2],
            [0.2, -0.1, 0.4, -0.3, 0.6, -0.5, 0.8, -0.7, 1.0, -0.9, 1.2, -1.1],
            [0.3, 0.1, -0.2, 0.5, -0.4, 0.7, -0.6, 0.9, -0.8, 1.1, -1.0, 1.3],
            [0.4, -0.2, 0.1, -0.5, 0.3, -0.7, 0.5, -0.9, 0.7, -1.1, 0.9, -1.3],
        ],
        "qkv_bias": [0.01] * 12,
        "attention_out_weight": [
            [0.1, 0.2, 0.3, 0.4],
            [0.5, 0.6, 0.7, 0.8],
            [0.9, 1.0, 1.1, 1.2],
            [1.3, 1.4, 1.5, 1.6],
        ],
        "attention_out_bias": [0.0, 0.01, 0.02, 0.03],
        "ln_2_weight": [1.0, 1.0, 1.0, 1.0],
        "ln_2_bias": [0.0, 0.0, 0.0, 0.0],
        "ffn_in_weight": [
            [0.1, 0.2, 0.3],
            [0.4, 0.5, 0.6],
            [0.7, 0.8, 0.9],
            [1.0, 1.1, 1.2],
        ],
        "ffn_in_bias": [0.0, 0.1, 0.2],
        "ffn_out_weight": [
            [0.2, 0.1, 0.0, -0.1],
            [0.3, 0.2, 0.1, 0.0],
            [0.4, 0.3, 0.2, 0.1],
        ],
        "ffn_out_bias": [0.0, 0.0, 0.0, 0.0],
    }
    secure_output = ops.block(ops.share_value(hidden), parameters=parameters)
    secure_values = [
        float(value) for value in ops.decode(secure_output)[0]
    ]
    float_values = _float_block(hidden[0], parameters)
    for actual, expected in zip(secure_values, float_values):
        assert math.isclose(actual, expected, abs_tol=0.08, rel_tol=0.08)
    assert any(
        trace["operation"] == "rss_matmul"
        for trace in ops.trace_dicts()
    )
    assert any(
        trace["operation"] == "layernorm" and trace["simulated_reveal"]
        for trace in ops.trace_dicts()
    )


def test_secure_argmax_is_explicit_and_returns_token_index() -> None:
    context = RSSContext(ring_bits=64, seed=3)
    ops = FixedSecureOps(context, fractional_bits=16)
    logits = ops.share_value([0.2, 1.5, -0.4])
    assert ops.argmax(logits) == 1


def _float_block(hidden, parameters):
    x = torch.tensor([[hidden]], dtype=torch.float64)

    def linear(value, weight, bias):
        return value @ torch.tensor(weight, dtype=torch.float64) + torch.tensor(
            bias, dtype=torch.float64
        )

    normalized = _layer_norm(
        x,
        parameters["ln_1_weight"],
        parameters["ln_1_bias"],
    )
    qkv = linear(normalized, parameters["qkv_weight"], parameters["qkv_bias"])
    q, k, v = qkv.chunk(3, dim=-1)
    sequence = x.shape[1]
    head_size = x.shape[-1] // parameters["num_heads"]
    q = q.reshape(1, sequence, parameters["num_heads"], head_size).transpose(1, 2)
    k = k.reshape(1, sequence, parameters["num_heads"], head_size).transpose(1, 2)
    v = v.reshape(1, sequence, parameters["num_heads"], head_size).transpose(1, 2)
    scores = (q @ k.transpose(-2, -1)) / math.sqrt(head_size)
    mask = torch.tril(torch.ones(sequence, sequence, dtype=torch.bool))
    scores = scores.masked_fill(~mask, -1e9)
    attention = torch.softmax(scores, dim=-1)
    attended = (attention @ v).transpose(1, 2).reshape(1, sequence, -1)
    attended = linear(
        attended,
        parameters["attention_out_weight"],
        parameters["attention_out_bias"],
    )
    residual = x + attended
    normalized = _layer_norm(
        residual,
        parameters["ln_2_weight"],
        parameters["ln_2_bias"],
    )
    hidden_value = linear(
        normalized,
        parameters["ffn_in_weight"],
        parameters["ffn_in_bias"],
    )
    hidden_value = 0.5 * hidden_value * (
        1.0 + torch.erf(hidden_value / math.sqrt(2.0))
    )
    output = linear(
        hidden_value,
        parameters["ffn_out_weight"],
        parameters["ffn_out_bias"],
    )
    return (residual + output)[0, 0].tolist()


def _layer_norm(value, gamma, beta):
    mean = value.mean(dim=-1, keepdim=True)
    variance = value.var(dim=-1, unbiased=False, keepdim=True)
    return (value - mean) / torch.sqrt(variance + 1e-5) * torch.tensor(
        gamma, dtype=torch.float64
    ) + torch.tensor(beta, dtype=torch.float64)

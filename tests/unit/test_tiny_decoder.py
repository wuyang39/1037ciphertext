from __future__ import annotations

import json
from pathlib import Path

import torch

from model.tiny_decoder import TinyDecoder, TinyDecoderConfig


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "tiny_float_reference.json"
)


def test_tiny_decoder_matches_frozen_float_reference() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    config = TinyDecoderConfig(**fixture["config"])
    model = TinyDecoder(config, seed=fixture["seed"]).eval()
    assert model.parameter_hash() == fixture["parameter_hash"]

    for prompt in fixture["prompts"]:
        input_ids = torch.tensor([prompt["input_ids"]], dtype=torch.long)
        with torch.inference_mode():
            output = model(input_ids)
        expected_logits = torch.tensor(prompt["logits"], dtype=output.logits.dtype)
        expected_argmax = torch.tensor(prompt["argmax"], dtype=torch.long)
        assert torch.allclose(output.logits[0], expected_logits, atol=1e-6, rtol=1e-6)
        assert torch.equal(output.logits[0].argmax(dim=-1), expected_argmax)


def test_incremental_cache_matches_full_forward() -> None:
    config = TinyDecoderConfig(
        vocab_size=32,
        hidden_size=8,
        num_layers=2,
        num_heads=2,
        intermediate_size=16,
        max_seq_len=16,
    )
    model = TinyDecoder(config, seed=7).eval()
    prompt = torch.tensor([[1, 4, 7, 10]], dtype=torch.long)
    with torch.inference_mode():
        full = model(prompt).logits
        prefix = model(prompt[:, :2], use_cache=True)
        incremental = model(
            prompt[:, 2:],
            past_key_values=prefix.past_key_values,
            use_cache=True,
        ).logits
    assert torch.allclose(full[:, 2:], incremental, atol=1e-6, rtol=1e-6)


def test_seed_and_parameter_hash_are_deterministic() -> None:
    config = TinyDecoderConfig(vocab_size=16, hidden_size=8, num_heads=2, num_layers=1)
    first = TinyDecoder(config, seed=11)
    second = TinyDecoder(config, seed=11)
    third = TinyDecoder(config, seed=12)
    assert first.parameter_hash() == second.parameter_hash()
    assert first.parameter_hash() != third.parameter_hash()


def test_greedy_generate_respects_token_limit() -> None:
    model = TinyDecoder(
        TinyDecoderConfig(vocab_size=16, hidden_size=8, num_heads=2, num_layers=1),
        seed=3,
    )
    prompt = torch.tensor([[1, 2, 3]], dtype=torch.long)
    generated = model.greedy_generate(prompt, max_new_tokens=2)
    assert generated.shape == (1, 5)
    assert torch.equal(generated[:, :3], prompt)


def test_greedy_generate_slides_fixed_context_window() -> None:
    model = TinyDecoder(
        TinyDecoderConfig(
            vocab_size=16,
            hidden_size=8,
            num_heads=2,
            num_layers=1,
            max_seq_len=8,
        ),
        seed=5,
    )
    prompt = torch.tensor([[1, 2, 3, 4, 5, 6, 7, 8]], dtype=torch.long)
    generated = model.greedy_generate(prompt, max_new_tokens=2, context_window=8)
    assert generated.shape == (1, 10)
    assert torch.equal(generated[:, :8], prompt)

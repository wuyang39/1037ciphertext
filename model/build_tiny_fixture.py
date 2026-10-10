"""Generate the deterministic Tiny Decoder float-reference fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from model.tiny_decoder import TinyDecoder, TinyDecoderConfig


def build_fixture(output: Path) -> None:
    config = TinyDecoderConfig(
        vocab_size=32,
        hidden_size=8,
        num_layers=2,
        num_heads=2,
        intermediate_size=16,
        max_seq_len=16,
    )
    seed = 7
    model = TinyDecoder(config, seed=seed).eval()
    prompts = [
        {
            "prompt_id": f"tiny-{index:02d}",
            "input_ids": [
                ((index + 1) * 3 + token * 5) % config.vocab_size
                for token in range(2 + index % 7)
            ],
        }
        for index in range(20)
    ]
    for prompt in prompts:
        input_ids = torch.tensor([prompt["input_ids"]], dtype=torch.long)
        with torch.inference_mode():
            logits = model(input_ids).logits[0]
        prompt["logits"] = [
            [round(float(value), 6) for value in row] for row in logits
        ]
        prompt["argmax"] = [
            int(value) for value in torch.argmax(logits, dim=-1).tolist()
        ]

    document = {
        "fixture_version": "tiny-float-v1",
        "seed": seed,
        "config": config.__dict__,
        "parameter_hash": model.parameter_hash(),
        "prompts": prompts,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    output.write_bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/fixtures/tiny_float_reference.json"),
    )
    args = parser.parse_args()
    build_fixture(args.output)


if __name__ == "__main__":
    main()

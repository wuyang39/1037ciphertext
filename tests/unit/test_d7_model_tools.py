from __future__ import annotations

import json
import tempfile
from pathlib import Path

import numpy as np
import pytest
import torch

from model.export import (
    ModelExportError,
    export_model,
    load_model_bundle,
    tensor_from_bundle,
    write_model_bundle,
)
from model.graph import convert_tiny_decoder_graph
from model.quantization import build_precision_plan, quantize_tensor
from model.share_import import (
    ShareImportError,
    import_model_share,
    reconstruct_model_payload,
    split_model_payload,
)
from model.tiny_decoder import TinyDecoder, TinyDecoderConfig


def make_model() -> TinyDecoder:
    return TinyDecoder(
        TinyDecoderConfig(
            vocab_size=8,
            hidden_size=4,
            num_layers=1,
            num_heads=2,
            intermediate_size=8,
            max_seq_len=8,
        ),
        seed=19,
    )


def test_model_export_is_deterministic_and_manifest_verified() -> None:
    first = export_model(make_model(), model_version="tiny-v1")
    second = export_model(make_model(), model_version="tiny-v1")
    assert first.model_hash == second.model_hash
    assert first.payload == second.payload
    with tempfile.TemporaryDirectory() as directory:
        path = write_model_bundle(first, Path(directory))
        loaded = load_model_bundle(path)
        assert loaded.model_hash == first.model_hash
        values = tensor_from_bundle(loaded, "token_embedding.weight")
        assert values.shape == (8, 4)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["model_hash"] = "00" * 32
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(ModelExportError, match="hash"):
            load_model_bundle(path)


def test_dyadic_quantization_and_graph_freeze() -> None:
    tensor = quantize_tensor(
        "weight",
        np.array([[-1.25, 0.5], [3.0, -0.125]]),
        fractional_bits=8,
    )
    assert tensor.values == (-320, 128, 768, -32)
    restored = tensor.dequantize()
    assert np.allclose(restored, [[-1.25, 0.5], [3.0, -0.125]])
    plan = build_precision_plan({"weight": tensor}, plan_id="tiny-plan")
    assert plan["scales"]["weight"] == 8

    first = convert_tiny_decoder_graph(
        num_layers=2,
        hidden_size=8,
        num_heads=2,
        intermediate_size=16,
    )
    second = convert_tiny_decoder_graph(
        num_layers=2,
        hidden_size=8,
        num_heads=2,
        intermediate_size=16,
    )
    assert first.digest() == second.digest()
    assert first.nodes[-1].op == "secure_argmax"


def test_model_share_split_import_and_epoch_rejection() -> None:
    payload = b"quantized-model-payload"
    shares = split_model_payload(
        payload,
        model_hash="aa" * 32,
        share_epoch=7,
        seed=20261009,
    )
    assert reconstruct_model_payload(shares) == payload
    with pytest.raises(ShareImportError, match="epoch"):
        import_model_share(
            shares[0],
            expected_model_hash="aa" * 32,
            expected_share_epoch=8,
            expected_role="P0",
            attestation_release_id="release-v1",
            allowed_release_ids={"release-v1"},
        )
    with pytest.raises(ShareImportError, match="role"):
        import_model_share(
            shares[0],
            expected_model_hash="aa" * 32,
            expected_share_epoch=7,
            expected_role="P1",
            attestation_release_id="release-v1",
            allowed_release_ids={"release-v1"},
        )

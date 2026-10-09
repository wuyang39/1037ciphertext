from __future__ import annotations

import pytest

from contracts import canonical_hash
from crypto import SM2KeyPair
from model.manifests import (
    ModelManifest,
    PrecisionPlan,
    sign_manifest,
    verify_manifest_signature,
)


def test_manifest_validation_and_canonical_hash_are_order_independent() -> None:
    first = {
        "model_hash": "01" * 32,
        "tokenizer_hash": "02" * 32,
        "precision_plan_hash": "03" * 32,
        "model_version": "tiny-v1",
        "operator_version": "rss-v1",
    }
    reordered = dict(reversed(list(first.items())))
    assert canonical_hash(first) == canonical_hash(reordered)
    assert ModelManifest.from_dict(first).digest() == canonical_hash(first)


def test_manifest_rejects_missing_or_malformed_fields() -> None:
    with pytest.raises(ValueError, match="invalid model_manifest"):
        ModelManifest.from_dict(
            {
                "model_hash": "not-a-hash",
                "tokenizer_hash": "02" * 32,
                "precision_plan_hash": "03" * 32,
                "model_version": "tiny-v1",
                "operator_version": "rss-v1",
            }
        )


def test_manifest_sm2_signature_round_trip() -> None:
    manifest = {
        "plan_id": "tiny-plan-v1",
        "ring": "Z_2_64",
        "tensor_layout": "row_major",
        "scales": {"linear": 12, "softmax": 16},
        "approximations": {"gelu": "piecewise-v1"},
        "error_thresholds": {"max_abs_error": 0.01},
    }
    PrecisionPlan.from_dict(manifest)
    key_pair = SM2KeyPair.generate()
    signature = sign_manifest(key_pair, manifest, random_hex="02" * 32)
    assert verify_manifest_signature(manifest, signature, key_pair.public_key)
    assert not verify_manifest_signature(
        {**manifest, "plan_id": "tiny-plan-v2"},
        signature,
        key_pair.public_key,
    )

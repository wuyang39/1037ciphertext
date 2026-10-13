from __future__ import annotations

import numpy as np
import pytest

from tee.enclave.d5_node import D5NodeConfig, _error_stats, _verdict
from tee.enclave.node_common import NodeError


def _document() -> dict:
    return {
        "config_version": "a122-d5-node-v1",
        "run_id": "d5-test",
        "role": "P0",
        "partition_id": "a122-d5-d5-test",
        "endpoints": [
            {"role": "P0", "host": "10.0.0.1", "port": 47100},
            {"role": "P1", "host": "10.0.0.2", "port": 47101},
            {"role": "P2", "host": "10.0.0.3", "port": 47102},
        ],
        "identity": {
            "role": "P0",
            "certificate": "/w/pki/P0.pem",
            "private_key": "/w/pki/P0-key.pem",
            "ca_bundle": "/w/pki/ca.pem",
        },
        "peer_certificates": {"P1": "/w/pki/P1.pem", "P2": "/w/pki/P2.pem"},
        "share_channel": {"host": "10.0.0.1", "port": 47200},
        "peer_share_channels": {
            "P1": {"host": "10.0.0.2", "port": 47201},
            "P2": {"host": "10.0.0.3", "port": 47202},
        },
        "out_dir": "/w/out/P0",
        "block": {"sequence": 8, "hidden_size": 8, "num_heads": 2},
        "seed": 20261013,
    }


def test_node_config_builds_a_fail_closed_policy() -> None:
    config = D5NodeConfig.from_document(_document())
    assert config.role == "P0"
    assert config.peer_roles == ("P1", "P2")
    assert config.block_config.num_heads == 2
    policy = config.policy()
    assert policy.min_version == "TLS1.3"
    assert policy.require_client_certificate is True
    assert policy.rank == 0
    assert policy.peer_sans() == ("spiffe://a122/P1", "spiffe://a122/P2")


def test_node_config_rejects_a_disabled_tls_context() -> None:
    document = _document()
    document["enable_ssl"] = False
    config = D5NodeConfig.from_document(document)
    with pytest.raises(Exception):
        config.policy()


def test_node_config_reports_a_malformed_document() -> None:
    with pytest.raises(NodeError):
        D5NodeConfig.from_document({"run_id": "x"})


def test_error_stats_flags_overflow_and_shape_mismatch() -> None:
    stats = _error_stats(
        np.array([1.0, 2.0]), np.array([1.0, 2.0]), atol=1e-3, rtol=1e-3
    )
    assert stats["max_abs_error"] == 0.0
    assert stats["max_scaled_error"] == 0.0
    assert stats["overflow_count"] == 0
    mismatch = _error_stats(np.array([1.0]), np.array([1.0, 2.0]), atol=1e-3)
    assert mismatch["shape_mismatch"] is True
    saturated = _error_stats(np.array([1e15]), np.array([1e15]), atol=1e-3)
    assert saturated["overflow_count"] == 1
    # A relative error against a zero reference stays finite thanks to the
    # absolute floor, instead of dividing by zero.
    zero = _error_stats(np.array([0.0]), np.array([0.0]), atol=1e-3, rtol=1e-2)
    assert zero["relative_error"] == 0.0


def test_verdict_passes_matching_argmax_and_fails_mismatched_tokens() -> None:
    entry = _verdict(
        "argmax",
        {"index": np.array([3.0])},
        {"index": [3.0]},
        {"logits": np.zeros(8)},
        case="unique",
    )
    assert entry["verdict"] == "pass"
    assert entry["argmax_match"] is True

    block = _verdict(
        "block",
        {
            "hidden": np.zeros((2, 2)),
            "logits": np.zeros((2, 4)),
            "token": np.array([0.0]),
        },
        {
            "hidden": np.zeros((2, 2)),
            "logits": np.zeros((2, 4)),
            "token": np.array([2.0]),
        },
        {},
        case="random-00",
    )
    assert block["verdict"] == "fail"
    assert block["failed_outputs"] == ["token"]

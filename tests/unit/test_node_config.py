from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from infra.validate_node_config import (
    NodeConfigError,
    load_node_config,
    role_san,
    validate_node_config,
)


EXAMPLE_PATH = Path(__file__).resolve().parents[2] / "configs" / "node.example.json"


def _example() -> dict:
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def test_shipped_example_config_is_valid() -> None:
    result = validate_node_config(_example())
    assert result["valid"] is True
    assert result["node_role"] == "P0"
    assert result["listen_port"] == 47100


def test_each_role_validates_with_its_frozen_port() -> None:
    expected = {"P0": 47100, "P1": 47101, "P2": 47102}
    for role, port in expected.items():
        document = _example()
        document["node_role"] = role
        document["listen"]["port"] = port
        document["peers"] = [
            {
                "role": other,
                "address": f"192.0.2.1{index}",
                "port": expected[other],
                "san": role_san(other),
            }
            for index, other in enumerate(
                candidate for candidate in ("P0", "P1", "P2") if candidate != role
            )
        ]
        document["tls"]["role_san_allowlist"] = [
            peer["san"] for peer in document["peers"]
        ]
        assert validate_node_config(document)["node_role"] == role


def test_wrong_listen_port_is_rejected() -> None:
    document = _example()
    document["listen"]["port"] = 12345
    with pytest.raises(NodeConfigError):
        validate_node_config(document)


def test_peer_port_must_match_the_frozen_mapping() -> None:
    document = _example()
    document["peers"][0]["port"] = 47102
    with pytest.raises(NodeConfigError):
        validate_node_config(document)


def test_peer_san_must_match_the_peer_role() -> None:
    document = _example()
    document["peers"][0]["san"] = role_san("P2")
    with pytest.raises(NodeConfigError):
        validate_node_config(document)


def test_a_node_may_not_allow_its_own_san() -> None:
    document = _example()
    document["tls"]["role_san_allowlist"] = [role_san("P0"), role_san("P1")]
    with pytest.raises(NodeConfigError):
        validate_node_config(document)


def test_missing_peer_is_rejected() -> None:
    document = _example()
    document["peers"] = document["peers"][:1]
    with pytest.raises(ValueError):
        validate_node_config(document)


def test_debug_enclave_is_rejected() -> None:
    document = _example()
    document["sgx"]["debug"] = True
    with pytest.raises(ValueError):
        validate_node_config(document)


def test_tls_baseline_cannot_be_relaxed() -> None:
    document = _example()
    document["tls"]["min_version"] = "TLS1.2"
    with pytest.raises(ValueError):
        validate_node_config(document)


def test_plain_http_kas_endpoint_is_rejected() -> None:
    document = _example()
    document["kas"]["base_url"] = "http://kas.a122.internal:8443"
    with pytest.raises(ValueError):
        validate_node_config(document)


def test_unknown_fields_are_rejected() -> None:
    document = _example()
    document["extra"] = True
    with pytest.raises(ValueError):
        validate_node_config(document)


def test_load_node_config_rejects_non_json(tmp_path: Path) -> None:
    bad = tmp_path / "node.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(NodeConfigError):
        load_node_config(bad)


def test_evidence_hash_is_stable_across_reloads() -> None:
    first = validate_node_config(_example())
    second = validate_node_config(copy.deepcopy(_example()))
    assert first["sha256"] == second["sha256"]

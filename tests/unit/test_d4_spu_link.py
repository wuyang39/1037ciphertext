from __future__ import annotations

import numpy as np
import pytest

from infra.d4_pki import issue_node_credentials, provision_cluster
from infra.d4_workspace import ROLES, build_workspace, loopback_cluster
from mpc.spu_backend.spu_link import (
    NodeIdentity,
    SpuBackendError,
    SpuEndpoint,
    SpuLinkPolicy,
    certificate_role,
    decode_share,
    encode_share,
    verify_local_identity,
    verify_peer_certificates,
)
from mpc.spu_backend.spu_ops import (
    SPU_OPERATORS,
    build_program,
    compare_with_reference,
    reference_outputs,
)


def _policy(role: str = "P0", **overrides) -> SpuLinkPolicy:
    endpoints = tuple(
        SpuEndpoint(role=name, host="127.0.0.1", port=47100 + index)
        for index, name in enumerate(ROLES)
    )
    return SpuLinkPolicy(role=role, endpoints=endpoints, **overrides)


def test_program_contains_the_six_operators() -> None:
    program = build_program(batch=8, rows=4, cols=4)
    assert "mhlo.add" in program
    assert "mhlo.multiply" in program
    assert "mhlo.dot_general" in program
    assert "mhlo.floor" in program
    assert "mhlo.compare" in program
    assert "mhlo.divide" in program
    assert "tensor<8x4x4xf64>" in program
    # The batched contraction must keep the batching and contracting axes
    # disjoint: dim 0 batches, the last lhs axis contracts with the rhs rows.
    assert (
        "#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        "lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>"
        in program
    )
    with pytest.raises(ValueError):
        build_program(batch=0, rows=4, cols=4)


def test_reference_outputs_match_numpy() -> None:
    rng = np.random.default_rng(3)
    x = np.round(rng.uniform(-2, 2, size=(3, 2, 2)) * 4) / 4
    y = np.round(rng.uniform(-2, 2, size=(3, 2, 2)) * 4) / 4
    x = np.where(x == 0.0, 0.25, x)
    expected = reference_outputs(x, y)
    assert set(expected) == set(SPU_OPERATORS)
    assert np.allclose(expected["matmul"], x @ y)
    assert np.array_equal(
        expected["compare"].astype(bool), (x < y)
    )


def test_compare_with_reference_flags_a_divergent_operator() -> None:
    x = np.array([[[1.5, -2.0], [0.5, 3.0]]])
    y = np.array([[[0.5, 2.0], [-1.0, 1.0]]])
    actual = reference_outputs(x, y)
    assert compare_with_reference(actual, x, y) == []
    actual["mul"] = actual["mul"] + 1.0
    assert compare_with_reference(actual, x, y) == ["mul"]
    del actual["add"]
    assert "add" in compare_with_reference(actual, x, y)


def test_link_policy_refuses_every_degradation() -> None:
    with pytest.raises(SpuBackendError):
        _policy(enable_ssl=False)
    with pytest.raises(SpuBackendError):
        _policy(require_client_certificate=False)
    with pytest.raises(SpuBackendError):
        _policy(allow_brpc_builtin_services=True)
    with pytest.raises(SpuBackendError):
        _policy(min_version="TLS1.2")
    with pytest.raises(SpuBackendError):
        _policy(server_verify_depth=-1)
    with pytest.raises(SpuBackendError):
        _policy(client_verify_depth=-1)
    with pytest.raises(SpuBackendError):
        _policy(role="P3")
    shuffled = (
        SpuEndpoint(role="P1", host="127.0.0.1", port=47101),
        SpuEndpoint(role="P0", host="127.0.0.1", port=47100),
        SpuEndpoint(role="P2", host="127.0.0.1", port=47102),
    )
    with pytest.raises(SpuBackendError):
        SpuLinkPolicy(role="P0", endpoints=shuffled)


def test_policy_reports_rank_and_peer_sans() -> None:
    policy = _policy(role="P2")
    assert policy.rank == 2
    assert policy.peer_roles == ("P0", "P1")
    assert policy.peer_sans() == ("spiffe://a122/P0", "spiffe://a122/P1")
    assert policy.to_dict()["enable_ssl"] is True


def test_certificate_gate_accepts_kas_leaves_and_rejects_mutations(tmp_path) -> None:
    credentials = provision_cluster(tmp_path / "pki", roles=ROLES)
    ca_bundle = tmp_path / "pki" / "ca" / "ca-cert.pem"
    policy = _policy()
    peer_certificates = {
        "P1": credentials["P1"].certificate_path,
        "P2": credentials["P2"].certificate_path,
    }
    fingerprints = verify_peer_certificates(
        policy, peer_certificates, ca_bundle_path=ca_bundle
    )
    assert set(fingerprints) == {"P1", "P2"}
    assert all(len(value) == 64 for value in fingerprints.values())

    from cryptography import x509

    leaf = x509.load_pem_x509_certificate(
        credentials["P1"].certificate_path.read_bytes()
    )
    assert certificate_role(leaf) == "P1"

    missing = dict(peer_certificates)
    missing.pop("P2")
    with pytest.raises(SpuBackendError, match="no certificate provisioned"):
        verify_peer_certificates(policy, missing, ca_bundle_path=ca_bundle)


def test_certificate_gate_rejects_a_foreign_ca_and_a_wrong_san(tmp_path) -> None:
    credentials = provision_cluster(tmp_path / "pki", roles=ROLES)
    foreign_key = tmp_path / "pki" / "foreign-ca" / "ca-key.pem"
    foreign_certificate = tmp_path / "pki" / "foreign-ca" / "ca-cert.pem"
    from infra.d4_pki import generate_authority

    foreign_key, foreign_certificate = generate_authority(
        tmp_path / "pki" / "foreign-ca"
    )
    foreign_leaf = issue_node_credentials(
        ca_key_path=foreign_key,
        ca_certificate_path=foreign_certificate,
        role="P2",
        out_dir=tmp_path / "foreign-leaf",
    )
    ca_bundle = tmp_path / "pki" / "ca" / "ca-cert.pem"
    policy = _policy()
    with pytest.raises(SpuBackendError, match="was not signed by the KAS CA"):
        verify_peer_certificates(
            policy,
            {
                "P1": credentials["P1"].certificate_path,
                "P2": foreign_leaf.certificate_path,
            },
            ca_bundle_path=ca_bundle,
        )

    wrong_san = issue_node_credentials(
        ca_key_path=tmp_path / "pki" / "ca" / "ca-key.pem",
        ca_certificate_path=ca_bundle,
        role="P2",
        san_role="P1",
        out_dir=tmp_path / "wrong-san",
    )
    with pytest.raises(SpuBackendError, match="SAN does not match its role"):
        verify_peer_certificates(
            policy,
            {
                "P1": credentials["P1"].certificate_path,
                "P2": wrong_san.certificate_path,
            },
            ca_bundle_path=ca_bundle,
        )


def test_local_identity_must_match_the_configured_role(tmp_path) -> None:
    credentials = provision_cluster(tmp_path / "pki", roles=ROLES)
    identity = NodeIdentity(
        role="P0",
        certificate_path=credentials["P0"].certificate_path,
        private_key_path=credentials["P0"].private_key_path,
        ca_bundle_path=credentials["P0"].ca_bundle_path,
    )
    assert verify_local_identity(_policy(), identity)["role"] == "P0"
    swapped = NodeIdentity(
        role="P0",
        certificate_path=credentials["P1"].certificate_path,
        private_key_path=credentials["P1"].private_key_path,
        ca_bundle_path=credentials["P1"].ca_bundle_path,
    )
    with pytest.raises(SpuBackendError, match="SAN does not match"):
        verify_local_identity(_policy(), swapped)


class _FakeShare:
    def __init__(self, meta: bytes, chunks: list[bytes]) -> None:
        self.meta = meta
        self.share_chunks = chunks


class _FakeLibspu:
    class Share:  # noqa: D106 - mirrors the pybind struct
        def __init__(self) -> None:
            self.meta = b""
            self.share_chunks: list[bytes] = []


def test_share_encoding_round_trips() -> None:
    share = _FakeShare(b"meta", [b"a", b"b"])
    encoded = encode_share(share)
    decoded = decode_share(_FakeLibspu, encoded)
    assert decoded.meta == b"meta"
    assert decoded.share_chunks == [b"a", b"b"]
    with pytest.raises(SpuBackendError, match="malformed"):
        decode_share(_FakeLibspu, "{not json")

from __future__ import annotations

import datetime as dt
import json
import struct
import urllib.error
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crypto.sm2 import SM2KeyPair
from infra.sgx_quote import QUOTE_HEADER_BYTES, REPORT_BODY_BYTES, parse_quote
from kas.ca import RELEASE_EXTENSION_OID, CertificateAuthority
from kas.errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
    PolicyRejected,
)
from kas.models import AttestRequest, ChallengeRequest
from kas.policy import PolicyRegistry, ReleaseManifest, VerifiedQuote
from kas.service import KASService
from tee.enclave.attestation import (
    AttestationConfig,
    AttestationError,
    assert_peer_certificate,
    await_peer_certificates,
    bootstrap_node_identity,
    read_platform_quote,
)

NOW = dt.datetime(2026, 10, 14, 8, 0, tzinfo=dt.timezone.utc)
RELEASE_ID = "a122-attest-v1"
MRENCLAVE = "11" * 32
MRSIGNER = "22" * 32
ISVSVN = 18


def make_release() -> ReleaseManifest:
    return ReleaseManifest.from_dict(
        {
            "release_id": RELEASE_ID,
            "mrenclave": MRENCLAVE,
            "mrsigner": MRSIGNER,
            "min_isvsvn": 10,
            "debug_allowed": False,
            "spu_build_hash": "33" * 32,
            "model_version": "gpt2-1l-cand1028-v1",
            "model_manifest_hash": "44" * 32,
            "precision_plan_hash": "55" * 32,
            "expires_at": "2027-01-01T00:00:00Z",
        }
    )


def make_ca(common_name: str = "A1-22 Test KAS CA") -> CertificateAuthority:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return CertificateAuthority(private_key, certificate)


class ParsingQuoteVerifier:
    """The KAS-side verifier, reading the claims out of a real quote blob."""

    def verify(self, quote: bytes) -> VerifiedQuote:
        claims = parse_quote(quote)
        if claims.debug:
            raise AttestationRejected("debug Quote is forbidden")
        return VerifiedQuote(
            mrenclave=claims.mr_enclave.hex(),
            mrsigner=claims.mr_signer.hex(),
            isvsvn=claims.isv_svn,
            debug=claims.debug,
            report_data=claims.report_data,
        )


def build_quote(
    *,
    report_data: bytes,
    mrenclave: bytes = bytes.fromhex(MRENCLAVE),
    mrsigner: bytes = bytes.fromhex(MRSIGNER),
    attributes_flags: int = 0x04,
    isv_svn: int = ISVSVN,
) -> bytes:
    header = struct.pack("<HHIHH", 3, 2, 0, 12, 17) + bytes(36)
    body = bytearray(REPORT_BODY_BYTES)
    struct.pack_into("<QQ", body, 48, attributes_flags, 0)
    body[64:96] = mrenclave
    body[128:160] = mrsigner
    struct.pack_into("<H", body, 258, isv_svn)
    body[320:384] = report_data
    trailer = struct.pack("<I", 16) + bytes(16)
    assert len(header) == QUOTE_HEADER_BYTES
    return header + bytes(body) + trailer


def make_service(
    *, verifier: Any | None = None, authority: CertificateAuthority | None = None
) -> KASService:
    return KASService(
        quote_verifier=verifier or ParsingQuoteVerifier(),
        policy_registry=PolicyRegistry([make_release()]),
        certificate_authority=authority or make_ca(),
        ticket_signing_key=SM2KeyPair.generate(),
        # The KAS issues short-lived leaves, so the test clock has to be the
        # real one for the peer-validity window to be open.
        clock=lambda: dt.datetime.now(dt.timezone.utc),
    )


def kas_post(service: KASService):
    """A stand-in for the node's HTTP client that keeps the real KAS logic."""

    def post(
        base_url: str, path: str, payload: dict[str, Any], *, timeout: float
    ) -> tuple[int, dict[str, Any]]:
        del base_url, timeout
        try:
            if path == "/v1/challenge":
                response = service.issue_challenge(ChallengeRequest(**payload))
                return 201, json.loads(response.model_dump_json())
            if path == "/v1/attest":
                response = service.attest(AttestRequest(**payload))
                return 200, json.loads(response.model_dump_json())
        except (AttestationRejected, PolicyRejected) as exc:
            return 403, {"detail": str(exc)}
        except ChallengeNotFound as exc:
            return 404, {"detail": str(exc)}
        except ChallengeExpired as exc:
            return 410, {"detail": str(exc)}
        raise AssertionError(f"unexpected KAS path {path}")

    return post


def platform_quote_source(**overrides: Any):
    """A quote source whose blob carries whatever REPORTDATA it was handed."""

    def source(report_data: bytes) -> bytes:
        return build_quote(report_data=report_data, **overrides)

    return source


def cas_certificate_pem(service: KASService) -> str:
    return service._ca.certificate_pem


def config(tmp_path: Path, **overrides: Any) -> AttestationConfig:
    values: dict[str, Any] = {
        "kas_url": "http://127.0.0.1:18443",
        "release_id": RELEASE_ID,
        "shared_dir": tmp_path / "shared",
        "private_dir": tmp_path / "private",
        "peers_timeout_seconds": 2.0,
    }
    values.update(overrides)
    return AttestationConfig(**values)


def test_a_real_kas_issues_the_identity_from_the_nodes_own_quote(
    tmp_path: Path,
) -> None:
    service = make_service()
    attestation = config(tmp_path)

    attested = bootstrap_node_identity(
        attestation,
        role="P1",
        quote_source=platform_quote_source(),
        post=kas_post(service),
    )

    assert attested.identity.role == "P1"
    assert attested.identity.private_key_path.is_file()
    assert attested.identity.certificate_path.is_file()
    assert attested.mrenclave == MRENCLAVE
    assert attested.mrsigner == MRSIGNER
    assert attested.lease_id
    assert attested.quote_bytes > 0
    # The published copy is what the driver collects; the private key stays in
    # the enclave-private directory.
    published = attestation.shared_dir / "P1-cert.pem"
    assert published.is_file()
    assert attestation.shared_dir not in attested.identity.private_key_path.parents

    leaf = x509.load_pem_x509_certificate(published.read_bytes())
    sans = (
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        .value.get_values_for_type(x509.UniformResourceIdentifier)
    )
    assert list(sans) == ["spiffe://a122/P1"]
    release = leaf.extensions.get_extension_for_oid(RELEASE_EXTENSION_OID).value
    assert bytes(release.value) == RELEASE_ID.encode("utf-8")
    evidence = attested.to_evidence()
    assert evidence["mode"] == "kas-attested"
    assert evidence["lease_id"] == attested.lease_id


def test_a_quote_that_does_not_bind_the_nodes_own_key_is_refused(
    tmp_path: Path,
) -> None:
    service = make_service()
    with pytest.raises(AttestationError, match="does not bind the node key"):
        bootstrap_node_identity(
            config(tmp_path),
            role="P0",
            quote_source=lambda _report_data: build_quote(report_data=b"\x07" * 64),
            post=kas_post(service),
        )


def test_the_node_refuses_when_the_platform_quote_is_absent(tmp_path: Path) -> None:
    attestation = config(
        tmp_path,
        report_data_path=tmp_path / "user_report_data",
        quote_path=tmp_path / "no-quote",
    )
    with pytest.raises(AttestationError, match="platform quote is unavailable"):
        bootstrap_node_identity(attestation, role="P0", post=kas_post(make_service()))


def test_the_node_refuses_when_it_cannot_write_report_data(tmp_path: Path) -> None:
    attestation = config(
        tmp_path,
        report_data_path=tmp_path / "missing-dir" / "user_report_data",
    )
    with pytest.raises(AttestationError, match="REPORTDATA file is unavailable"):
        bootstrap_node_identity(attestation, role="P0", post=kas_post(make_service()))


def test_a_release_the_policy_does_not_know_is_refused(tmp_path: Path) -> None:
    service = make_service()
    with pytest.raises(AttestationError, match="release is not registered"):
        bootstrap_node_identity(
            config(tmp_path, release_id="a122-unknown-v1"),
            role="P0",
            quote_source=platform_quote_source(),
            post=kas_post(service),
        )


def test_a_quote_below_the_release_isvsvn_is_refused(tmp_path: Path) -> None:
    service = make_service()
    with pytest.raises(AttestationError, match="ISVSVN is below"):
        bootstrap_node_identity(
            config(tmp_path),
            role="P0",
            quote_source=platform_quote_source(isv_svn=4),
            post=kas_post(service),
        )


def test_a_debug_quote_is_refused(tmp_path: Path) -> None:
    service = make_service()
    with pytest.raises(AttestationError, match="debug Quote is forbidden"):
        bootstrap_node_identity(
            config(tmp_path),
            role="P0",
            quote_source=platform_quote_source(attributes_flags=0x06),
            post=kas_post(service),
        )


def test_an_unreachable_kas_is_a_refusal_not_a_retry(tmp_path: Path) -> None:
    def unreachable(*_args: Any, **_kwargs: Any):
        raise urllib.error.URLError("connection refused")

    with pytest.raises(AttestationError, match="KAS is unreachable"):
        bootstrap_node_identity(
            config(tmp_path),
            role="P0",
            quote_source=platform_quote_source(),
            post=unreachable,
        )


def test_read_platform_quote_round_trips_the_report_data(tmp_path: Path) -> None:
    report_data = bytes(range(64))
    quote_path = tmp_path / "quote.bin"
    quote_path.write_bytes(build_quote(report_data=report_data))
    report_data_path = tmp_path / "user_report_data"
    quote = read_platform_quote(
        report_data, report_data_path=report_data_path, quote_path=quote_path
    )
    assert report_data_path.read_bytes() == report_data
    assert parse_quote(quote).report_data == report_data


def test_the_peer_map_pins_one_kas_issued_leaf_per_role(tmp_path: Path) -> None:
    service = make_service()
    attestation = config(tmp_path)
    post = kas_post(service)
    for role in ("P0", "P1", "P2"):
        bootstrap_node_identity(
            attestation,
            role=role,
            quote_source=platform_quote_source(),
            post=post,
        )
    peers = {
        role: (attestation.shared_dir / f"{role}-cert.pem").read_text(encoding="ascii")
        for role in ("P0", "P1", "P2")
    }
    (attestation.shared_dir / "peers.json").write_text(
        json.dumps(peers), encoding="utf-8"
    )

    pinned = await_peer_certificates(
        attestation,
        peer_roles=("P1", "P2"),
        pin_dir=attestation.private_dir / "peers",
        ca_bundle_pem=cas_certificate_pem(service),
        poll_seconds=0.01,
    )
    assert set(pinned) == {"P1", "P2"}
    for path in pinned.values():
        assert path.is_file()


def test_a_peer_leaf_from_another_ca_or_role_is_refused(tmp_path: Path) -> None:
    service = make_service()
    foreign = make_service(authority=make_ca("A1-22 Foreign CA"))
    attestation = config(tmp_path / "foreign")
    bootstrap_node_identity(
        attestation,
        role="P1",
        quote_source=platform_quote_source(),
        post=kas_post(foreign),
    )
    foreign_leaf = (attestation.shared_dir / "P1-cert.pem").read_text(encoding="ascii")
    with pytest.raises(AttestationError, match="not from the KAS CA"):
        assert_peer_certificate(
            foreign_leaf,
            peer_role="P1",
            release_id=RELEASE_ID,
            ca_bundle_pem=cas_certificate_pem(service),
        )

    mine = config(tmp_path / "mine")
    bootstrap_node_identity(
        mine,
        role="P1",
        quote_source=platform_quote_source(),
        post=kas_post(service),
    )
    leaf = (mine.shared_dir / "P1-cert.pem").read_text(encoding="ascii")
    with pytest.raises(AttestationError, match="SAN does not match"):
        assert_peer_certificate(
            leaf,
            peer_role="P2",
            release_id=RELEASE_ID,
            ca_bundle_pem=cas_certificate_pem(service),
        )
    with pytest.raises(AttestationError, match="bound to another release"):
        assert_peer_certificate(
            leaf,
            peer_role="P1",
            release_id="a122-other-v1",
            ca_bundle_pem=cas_certificate_pem(service),
        )


def test_a_peer_map_that_never_arrives_stops_the_node(tmp_path: Path) -> None:
    attestation = config(tmp_path, peers_timeout_seconds=0.2)
    with pytest.raises(AttestationError, match="did not list every peer role"):
        await_peer_certificates(
            attestation,
            peer_roles=("P1", "P2"),
            pin_dir=attestation.private_dir / "peers",
            ca_bundle_pem=make_ca().certificate_pem,
            poll_seconds=0.01,
        )


def test_the_attestation_config_is_validated() -> None:
    with pytest.raises(AttestationError, match="must be http"):
        AttestationConfig.from_document(
            {
                "kas_url": "ftp://kas",
                "release_id": RELEASE_ID,
                "shared_dir": "/tmp/shared",
            }
        )
    with pytest.raises(AttestationError, match="too short"):
        AttestationConfig.from_document(
            {
                "kas_url": "http://kas:8443",
                "release_id": "x",
                "shared_dir": "/tmp/shared",
            }
        )
    with pytest.raises(AttestationError, match="timeouts must be positive"):
        AttestationConfig.from_document(
            {
                "kas_url": "http://kas:8443",
                "release_id": RELEASE_ID,
                "shared_dir": "/tmp/shared",
                "timeout_seconds": 0,
            }
        )
    with pytest.raises(AttestationError, match="missing 'shared_dir'"):
        AttestationConfig.from_document(
            {"kas_url": "http://kas:8443", "release_id": RELEASE_ID}
        )


def test_an_attested_node_never_reaches_the_link_without_a_lease(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The refusal has to happen before any SPU material is touched."""
    from tee.enclave import d6_node

    def refuse(*_args: Any, **_kwargs: Any):
        raise AttestationError("the KAS rejected the attestation (403): no lease")

    def no_link(*_args: Any, **_kwargs: Any):
        raise AssertionError("the node loaded libspu before it had a lease")

    monkeypatch.setattr(d6_node, "bootstrap_node_identity", refuse)
    monkeypatch.setattr(d6_node, "load_libspu", no_link)
    node = d6_node.D6NodeConfig(
        run_id="unit",
        role="P0",
        partition_id="a122-d4",
        endpoints=(
            d6_node.SpuEndpoint(role="P0", host="127.0.0.1", port=47000),
            d6_node.SpuEndpoint(role="P1", host="127.0.0.1", port=47001),
            d6_node.SpuEndpoint(role="P2", host="127.0.0.1", port=47002),
        ),
        identity=d6_node.NodeIdentity(
            role="P0",
            certificate_path=tmp_path / "cert.pem",
            private_key_path=tmp_path / "key.pem",
            ca_bundle_path=tmp_path / "ca.pem",
        ),
        peer_certificates={},
        share_host="127.0.0.1",
        share_port=47200,
        out_dir=tmp_path / "out",
        plan=_d6_plan(),
        model=_d6_model(),
        weights_path=tmp_path / "weights.json",
        sm2_private_key="ab" * 32,
        sm2_certificate={},
        kas_public_key="cd" * 64,
        client_authority_public_key="ef" * 64,
        session_dir=tmp_path / "session",
        seed=1,
        attestation=AttestationConfig(
            kas_url="http://127.0.0.1:18443",
            release_id=RELEASE_ID,
            shared_dir=tmp_path / "shared",
            private_dir=tmp_path / "private",
        ),
    )
    with pytest.raises(AttestationError, match="no lease"):
        d6_node.run_node(node, programs=None, payloads=None)


def _d6_model():
    from client.tokenizer import WordTokenizer
    from contracts.d6_session import ModelManifest
    from infra.d6_vectors import D6_GEOMETRY

    tokenizer = WordTokenizer()
    return ModelManifest(
        model_version="tiny-decoder-d6-v1",
        weight_seed=20261013,
        sequence=D6_GEOMETRY["sequence"],
        hidden_size=D6_GEOMETRY["hidden_size"],
        num_heads=D6_GEOMETRY["num_heads"],
        intermediate_size=D6_GEOMETRY["intermediate_size"],
        vocab_size=tokenizer.vocab_size,
        tokenizer_digest=tokenizer.vocabulary_digest,
        fractional_bits=D6_GEOMETRY["fractional_bits"],
    )


def _d6_plan():
    from contracts.d6_session import SessionPlan

    return SessionPlan.for_manifest(
        _d6_model(),
        release_id="a122-d4",
        share_epoch=1,
        max_new_tokens=3,
        length_bound=1 << 20,
    )

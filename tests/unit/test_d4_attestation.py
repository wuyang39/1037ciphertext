"""Driver-side tests for the attested D4 run.

The node half is covered by ``test_node_attestation``; this file covers what
the acceptance driver does around it: generate the KAS's own material on the
instance that runs it, pin a release to a measurement read out of a real
quote, collect the leaves the nodes published, and refuse a run whose nodes
did not end up on the identity the release registered.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from contracts import validate_contract
from infra.d4_three_hosts import (
    AttestationRequest,
    ThreeHostError,
    assert_attested_evidence,
    collect_node_certificates,
    precision_plan_hash,
    resolve_remote_path,
    stop_kas_command,
)
from infra.evidence import EvidenceError
from infra.kas_material import KasMaterialError, generate
from infra.node_attestation import (
    PEERS_FILE_NAME,
    EnclaveClaims,
    NodeAttestationError,
    assert_attested_run,
    assert_certificates_agree,
    attestation_block,
    bootstrap_report_data,
    certificate_is_for_role,
    collect_published_certificates,
    kas_start_command,
    peer_map_document,
    read_bootstrap_claims,
    release_policy_document,
    run_release_id,
    shared_attestation_dir,
    write_release_policy,
)
from infra.sgx_quote import QUOTE_HEADER_BYTES, REPORT_BODY_BYTES
from kas.ca import CertificateAuthority
from kas.models import AttestRequest, ChallengeRequest
from kas.policy import PolicyRegistry, VerifiedQuote
from kas.service import KASService
from kas.settings import KASSettings, build_service
from tee.enclave.attestation import (
    assert_peer_certificate,
    bootstrap_node_identity,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_ID = "a122-d4-attested-unit"
MRENCLAVE = "ab" * 32
MRSIGNER = "cd" * 32
ISVSVN = 12


def build_quote(
    *,
    report_data: bytes,
    mrenclave: str = MRENCLAVE,
    mrsigner: str = MRSIGNER,
    attributes_flags: int = 0x04,
    isv_svn: int = ISVSVN,
) -> bytes:
    header = struct.pack("<HHIHH", 3, 2, 0, 12, 17) + bytes(36)
    body = bytearray(REPORT_BODY_BYTES)
    struct.pack_into("<QQ", body, 48, attributes_flags, 0)
    body[64:96] = bytes.fromhex(mrenclave)
    body[128:160] = bytes.fromhex(mrsigner)
    struct.pack_into("<H", body, 258, isv_svn)
    body[320:384] = report_data
    trailer = struct.pack("<I", 16) + bytes(16)
    assert len(header) == QUOTE_HEADER_BYTES
    return header + bytes(body) + trailer


def write_verifier_script(path: Path) -> Path:
    """A stand-in for the DCAP adapter: it reports the quote it was handed."""
    body = "\n".join(
        [
            "import base64, json, sys",
            f"sys.path.insert(0, {str(REPO_ROOT)!r})",
            "from infra.sgx_quote import parse_quote",
            "argv = sys.argv",
            "quote = open(argv[argv.index('--quote') + 1], 'rb').read()",
            "claims = parse_quote(quote)",
            "print(json.dumps({",
            "    'mrenclave': claims.mr_enclave.hex(),",
            "    'mrsigner': claims.mr_signer.hex(),",
            "    'isvsvn': claims.isv_svn,",
            "    'debug': claims.debug,",
            "    'report_data_b64': base64.b64encode(",
            "        claims.report_data).decode(),",
            "}))",
            "",
        ]
    )
    script = path.with_suffix(".py")
    script.write_text(body, encoding="utf-8", newline="\n")
    if os.name == "nt":
        # Windows cannot run a shebang script directly, so the adapter the KAS
        # invokes is a one-line shim over the same code.
        shim = path.with_suffix(".cmd")
        shim.write_text(
            f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8"
        )
        return shim
    script.chmod(0o755)
    return script


def kas_environment(material: dict[str, Any], verifier: Path, policy: Path) -> dict[str, str]:
    return {
        "KAS_CA_KEY_PATH": str(material["ca_key_path"]),
        "KAS_CA_CERT_PATH": str(material["ca_cert_path"]),
        "KAS_RELEASE_POLICY_PATH": str(policy),
        "KAS_DCAP_VERIFY_BIN": str(verifier),
        "KAS_TICKET_SIGNING_KEY_PATH": str(material["ticket_signing_key_path"]),
        "KAS_STORAGE_KEY_MASTER_HEX": Path(
            material["storage_key_master_hex_path"]
        ).read_text(encoding="ascii").strip(),
    }


def kas_post(service: KASService):
    """A stand-in for the node's HTTP client that keeps the real KAS logic."""
    from kas.errors import (
        AttestationRejected,
        ChallengeExpired,
        ChallengeNotFound,
        PolicyRejected,
    )

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


def claims_from_quote(path: Path, **overrides: Any) -> EnclaveClaims:
    path.write_bytes(
        build_quote(report_data=bootstrap_report_data(), **overrides)
    )
    return read_bootstrap_claims(path)


def test_the_generated_material_builds_a_working_kas(tmp_path: Path) -> None:
    material = generate(tmp_path / "kas-material")
    # Private keys and the storage master have to be unreadable to anyone else,
    # and none of them may appear in the document the driver keeps.
    for name in ("ca_key_path", "ticket_signing_key_path", "storage_key_master_hex_path"):
        assert Path(material[name]).is_file()
        if os.name == "posix":
            assert Path(material[name]).stat().st_mode & 0o077 == 0
    for value in material.values():
        if isinstance(value, str):
            assert "PRIVATE KEY" not in value
    assert "storage_key_master_hex" not in material

    settings = KASSettings.from_env(
        {
            "KAS_CA_KEY_PATH": material["ca_key_path"],
            "KAS_CA_CERT_PATH": material["ca_cert_path"],
            "KAS_RELEASE_POLICY_PATH": str(tmp_path / "policy.json"),
            "KAS_DCAP_VERIFY_BIN": str(tmp_path / "verifier"),
            "KAS_TICKET_SIGNING_KEY_PATH": material["ticket_signing_key_path"],
            "KAS_STORAGE_KEY_MASTER_HEX": "00" * 32,
        }
    )
    assert settings.ca_key_path == Path(material["ca_key_path"])
    authority = CertificateAuthority.from_pem_files(
        Path(material["ca_key_path"]), Path(material["ca_cert_path"])
    )
    assert authority.certificate_pem.strip() == material["ca_certificate_pem"].strip()


def test_the_material_generator_refuses_to_reuse_a_directory(tmp_path: Path) -> None:
    directory = tmp_path / "kas-material"
    generate(directory)
    with pytest.raises(KasMaterialError, match="not empty"):
        generate(directory)


def test_a_release_is_pinned_to_the_measurement_the_quote_reports(
    tmp_path: Path,
) -> None:
    claims = claims_from_quote(tmp_path / "quote.bin")
    policy = release_policy_document(
        release_id=RELEASE_ID,
        claims=claims,
        spu_build_hash=claims.mrenclave,
        model_version="a122-d4-spu-grid",
        model_manifest_hash="11" * 32,
        precision_plan_hash="22" * 32,
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
    )
    # The release the KAS will register has to satisfy its own contract.
    validate_contract("release_manifest", policy["releases"][0])
    path = write_release_policy(tmp_path / "policy.json", policy)
    registry = PolicyRegistry.from_json_file(path)
    verified = VerifiedQuote(
        mrenclave=claims.mrenclave,
        mrsigner=claims.mrsigner,
        isvsvn=claims.isvsvn,
        debug=False,
        report_data=bytes(64),
    )
    release = registry.validate_quote(
        RELEASE_ID, verified, now=dt.datetime.now(dt.timezone.utc)
    )
    assert release.mrenclave == MRENCLAVE


def test_a_release_cannot_be_pinned_to_a_debug_quote(tmp_path: Path) -> None:
    claims = claims_from_quote(tmp_path / "quote.bin", attributes_flags=0x06)
    assert claims.debug is True
    with pytest.raises(NodeAttestationError, match="debug quote"):
        release_policy_document(
            release_id=RELEASE_ID,
            claims=claims,
            spu_build_hash=claims.mrenclave,
            model_version="a122-d4-spu-grid",
            model_manifest_hash="11" * 32,
            precision_plan_hash="22" * 32,
            expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
        )


def test_the_three_ranks_have_to_report_one_enclave(tmp_path: Path) -> None:
    agreed = {role: claims_from_quote(tmp_path / f"{role}.bin") for role in ("P0", "P1", "P2")}
    assert assert_certificates_agree(agreed).mrenclave == MRENCLAVE

    divergent = dict(agreed)
    divergent["P2"] = claims_from_quote(
        tmp_path / "other.bin", mrenclave="ef" * 32
    )
    with pytest.raises(NodeAttestationError, match="different measurements"):
        assert_certificates_agree(divergent)

    signed_elsewhere = dict(agreed)
    signed_elsewhere["P1"] = claims_from_quote(
        tmp_path / "signer.bin", mrsigner="ee" * 32
    )
    with pytest.raises(NodeAttestationError, match="different signers"):
        assert_certificates_agree(signed_elsewhere)


def test_the_release_id_and_shared_dir_are_safe_for_a_run_id() -> None:
    release_id = run_release_id("d4 attested/2026-10-14T21:00:00Z")
    assert release_id.startswith("a122-d4-attested-")
    assert release_id.isascii()
    assert all(character.isalnum() or character in "._-" for character in release_id)
    validate_contract(
        "release_manifest",
        {
            "release_id": release_id,
            "mrenclave": MRENCLAVE,
            "mrsigner": MRSIGNER,
            "min_isvsvn": ISVSVN,
            "debug_allowed": False,
            "spu_build_hash": MRENCLAVE,
            "model_version": "a122-d4-spu-grid",
            "model_manifest_hash": "11" * 32,
            "precision_plan_hash": "22" * 32,
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )
    assert shared_attestation_dir("/srv/ws", "d4 attested/2026").endswith(
        "/out/attest-d4-attested-2026"
    )
    assert shared_attestation_dir("/srv/ws", "run") == "/srv/ws/out/attest-run"


def test_the_precision_plan_is_the_grid_geometry(tmp_path: Path) -> None:
    first = precision_plan_hash(batch=64, rows=4, cols=8)
    assert first == precision_plan_hash(batch=64, rows=4, cols=8)
    assert first != precision_plan_hash(batch=32, rows=4, cols=8)
    assert len(first) == 64


def test_a_peer_map_is_only_written_when_every_rank_published(
    tmp_path: Path,
) -> None:
    material = generate(tmp_path / "kas")
    authority = CertificateAuthority.from_pem_files(
        Path(material["ca_key_path"]), Path(material["ca_cert_path"])
    )
    now = dt.datetime.now(dt.timezone.utc)
    leaves: dict[str, str] = {}
    for role in ("P0", "P1", "P2"):
        key = _generate_key()
        csr = _csr(role, key)
        leaves[role] = authority.issue_node_certificate(
            csr, role=role, release_id=RELEASE_ID, now=now, ttl=dt.timedelta(hours=1)
        ).certificate_pem

    assert collect_published_certificates({"P0": None}, ("P0",)) is None
    assert (
        collect_published_certificates(
            {"P0": leaves["P0"], "P1": None, "P2": leaves["P2"]}, ("P0", "P1", "P2")
        )
        is None
    )
    complete = collect_published_certificates(leaves, ("P0", "P1", "P2"))
    assert complete is not None and set(complete) == {"P0", "P1", "P2"}
    # A leaf that names another role is a driver error, not a gap to wait out.
    swapped = {**leaves, "P1": leaves["P2"]}
    with pytest.raises(NodeAttestationError, match="not a certificate for that role"):
        collect_published_certificates(swapped, ("P0", "P1", "P2"))
    assert certificate_is_for_role(leaves["P0"], "P0")
    assert not certificate_is_for_role(leaves["P0"], "P1")
    assert not certificate_is_for_role("not a pem", "P0")
    assert peer_map_document(leaves)["P0"] == leaves["P0"]


def test_the_collector_waits_and_then_refuses(tmp_path: Path) -> None:
    class SilentTransport:
        def run(self, route, command, *, timeout=None, check=True):
            del route, command, timeout, check
            return 0, "", ""

    with pytest.raises(ThreeHostError, match="published no KAS identity"):
        collect_node_certificates(
            transport=SilentTransport(),
            role_routes={"P0": object(), "P1": object(), "P2": object()},
            shared_dir="/srv/ws/out/attest-run",
            timeout=0.05,
            poll=0.01,
        )


def test_the_run_only_counts_when_every_rank_reports_its_own_lease() -> None:
    def status(role: str, lease: str, quote: str) -> dict[str, Any]:
        return {
            "role": role,
            "attestation": {
                "mode": "kas-attested",
                "lease_id": lease,
                "expires_at": "2026-10-14T22:00:00Z",
                "mrenclave": MRENCLAVE,
                "mrsigner": MRSIGNER,
                "quote_sha256": quote,
                "quote_bytes": 4734,
                "certificate": f"/tmp/a122-attest/attestation/{role}/{role}-cert.pem",
            },
        }

    good = {
        "P0": status("P0", "lease-0", "aa" * 32),
        "P1": status("P1", "lease-1", "bb" * 32),
        "P2": status("P2", "lease-2", "cc" * 32),
    }
    summary = assert_attested_run(good, roles=("P0", "P1", "P2"), mrenclave=MRENCLAVE)
    assert summary["distinct_leases"] == 3 and summary["distinct_quotes"] == 3

    missing = {role: dict(value) for role, value in good.items()}
    missing["P2"] = {"role": "P2"}
    with pytest.raises(NodeAttestationError, match="no attestation block"):
        assert_attested_run(missing, roles=("P0", "P1", "P2"), mrenclave=MRENCLAVE)

    local_pki = {role: dict(value) for role, value in good.items()}
    local_pki["P1"]["attestation"] = {"mode": "driver-pki"}
    with pytest.raises(NodeAttestationError, match="instead of a KAS identity"):
        assert_attested_run(local_pki, roles=("P0", "P1", "P2"), mrenclave=MRENCLAVE)

    elsewhere = {role: dict(value) for role, value in good.items()}
    elsewhere["P0"]["attestation"] = {**good["P0"]["attestation"], "mrenclave": "00" * 32}
    with pytest.raises(NodeAttestationError, match="not the registered"):
        assert_attested_run(elsewhere, roles=("P0", "P1", "P2"), mrenclave=MRENCLAVE)

    shared_lease = {role: dict(value) for role, value in good.items()}
    shared_lease["P1"]["attestation"] = {
        **good["P1"]["attestation"],
        "lease_id": "lease-0",
    }
    with pytest.raises(NodeAttestationError, match="same lease"):
        assert_attested_run(shared_lease, roles=("P0", "P1", "P2"), mrenclave=MRENCLAVE)


def test_the_attestation_block_names_what_the_node_needs() -> None:
    block = AttestationRequest(kas_port=18443).node_block(
        kas_host="172.27.172.201",
        shared_dir="/srv/ws/out/attest-run",
        release_id=RELEASE_ID,
    )
    assert block["kas_url"] == "http://172.27.172.201:18443"
    assert block["shared_dir"].endswith("/out/attest-run")
    assert block["release_id"] == RELEASE_ID
    assert block["peers_timeout_seconds"] > 0
    assert attestation_block(
        kas_url="http://host:1", release_id=RELEASE_ID, shared_dir="/srv/ws/out/x"
    )["kas_url"] == "http://host:1"
    assert PEERS_FILE_NAME == "peers.json"


def test_the_bundle_check_reads_back_what_the_nodes_wrote(tmp_path: Path) -> None:
    """The seal only means something if the nodes' own files say so."""
    material = generate(tmp_path / "kas")
    authority = CertificateAuthority.from_pem_files(
        Path(material["ca_key_path"]), Path(material["ca_cert_path"])
    )
    now = dt.datetime.now(dt.timezone.utc)
    leaves = {
        role: authority.issue_node_certificate(
            _csr(role, _generate_key()),
            role=role,
            release_id=RELEASE_ID,
            now=now,
            ttl=dt.timedelta(hours=1),
        ).certificate_pem
        for role in ("P0", "P1", "P2")
    }
    out = tmp_path / "bundle"
    out.mkdir()
    for index, role in enumerate(("P0", "P1", "P2")):
        (out / f"d4-attest-{role.lower()}-cert.pem").write_text(
            leaves[role], encoding="ascii", newline="\n"
        )
        (out / f"d4-three-{role.lower()}-node-status.json").write_text(
            json.dumps(
                {
                    "role": role,
                    "attestation": {
                        "mode": "kas-attested",
                        "lease_id": f"lease-{index}",
                        "expires_at": "2026-10-14T22:00:00Z",
                        "mrenclave": MRENCLAVE,
                        "mrsigner": MRSIGNER,
                        "quote_sha256": f"{index:02x}" * 32,
                        "quote_bytes": 4734,
                        "certificate": f"/tmp/a122-attest/attestation/{role}/x.pem",
                    },
                }
            ),
            encoding="utf-8",
            newline="\n",
        )
        (out / f"d4-three-{role.lower()}-node.log").write_text(
            "A122-ATTESTED " + json.dumps({"role": role}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    write_release_policy(
        out / "d4-attest-policy.json",
        release_policy_document(
            release_id=RELEASE_ID,
            claims=claims_from_quote(tmp_path / "quote.bin"),
            spu_build_hash=MRENCLAVE,
            model_version="a122-d4-spu-grid",
            model_manifest_hash="11" * 32,
            precision_plan_hash="22" * 32,
            expires_at=now + dt.timedelta(hours=1),
        ),
    )
    (out / "d4-attest-peers.json").write_text(
        json.dumps(peer_map_document(leaves)), encoding="utf-8", newline="\n"
    )

    result = assert_attested_evidence(out)
    assert result["distinct_leases"] == 3
    assert result["attested_logs"] == {"P0": True, "P1": True, "P2": True}
    assert len(result["peer_map_sha256"]) == 64

    # A rank that never logged the attested line makes the bundle not one.
    (out / "d4-three-p1-node.log").write_text(
        "the node started\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(ThreeHostError, match="never logged an attested identity"):
        assert_attested_evidence(out)

    # A peer map that does not carry the published leaf is a different failure.
    (out / "d4-three-p1-node.log").write_text(
        "A122-ATTESTED {}\n", encoding="utf-8", newline="\n"
    )
    (out / "d4-attest-peers.json").write_text("{}", encoding="utf-8", newline="\n")
    with pytest.raises(ThreeHostError, match="peer map does not carry"):
        assert_attested_evidence(out)


def test_the_kas_start_command_reads_the_storage_master_from_its_file() -> None:
    command = kas_start_command(
        repo="/srv/repo",
        python="/srv/venv/bin/python",
        settings={"KAS_HOST": "0.0.0.0", "KAS_PORT": "18443"},
        secret_files={"KAS_STORAGE_KEY_MASTER_HEX": "/tmp/kas/storage-key-master.hex"},
        log="/tmp/kas.log",
    )
    assert 'KAS_STORAGE_KEY_MASTER_HEX="$(cat /tmp/kas/storage-key-master.hex)"' in command
    assert "KAS_HOST=0.0.0.0" in command
    assert "-m kas" in command
    assert command.index("KAS_HOST") < command.index("-m kas")


def test_the_kas_is_stopped_by_port_and_not_by_name() -> None:
    command = stop_kas_command(18443)
    assert "18443" in command
    assert "kill" in command
    # Nothing broader than the one listener may be matched: a pattern kill
    # would take down whatever else happens to mention the KAS.
    assert "pkill" not in command


def test_a_relative_remote_path_resolves_through_home() -> None:
    class HomeTransport:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def run(self, route, command, *, timeout=None, check=True):
            del route, timeout, check
            self.commands.append(command)
            return 0, "/home/jiahao\n", ""

    transport = HomeTransport()
    assert resolve_remote_path(transport, None, "/already/absolute") == "/already/absolute"
    assert transport.commands == []
    assert resolve_remote_path(transport, None, "~/a122-shared/ws") == (
        "/home/jiahao/a122-shared/ws"
    )
    assert resolve_remote_path(transport, None, "~") == "/home/jiahao"


def test_a_generated_kas_issues_the_identity_the_nodes_pin(tmp_path: Path) -> None:
    """The whole chain: generated material -> release -> KAS -> pinned leaf."""
    material = generate(tmp_path / "kas-material")
    verifier = write_verifier_script(tmp_path / "verifier")
    quote_path = tmp_path / "bootstrap.bin"
    claims = claims_from_quote(quote_path)
    policy_path = write_release_policy(
        tmp_path / "policy.json",
        release_policy_document(
            release_id=RELEASE_ID,
            claims=claims,
            spu_build_hash=claims.mrenclave,
            model_version="a122-d4-spu-grid",
            model_manifest_hash="11" * 32,
            precision_plan_hash="22" * 32,
            expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
        ),
    )
    service = build_service(
        KASSettings.from_env(kas_environment(material, verifier, policy_path))
    )
    shared = tmp_path / "shared"
    attested = bootstrap_node_identity(
        _attestation_config(tmp_path, shared),
        role="P0",
        quote_source=lambda report_data: build_quote(report_data=report_data),
        post=kas_post(service),
    )
    assert attested.mrenclave == MRENCLAVE
    assert attested.lease_id

    published = (shared / "P0-cert.pem").read_text(encoding="ascii")
    collected = collect_published_certificates({"P0": published}, ("P0",))
    assert collected is not None
    # The node side then has to accept exactly that leaf, and reject the same
    # leaf claimed for another release.
    assert_peer_certificate(
        published,
        peer_role="P0",
        release_id=RELEASE_ID,
        ca_bundle_pem=str(material["ca_certificate_pem"]),
    )
    with pytest.raises(Exception, match="bound to another release"):
        assert_peer_certificate(
            published,
            peer_role="P0",
            release_id="a122-d4-attested-other",
            ca_bundle_pem=str(material["ca_certificate_pem"]),
        )


def test_the_evidence_writer_refuses_material_that_must_not_ship(
    tmp_path: Path,
) -> None:
    from infra.d4_evidence import write_document

    with pytest.raises(EvidenceError, match="sensitive markers"):
        write_document(
            tmp_path / "record.json",
            {"note": 'the record said "storage_key": "deadbeef"'},
        )
    assert not (tmp_path / "record.json").is_file()


def _attestation_config(tmp_path: Path, shared: Path):
    from tee.enclave.attestation import AttestationConfig

    return AttestationConfig(
        kas_url="http://127.0.0.1:18443",
        release_id=RELEASE_ID,
        shared_dir=shared,
        private_dir=tmp_path / "private",
        peers_timeout_seconds=1.0,
    )


def _generate_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def _csr(role: str, key) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"a122-{role}")])
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

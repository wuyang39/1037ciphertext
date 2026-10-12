from __future__ import annotations

import json

import pytest

from infra.d4_evidence import (
    REQUIRED_FILES,
    copy_certificates,
    copy_pcap,
    finalise,
    missing_required,
    write_document,
    write_text,
)
from infra.d4_workspace import (
    NEGATIVE_CASES,
    ROLES,
    build_workspace,
    load_workspace,
    loopback_cluster,
)
from infra.evidence import sha256_file


def _small_workspace(tmp_path):
    return build_workspace(
        tmp_path / "run",
        run_id="d4-test",
        cluster=loopback_cluster(),
        vector_count=16,
        batch=8,
        rows=2,
        cols=2,
    )


def test_workspace_layout_is_complete(tmp_path) -> None:
    manifest = _small_workspace(tmp_path)
    root = tmp_path / "run"
    assert manifest["vector_count"] == 16
    assert set(manifest["configs"]) == set(ROLES)
    for role in ROLES:
        assert (root / "pki" / "nodes" / role / f"{role}-cert.pem").is_file()
        assert (root / "pki" / "nodes" / role / f"{role}-key.pem").is_file()
        config = json.loads(manifest["configs"][role].replace("\\", "/") and
                            (root / "configs" / f"{role}.json").read_text(encoding="utf-8"))
        assert config["role"] == role
        assert [entry["role"] for entry in config["endpoints"]] == list(ROLES)
        assert set(config["peer_certificates"]) == set(ROLES) - {role}
        if role == "P0":
            assert config["vectors"]["count"] == 16
        else:
            assert config["vectors"] is None
    assert (root / "vectors.json").is_file()
    assert load_workspace(root)["run_id"] == "d4-test"


def test_negative_configurations_are_written_and_mutated(tmp_path) -> None:
    manifest = _small_workspace(tmp_path)
    root = tmp_path / "run"
    assert set(manifest["negative_configs"]) == set(NEGATIVE_CASES) - {"plaintext"}
    baseline = json.loads((root / "configs" / "P0.json").read_text(encoding="utf-8"))
    no_client = json.loads(
        (root / "negative" / "no-client-cert.json").read_text(encoding="utf-8")
    )
    assert baseline["present_client_certificate"] is True
    assert no_client["present_client_certificate"] is False
    disabled = json.loads(
        (root / "negative" / "tls-disabled.json").read_text(encoding="utf-8")
    )
    assert disabled["enable_ssl"] is False
    wrong_ca = json.loads(
        (root / "negative" / "wrong-ca.json").read_text(encoding="utf-8")
    )
    assert wrong_ca["peer_certificates"]["P2"] != baseline["peer_certificates"]["P2"]


def test_private_keys_are_not_world_readable_on_posix(tmp_path) -> None:
    if not hasattr(__import__("os"), "geteuid"):
        pytest.skip("POSIX permission bits are not available on this platform")
    _small_workspace(tmp_path)
    key = tmp_path / "run" / "pki" / "nodes" / "P0" / "P0-key.pem"
    assert key.stat().st_mode & 0o077 == 0


def test_evidence_assembly_requires_every_artifact(tmp_path) -> None:
    out = tmp_path / "d4"
    out.mkdir()
    write_text(out / "deny-plaintext.txt", "verdict: refused")
    write_document(out / "material-ledger.json", {"one_time_consumption": True})
    missing = missing_required(out)
    assert "tls-pcap.pcap" in missing
    assert len(missing) == len(REQUIRED_FILES) - 2
    for name in REQUIRED_FILES:
        target = out / name
        if target.is_file():
            continue
        target.write_bytes(b"placeholder")
    assert missing_required(out) == []


def test_finalise_seals_the_evidence_directory(tmp_path) -> None:
    out = tmp_path / "d4"
    out.mkdir()
    for name in REQUIRED_FILES:
        target = out / name
        if name.endswith(".json"):
            write_document(target, {"file": name})
        else:
            write_text(target, f"placeholder for {name}")
    result = finalise(
        out,
        run_id="d4-test",
        instance_id="i-test",
        cloud_region="cn-shanghai",
        details={"verdicts": {"rss_vectors": "passed"}},
    )
    assert result["summary"]["evidence_complete"] is True
    assert result["index"]["file_count"] == len(REQUIRED_FILES) + 1
    assert (out / "evidence.sha256").is_file()


def test_evidence_writer_refuses_sensitive_text(tmp_path) -> None:
    from infra.evidence import EvidenceError

    with pytest.raises(EvidenceError):
        write_text(tmp_path / "leak.txt", "-----BEGIN PRIVATE KEY-----\n")


def test_copy_pcap_accepts_a_capture_taken_in_place(tmp_path) -> None:
    """tcpdump writes straight into the evidence directory during a live run."""
    out = tmp_path / "d4"
    out.mkdir()
    capture = out / "tls-pcap.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1not-really-a-pcap")
    assert copy_pcap(capture, out) == sha256_file(capture)
    assert capture.read_bytes().startswith(b"\xd4\xc3\xb2\xa1")

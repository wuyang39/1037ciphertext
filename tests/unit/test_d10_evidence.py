"""The D10 bundle has to record its boundaries, not smooth them over."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from infra import d10_evidence


# Assembled from parts so this test does not itself carry a scanner needle.
STORAGE_NEEDLE = "bundle = {" + '"' + "storage_key" + '": value}\n'
DATA_NEEDLE = '{"' + "storage_key" + '": "abc"}\n'


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "README.md").write_text("submission\n", encoding="utf-8")
    return root


def _inputs(tmp_path: Path, root: Path) -> dict:
    archive = root / "a122-release.zip"
    archive.write_bytes(b"PK\x03\x04")
    release_manifest = root / "a122-release.manifest.json"
    release_manifest.write_text(
        json.dumps(
            {"file_count": 3, "tracked_only": True, "release_version": "test-tag"}
        ),
        encoding="utf-8",
    )
    release_check = root / "release-check.json"
    release_check.write_text(
        json.dumps(
            {
                "verdict": "released",
                "instances_still_ours": 0,
                "instances_unverified": 0,
                "note": "addresses silent",
            }
        ),
        encoding="utf-8",
    )
    sbom = root / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    rehearsal = root / "rehearsal.json"
    rehearsal.write_text(
        json.dumps({"verdict": "runs-without-patching"}), encoding="utf-8"
    )
    log = root / "rehearsal.log"
    log.write_text("$ compileall\n", encoding="utf-8")
    model_card = root / "model-card.md"
    model_card.write_text("# model card\n", encoding="utf-8")
    conclusion = root / "conclusion-map.md"
    conclusion.write_text("# conclusion map\n", encoding="utf-8")
    return {
        "root": root,
        "output_directory": root / "bundle",
        "run_id": "test-run",
        "archive": archive,
        "release_manifest": release_manifest,
        "release_check": release_check,
        "sbom": sbom,
        "rehearsal": rehearsal,
        "rehearsal_log": log,
        "model_card": model_card,
        "conclusion_map": conclusion,
    }


def test_bundle_records_the_release_and_stays_awaiting_operator(tmp_path):
    root = _repo(tmp_path)
    _git(root, "add", "-A")
    inputs = _inputs(tmp_path, root)
    summary = d10_evidence.run(**inputs)
    assert summary["probe_verdict"] == "released"
    assert summary["billing_status"] == "awaiting-operator"
    assert summary["secrets_sweep"] == "clean"
    assert summary["rehearsal_verdict"] == "runs-without-patching"
    bundle = inputs["output_directory"]
    assert (bundle / "evidence-index.json").is_file()
    assert (bundle / "evidence.sha256").is_file()
    resource = json.loads((bundle / "resource-release.json").read_text(encoding="utf-8"))
    assert resource["operator_confirmation"] is None
    assert "not signed off" in resource["boundary"]


def test_bundle_records_an_operator_billing_confirmation(tmp_path):
    root = _repo(tmp_path)
    _git(root, "add", "-A")
    inputs = _inputs(tmp_path, root)
    billing = root / "billing.json"
    billing.write_text(
        json.dumps({"confirmed": True, "checked_at": "2026-10-13"}), encoding="utf-8"
    )
    inputs["billing"] = billing
    summary = d10_evidence.run(**inputs)
    assert summary["billing_status"] == "recorded"
    resource = json.loads(
        (inputs["output_directory"] / "resource-release.json").read_text("utf-8")
    )
    assert resource["operator_confirmation"]["confirmed"] is True


def test_bundle_carries_the_acceptance_record_when_given(tmp_path):
    root = _repo(tmp_path)
    _git(root, "add", "-A")
    inputs = _inputs(tmp_path, root)
    acceptance = root / "d10-release-acceptance.md"
    acceptance.write_text("# acceptance\n", encoding="utf-8")
    inputs["acceptance"] = acceptance
    d10_evidence.run(**inputs)
    assert (inputs["output_directory"] / "d10-release-acceptance.md").is_file()


def test_sweep_reports_forbidden_key_paths(tmp_path):
    root = _repo(tmp_path)
    (root / "secrets").mkdir()
    (root / "secrets" / "id_rsa.key").write_text("x", encoding="utf-8")
    _git(root, "add", "-A")
    sweep = d10_evidence.sweep_repository(root)
    assert sweep["verdict"] == "found"
    rules = {entry["rule"] for entry in sweep["forbidden_paths"]}
    assert "secrets-directory" in rules
    assert "private-key-extension" in rules


def test_sweep_flags_a_marker_in_a_data_file(tmp_path):
    root = _repo(tmp_path)
    (root / "notes.json").write_text(DATA_NEEDLE, encoding="utf-8")
    _git(root, "add", "-A")
    sweep = d10_evidence.sweep_repository(root)
    assert sweep["verdict"] == "found"
    assert sweep["sensitive_markers"][0]["path"] == "notes.json"


def test_sweep_excuses_a_reviewed_source_path(tmp_path):
    root = _repo(tmp_path)
    (root / "crypto").mkdir()
    (root / "crypto" / "enclave_key.py").write_text(
        STORAGE_NEEDLE, encoding="utf-8"
    )
    _git(root, "add", "-A")
    sweep = d10_evidence.sweep_repository(root)
    assert sweep["verdict"] == "clean"
    assert sweep["reviewed_source_markers"][0]["path"] == "crypto/enclave_key.py"
    assert sweep["unreviewed_source_markers"] == []


def test_evidence_hashes_digest_each_sealed_bundle(tmp_path):
    root = _repo(tmp_path)
    bundle = root / "docs" / "evidence" / "d1-test"
    bundle.mkdir(parents=True)
    (bundle / "evidence-index.json").write_text(
        json.dumps({"file_count": 2}), encoding="utf-8"
    )
    (bundle / "evidence.sha256").write_text("a" * 64 + "  evidence-index.json\n")
    records = d10_evidence.evidence_hashes(root)
    assert records[0]["bundle"] == "d1-test"
    assert records[0]["file_count"] == 2
    assert len(records[0]["seal"]) == 64

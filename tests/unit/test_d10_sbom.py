"""The D10 SBOM has to describe the real tree, not a hand-written list."""

from __future__ import annotations

import json
from pathlib import Path

from infra import build_sbom


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_tree_digest_is_deterministic_and_tracks_content(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "a.py").write_text("x = 1\n", encoding="utf-8")
    first = build_sbom.tree_digest(package)
    assert first == build_sbom.tree_digest(package)
    (package / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert build_sbom.tree_digest(package) != first


def test_tree_digest_ignores_caches(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "a.py").write_text("x = 1\n", encoding="utf-8")
    before = build_sbom.tree_digest(package)
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "a.cpython-312.pyc").write_bytes(b"\x00\x01")
    assert build_sbom.tree_digest(package) == before


def test_declared_dependencies_split_runtime_and_optional():
    declared = build_sbom.parse_declared_dependencies(REPO_ROOT / "pyproject.toml")
    scopes = {entry["requirement"]: entry["scope"] for entry in declared}
    assert scopes["cryptography>=48,<49"] == "runtime"
    assert scopes["pytest>=9.1,<10"] == "optional:dev"


def test_sbom_lists_local_packages_and_the_frozen_model():
    document = build_sbom.build_sbom(REPO_ROOT, version="test-version")
    components = {component["name"]: component for component in document["components"]}
    assert "a122-privacy-llm::client" in components
    model = components["gpt2"]
    assert model["type"] == "machine-learning-model"
    assert len(model["hashes"]) == 6
    assert model["licenses"][0]["license"]["name"].startswith("Modified MIT")


def test_sbom_records_server_runtimes_it_cannot_resolve_locally():
    document = build_sbom.build_sbom(REPO_ROOT, version="test-version")
    runtimes = {
        component["name"]
        for component in document["components"]
        if component["group"] == "server-runtime"
    }
    assert {"gramine", "secretflow-spu", "dcap-qvl"} <= runtimes


def test_sbom_is_deterministic_without_a_timestamp():
    first = build_sbom.build_sbom(REPO_ROOT, version="test-version")
    second = build_sbom.build_sbom(REPO_ROOT, version="test-version")
    assert first == second
    assert "timestamp" not in first["metadata"]


def test_sbom_carries_a_timestamp_only_when_asked():
    document = build_sbom.build_sbom(
        REPO_ROOT, version="test-version", timestamp="2026-10-13T00:00:00Z"
    )
    assert document["metadata"]["timestamp"] == "2026-10-13T00:00:00Z"


def test_main_writes_cyclonedx_json(tmp_path):
    output = tmp_path / "sbom.json"
    assert (
        build_sbom.main(
            ["--root", str(REPO_ROOT), "--version", "test-version", "--output", str(output)]
        )
        == 0
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"

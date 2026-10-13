"""Build a CycloneDX SBOM for the A1-D10 submission.

The document has three layers, because the submission genuinely has three kinds
of component and collapsing them would be dishonest:

1. local packages that ship in the archive, summarised by a deterministic tree
   digest so the SBOM moves when the code moves;
2. Python distributions the code imports, with the declared constraint from
   ``pyproject.toml`` and, when this workstation can resolve it, the version
   actually installed;
3. server-only runtimes (Gramine, the SGX SDK, DCAP QVL, YACL/BRPC, SPU) that
   are pinned by the release measurement on the instance, not by a wheel here.

The frozen GPT-2 weights are carried as a ``machine-learning-model`` component
with the same per-file digests the freeze record pins, so the licence and the
model hash land in the SBOM rather than only in prose.

The output is deterministic: no wall-clock timestamp is written unless
``--timestamp`` is passed, so two builds of the same tree hash the same.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, Sequence

from infra.evidence import write_json


SBOM_FORMAT = "CycloneDX"
SBOM_SPEC_VERSION = "1.5"
LOCAL_PACKAGES = (
    "benchmark",
    "client",
    "contracts",
    "crypto",
    "infra",
    "kas",
    "model",
    "mpc",
    "tee",
)
# These are not on PyPI in the tested form or are not importable here; their
# authoritative version belongs to the release measurement.
SERVER_RUNTIMES: tuple[dict[str, str], ...] = (
    {
        "name": "gramine",
        "version": "1.9",
        "note": "Gramine-SGX runtime; pinned by the image and manifest measurement",
    },
    {
        "name": "intel-sgx-sdk",
        "version": "2.x",
        "note": "enclave build toolchain; pinned by the image digest",
    },
    {
        "name": "dcap-qvl",
        "version": "server-pinned",
        "note": "Quote verification library and PCCS configuration",
    },
    {
        "name": "yacl-brpc",
        "version": "spu-bundled",
        "note": "mTLS/BRPC transport shipped with SecretFlow-SPU",
    },
    {
        "name": "secretflow-spu",
        "version": "0.9.5",
        "note": "3PC RSS runtime used by the D4-D6 acceptance runs",
    },
)
GPT2_COMPONENT = {
    "name": "gpt2",
    "revision": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
    "license": "Modified MIT License (OpenAI, 2019)",
    "upstream": "https://github.com/openai/gpt-2",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: Path) -> dict[str, Any]:
    """Deterministic digest over the source files under one package directory."""
    digest = hashlib.sha256()
    files = 0
    total = 0
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        payload = path.read_bytes()
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).hexdigest().encode("ascii"))
        digest.update(b"\n")
        files += 1
        total += len(payload)
    return {"sha256": digest.hexdigest(), "files": files, "bytes": total}


def parse_declared_dependencies(pyproject: Path) -> list[dict[str, str]]:
    document = tomllib.loads(Path(pyproject).read_text(encoding="utf-8"))
    project = document.get("project", {})
    declared: list[dict[str, str]] = []
    for requirement in project.get("dependencies", []):
        declared.append({"requirement": str(requirement), "scope": "runtime"})
    optional = project.get("optional-dependencies", {})
    for group, requirements in optional.items():
        for requirement in requirements:
            declared.append({"requirement": str(requirement), "scope": f"optional:{group}"})
    return declared


def _requirement_name(requirement: str) -> str:
    name = requirement.split(";", 1)[0].strip()
    for separator in (">=", "<=", "==", "!=", "~=", ">", "<", "[", " "):
        name = name.split(separator, 1)[0]
    return name.strip().lower().replace("_", "-")


def python_components(pyproject: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for declared in parse_declared_dependencies(pyproject):
        requirement = declared["requirement"]
        name = _requirement_name(requirement)
        resolved = None
        try:
            resolved = metadata.version(name)
        except metadata.PackageNotFoundError:
            resolved = None
        components.append(
            {
                "type": "library",
                "name": name,
                "group": "pypi",
                "version": resolved or "unresolved",
                "scope": declared["scope"],
                "properties": [
                    {"name": "a122:requirement", "value": requirement},
                    {"name": "a122:resolved-locally", "value": bool(resolved)},
                ],
            }
        )
    return components


def local_components(root: Path, version: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for name in LOCAL_PACKAGES:
        directory = Path(root) / name
        if not directory.is_dir():
            continue
        digest = tree_digest(directory)
        components.append(
            {
                "type": "library",
                "name": f"a122-privacy-llm::{name}",
                "group": "local",
                "version": version,
                "properties": [
                    {"name": "a122:kind", "value": "local-package"},
                    {"name": "a122:path", "value": name},
                    {"name": "a122:tree-sha256", "value": digest["sha256"]},
                    {"name": "a122:file-count", "value": digest["files"]},
                    {"name": "a122:bytes", "value": digest["bytes"]},
                ],
            }
        )
    return components


def server_components() -> list[dict[str, Any]]:
    return [
        {
            "type": "platform",
            "name": runtime["name"],
            "group": "server-runtime",
            "version": runtime["version"],
            "properties": [
                {"name": "a122:kind", "value": "server-runtime"},
                {"name": "a122:note", "value": runtime["note"]},
            ],
        }
        for runtime in SERVER_RUNTIMES
    ]


def gpt2_component() -> dict[str, Any]:
    from model.gpt2 import SOURCE_FILES

    return {
        "type": "machine-learning-model",
        "name": GPT2_COMPONENT["name"],
        "group": "huggingface",
        "version": GPT2_COMPONENT["revision"],
        "licenses": [{"license": {"name": GPT2_COMPONENT["license"]}}],
        "externalReferences": [
            {"type": "vcs", "url": GPT2_COMPONENT["upstream"]}
        ],
        "hashes": [
            {"alg": "SHA-256", "content": source.sha256} for source in SOURCE_FILES
        ],
        "properties": [
            {"name": "a122:kind", "value": "frozen-model"},
            {"name": "a122:revision", "value": GPT2_COMPONENT["revision"]},
            *[
                {"name": f"a122:file:{source.name}", "value": f"{source.size}:{source.sha256}"}
                for source in SOURCE_FILES
            ],
        ],
    }


def build_sbom(
    root: Path,
    *,
    version: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve()
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise ValueError(f"pyproject.toml is missing under {root}")
    document: dict[str, Any] = {
        "bomFormat": SBOM_FORMAT,
        "specVersion": SBOM_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "a122-privacy-llm",
                "version": version,
                "licenses": [{"license": {"name": "proprietary-submission"}}],
            },
            "tools": [{"vendor": "A1-22", "name": "infra.build_sbom", "version": "1"}],
        },
        "components": (
            local_components(root, version)
            + python_components(pyproject)
            + server_components()
            + [gpt2_component()]
        ),
    }
    if timestamp is not None:
        document["metadata"]["timestamp"] = timestamp
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the A1-22 D10 CycloneDX SBOM")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--version", default="local-checkpoint")
    parser.add_argument("--timestamp", default=None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = build_sbom(args.root, version=args.version, timestamp=args.timestamp)
    except (OSError, ValueError) as exc:
        print(f"the SBOM could not be built: {exc}", file=sys.stderr)
        return 2
    write_json(args.output, document)
    print(
        json.dumps(
            {
                "bomFormat": document["bomFormat"],
                "specVersion": document["specVersion"],
                "components": len(document["components"]),
                "output": str(args.output),
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


__all__ = [
    "GPT2_COMPONENT",
    "LOCAL_PACKAGES",
    "SBOM_FORMAT",
    "SBOM_SPEC_VERSION",
    "SERVER_RUNTIMES",
    "build_sbom",
    "gpt2_component",
    "local_components",
    "main",
    "parse_declared_dependencies",
    "python_components",
    "server_components",
    "tree_digest",
]


if __name__ == "__main__":
    raise SystemExit(main())

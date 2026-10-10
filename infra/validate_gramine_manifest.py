"""Render and statically validate the A1-22 Gramine manifest template."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from infra.evidence import sha256_bytes, write_json


PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
REQUIRED_VALUES = {
    "entrypoint",
    "release_id",
    "role",
    "share_epoch",
    "enclave_size",
    "lib_dir",
    "run_tee_dir",
    "run_session_dir",
    "secure_fs_dir",
    "model_share_path",
    "preprocessing_package_path",
    "python_runtime_path",
}


class ManifestValidationError(ValueError):
    """The Gramine template is incomplete or violates the security baseline."""


def render_template(
    template: str,
    values: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    placeholders = set(PLACEHOLDER.findall(template))
    missing = sorted(REQUIRED_VALUES - set(values))
    if missing:
        raise ManifestValidationError(
            "manifest values are missing: " + ", ".join(missing)
        )
    unused = sorted(set(values) - placeholders)
    if unused:
        raise ManifestValidationError(
            "manifest values are unused: " + ", ".join(unused)
        )
    unresolved = sorted(placeholders - set(values))
    if unresolved:
        raise ManifestValidationError(
            "manifest placeholders are unresolved: " + ", ".join(unresolved)
        )

    def replace(match: re.Match[str]) -> str:
        value = values[match.group(1)]
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    rendered = PLACEHOLDER.sub(replace, template)
    if PLACEHOLDER.search(rendered):
        raise ManifestValidationError("manifest still contains placeholders")
    return rendered, {
        "placeholder_count": len(placeholders),
        "sha256": sha256_bytes(rendered.encode("utf-8")),
        "bytes": len(rendered.encode("utf-8")),
    }


def validate_manifest_text(manifest: str) -> None:
    normalized = "\n".join(
        line.split("#", 1)[0] for line in manifest.splitlines()
    )
    if re.search(r"\bsgx\.debug\s*=\s*true\b", normalized):
        raise ManifestValidationError("debug enclaves are forbidden")
    if not re.search(r"\bsgx\.debug\s*=\s*false\b", normalized):
        raise ManifestValidationError("sgx.debug must be explicitly false")
    if "loader.insecure__use_cmdline_argv = false" not in normalized:
        raise ManifestValidationError("insecure command-line argv must be disabled")
    if 'type = "encrypted"' not in normalized:
        raise ManifestValidationError("encrypted FS mount is required")
    if 'sgx.remote_attestation = "dcap"' not in normalized:
        raise ManifestValidationError("DCAP remote attestation is required")
    if 'sgx.attestation_quote_type = "ecdsa"' not in normalized:
        raise ManifestValidationError("ECDSA Quote type is required")
    if "{{" in normalized or "}}" in normalized:
        raise ManifestValidationError("manifest contains unresolved placeholders")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("tee/gramine/a122.manifest.template"),
    )
    parser.add_argument("--values", type=Path)
    parser.add_argument("--text", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.text:
            manifest = args.text.read_text(encoding="utf-8")
            details = {
                "mode": "validate-rendered",
                "sha256": sha256_bytes(manifest.encode("utf-8")),
            }
        else:
            values = json.loads(args.values.read_text(encoding="utf-8"))
            manifest, details = render_template(
                args.template.read_text(encoding="utf-8"),
                values,
            )
            details["mode"] = "render-and-validate"
        validate_manifest_text(manifest)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(manifest, encoding="utf-8")
        result = {"valid": True, **details}
        if args.evidence:
            write_json(args.evidence, result)
        else:
            print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Gramine manifest validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ManifestValidationError",
    "REQUIRED_VALUES",
    "render_template",
    "validate_manifest_text",
]

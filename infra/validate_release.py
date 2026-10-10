"""Validate deterministic A1-22 release archives and manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

from infra.evidence import assert_redacted, write_json


class ReleaseValidationError(ValueError):
    """A release archive is incomplete or fails an integrity check."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_json(value: bytes, *, name: str) -> dict[str, Any]:
    try:
        document = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError(f"{name} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ReleaseValidationError(f"{name} must contain a JSON object")
    return document


def validate_archive(
    archive_path: Path,
    *,
    external_manifest_path: Path | None = None,
    scan_sensitive: bool = False,
) -> dict[str, Any]:
    """Verify the embedded manifest, hashes, sizes, and archive file set."""
    archive_path = Path(archive_path)
    try:
        archive = zipfile.ZipFile(archive_path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReleaseValidationError("release archive is not a valid ZIP") from exc
    with archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ReleaseValidationError("release archive contains duplicate paths")
        if "release-manifest.json" not in names:
            raise ReleaseValidationError("release manifest is missing")
        manifest = _load_json(
            archive.read("release-manifest.json"),
            name="release manifest",
        )
        if manifest.get("format") != "deterministic-source-zip-v1":
            raise ReleaseValidationError("release format is not supported")
        entries = manifest.get("files")
        if not isinstance(entries, list):
            raise ReleaseValidationError("release manifest files field is invalid")
        expected_paths = {"release-manifest.json"}
        total_bytes = 0
        for entry in entries:
            if not isinstance(entry, dict):
                raise ReleaseValidationError("release manifest entry is invalid")
            name = str(entry.get("path", ""))
            if not name or name.startswith("/") or ".." in Path(name).parts:
                raise ReleaseValidationError("release manifest contains an unsafe path")
            if name in expected_paths:
                raise ReleaseValidationError("release manifest contains a duplicate path")
            try:
                payload = archive.read(name)
            except KeyError as exc:
                raise ReleaseValidationError(f"release file is missing: {name}") from exc
            if len(payload) != int(entry.get("bytes", -1)):
                raise ReleaseValidationError(f"release size mismatch: {name}")
            if _sha256(payload) != entry.get("sha256"):
                raise ReleaseValidationError(f"release hash mismatch: {name}")
            if scan_sensitive:
                try:
                    assert_redacted(payload.decode("utf-8"))
                except UnicodeDecodeError:
                    pass
                except ValueError as exc:
                    raise ReleaseValidationError(
                        f"release-sensitive marker in {name}: {exc}"
                    ) from exc
            expected_paths.add(name)
            total_bytes += len(payload)
        actual_paths = set(names)
        if actual_paths != expected_paths:
            extra = sorted(actual_paths - expected_paths)
            missing = sorted(expected_paths - actual_paths)
            raise ReleaseValidationError(
                f"release file set mismatch; extra={extra}, missing={missing}"
            )
        if int(manifest.get("file_count", -1)) != len(entries):
            raise ReleaseValidationError("release file count mismatch")
        if external_manifest_path is not None:
            external = _load_json(
                Path(external_manifest_path).read_bytes(),
                name="external manifest",
            )
            if external != manifest:
                raise ReleaseValidationError("external and embedded manifests differ")
    return {
        "archive": archive_path.name,
        "archive_sha256": _sha256(archive_path.read_bytes()),
        "release_version": manifest.get("release_version"),
        "format": manifest["format"],
        "file_count": len(entries),
        "uncompressed_bytes": total_bytes,
        "valid": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--scan-sensitive", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_archive(
            args.archive,
            external_manifest_path=args.manifest,
            scan_sensitive=args.scan_sensitive,
        )
    except (OSError, ValueError) as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 1
    if args.output:
        write_json(args.output, result)
    else:
        print(
            json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ReleaseValidationError", "validate_archive"]

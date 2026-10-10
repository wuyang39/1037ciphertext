"""Build a deterministic source archive for the D10 local handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


EXCLUDED_DIRS = {
    ".git",
    ".codex-artifacts",
    ".idea",
    ".venv",
    ".vscode",
    "build",
    "dist",
    ".pytest_cache",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    "artifacts",
}
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _iter_source_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(
            part in EXCLUDED_DIRS or part.endswith(".egg-info")
            for part in relative.parts
        ):
            continue
        if relative.name.endswith((".pyc", ".pyo")):
            continue
        yield path, relative


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def build(root: Path, output: Path, version: str) -> dict[str, object]:
    root = Path(root).resolve()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, str]] = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, relative in _iter_source_files(root):
            raw = path.read_bytes()
            name = relative.as_posix()
            digest = hashlib.sha256(raw).hexdigest()
            entries.append({"path": name, "sha256": digest, "bytes": len(raw)})
            archive.writestr(_zip_info(name), raw)
        manifest = {
            "release_version": version,
            "format": "deterministic-source-zip-v1",
            "files": entries,
            "file_count": len(entries),
        }
        archive.writestr(
            _zip_info("release-manifest.json"),
            (json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode(
                "utf-8"
            ),
        )
    manifest_path = output.with_suffix(".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default="local-checkpoint")
    args = parser.parse_args()
    build(args.root, args.output, args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

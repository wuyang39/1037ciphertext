"""Build a deterministic source archive for the D10 local handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Iterable, Iterator


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


def _iter_tracked_files(root: Path) -> Iterator[tuple[Path, Path]]:
    """Yield only the files Git tracks under ``root``.

    The submission archive must be exactly what is in the repository: a
    filesystem walk would sweep in untracked research notes and local scratch
    files that were never meant to ship.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "tracked-only packaging needs a Git work tree with a readable index"
        ) from exc
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        path = root / relative
        if not path.is_file():
            continue
        yield path, relative


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def _iter_files(root: Path, *, tracked_only: bool) -> Iterable[tuple[Path, Path]]:
    if tracked_only:
        yield from _iter_tracked_files(root)
    else:
        yield from _iter_source_files(root)


def build(
    root: Path,
    output: Path,
    version: str,
    *,
    tracked_only: bool = False,
) -> dict[str, object]:
    root = Path(root).resolve()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, str]] = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, relative in _iter_files(root, tracked_only=tracked_only):
            raw = path.read_bytes()
            name = relative.as_posix()
            digest = hashlib.sha256(raw).hexdigest()
            entries.append({"path": name, "sha256": digest, "bytes": len(raw)})
            archive.writestr(_zip_info(name), raw)
        manifest = {
            "release_version": version,
            "format": "deterministic-source-zip-v1",
            "tracked_only": tracked_only,
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
    parser.add_argument(
        "--tracked-only",
        action="store_true",
        help="package only the files Git tracks, so untracked scratch cannot ship",
    )
    args = parser.parse_args()
    build(args.root, args.output, args.version, tracked_only=args.tracked_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

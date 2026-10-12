"""Search the untrusted host for plaintext model-share material."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from infra.evidence import write_json


MAX_FILE_BYTES = 64 * 1024 * 1024


def scan_roots(
    needles: dict[str, bytes],
    roots: list[Path],
    *,
    skip: set[Path] | None = None,
) -> list[dict[str, object]]:
    """Return one record per file that contains any needle."""
    skip = {path.resolve() for path in (skip or set())}
    hits: list[dict[str, object]] = []
    for root in roots:
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in candidates:
            if not path.is_file():
                continue
            try:
                if path.resolve() in skip or path.stat().st_size > MAX_FILE_BYTES:
                    continue
                blob = path.read_bytes()
            except OSError:
                continue
            for name, needle in needles.items():
                if needle and needle in blob:
                    hits.append(
                        {
                            "path": str(path),
                            "needle": name,
                            "bytes": len(blob),
                        }
                    )
                    break
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--needle-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--skip", type=Path, action="append", default=[])
    args = parser.parse_args(argv)

    plaintext = args.needle_file.read_bytes()
    needles = {
        "first_64_bytes": plaintext[:64],
        "last_64_bytes": plaintext[-64:],
        "full_share": plaintext,
    }
    hits = scan_roots(needles, args.root, skip=set(args.skip))
    write_json(
        args.output,
        {
            "roots": [str(root) for root in args.root],
            "needle_bytes": len(plaintext),
            "hits": hits,
            "plaintext_share_found_on_host": bool(hits),
        },
    )
    print(json.dumps({"hits": len(hits)}, sort_keys=True))
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())

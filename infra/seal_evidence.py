"""CLI for sealing and verifying one evidence directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from infra.evidence import seal_directory, verify_directory


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal = subparsers.add_parser("seal")
    seal.add_argument("directory", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--allow-missing-seal", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "seal":
            result = seal_directory(args.directory)
        else:
            result = verify_directory(
                args.directory,
                require_seal=not args.allow_missing_seal,
            )
    except (OSError, ValueError) as exc:
        print(f"evidence operation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

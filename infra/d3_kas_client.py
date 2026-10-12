"""Minimal KAS HTTP client for the D3 sealed-storage-key acceptance run.

The run needs two calls: ask for a one-use challenge, then ask the KAS to seal
the disk key to the enclave key that the DCAP Quote binds. Everything is
written as JSON so the evidence bundle records exactly what the KAS answered.
"""

from __future__ import annotations

import argparse
import base64
import json
import urllib.error
import urllib.request
from pathlib import Path

from infra.evidence import write_json


class KASClientError(RuntimeError):
    """The KAS request could not be completed."""


def post(
    base_url: str,
    path: str,
    payload: dict[str, object],
    *,
    timeout: float = 30.0,
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            document = {"detail": raw}
        return exc.code, document
    except urllib.error.URLError as exc:
        raise KASClientError(f"KAS is unreachable: {exc}") from exc


def _challenge(args: argparse.Namespace) -> int:
    status, document = post(
        args.base_url,
        "/v1/challenge",
        {"role": args.role, "release_id": args.release_id},
    )
    write_json(
        args.output,
        {
            "request": {
                "role": args.role,
                "release_id": args.release_id,
            },
            "status": status,
            "body": document,
        },
    )
    print(json.dumps({"status": status}, sort_keys=True))
    return 0 if status == 201 else 1


def _seal(args: argparse.Namespace) -> int:
    challenge = json.loads(args.challenge_file.read_text(encoding="utf-8"))
    if challenge.get("status") != 201:
        raise KASClientError("the challenge file does not hold a 201 response")
    quote = args.quote_file.read_bytes()
    payload = {
        "challenge_id": str(challenge["body"]["challenge_id"]),
        "role": args.role,
        "release_id": args.release_id,
        "share_epoch": args.share_epoch,
        "purpose": args.purpose,
        "enclave_public_key": args.enclave_public_key,
        "dcap_quote_b64": base64.b64encode(quote).decode("ascii"),
    }
    status, document = post(
        args.base_url,
        "/v1/release-storage-key-sealed",
        payload,
    )
    record = {
        "request": {
            "role": args.role,
            "release_id": args.release_id,
            "share_epoch": args.share_epoch,
            "purpose": args.purpose,
            "enclave_public_key": args.enclave_public_key,
            "challenge_id": payload["challenge_id"],
            "quote_bytes": len(quote),
        },
        "status": status,
        "body": document,
    }
    write_json(args.output, record)
    output = {"status": status}
    if status == 200:
        output["key_id"] = str(document["key_id"])
        output["startup_hash"] = str(document["startup_hash"])
    print(json.dumps(output, sort_keys=True))
    if args.allow_status:
        return 0 if status in args.allow_status else 1
    return 0 if status == 200 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18443")
    parser.add_argument("--role", default="P0")
    parser.add_argument("--release-id", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    challenge_parser = subparsers.add_parser("challenge")
    challenge_parser.add_argument("--output", type=Path, required=True)
    challenge_parser.set_defaults(handler=_challenge)

    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--challenge-file", type=Path, required=True)
    seal_parser.add_argument("--quote-file", type=Path, required=True)
    seal_parser.add_argument("--enclave-public-key", required=True)
    seal_parser.add_argument("--share-epoch", type=int, required=True)
    seal_parser.add_argument("--purpose", default="model-store")
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.add_argument(
        "--allow-status",
        type=int,
        nargs="*",
        default=None,
        help="treat these HTTP status codes as an expected outcome",
    )
    seal_parser.set_defaults(handler=_seal)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (KASClientError, OSError, KeyError, ValueError) as exc:
        print(f"kas client failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

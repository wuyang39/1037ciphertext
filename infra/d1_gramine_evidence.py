"""Assemble the D1 Gramine-SGX evidence from a captured hello run."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
from pathlib import Path

from infra.evidence import sha256_bytes, write_json
from infra.sgx_quote import parse_quote


QUOTE_HEX = re.compile(r"^quote_hex=([0-9a-fA-F]+)$", re.MULTILINE)
REPORT_DATA_HEX = re.compile(r"^report_data_hex=([0-9a-fA-F]+)$", re.MULTILINE)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def extract_quote(hello_output: str) -> tuple[bytes, bytes]:
    """Return the (report_data, quote) pair captured by the hello probe."""
    quote_match = QUOTE_HEX.search(hello_output)
    if quote_match is None:
        raise ValueError("gramine hello output carries no quote_hex= line")
    report_match = REPORT_DATA_HEX.search(hello_output)
    if report_match is None:
        raise ValueError("gramine hello output carries no report_data_hex= line")
    return bytes.fromhex(report_match.group(1)), bytes.fromhex(quote_match.group(1))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hello-output", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance-id", default="unknown")
    parser.add_argument("--cloud-region", default="cn-shanghai")
    parser.add_argument("--image-id", default="unknown")
    args = parser.parse_args(argv)

    args.output.mkdir(parents=True, exist_ok=True)
    hello_text = args.hello_output.read_text(encoding="utf-8", errors="replace")
    report_data, quote = extract_quote(hello_text)

    quote_path = args.output / "gramine-quote.bin"
    quote_path.write_bytes(quote)
    claims = parse_quote(quote)

    verified = subprocess.run(
        [str(args.verifier), "--quote", str(quote_path), "--json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=180.0,
    )
    try:
        verifier_json = json.loads(verified.stdout)
    except json.JSONDecodeError:
        verifier_json = None

    timestamp = _now().isoformat()
    common = {
        "run_id": args.run_id,
        "phase": "D1-gramine",
        "timestamp_utc": timestamp,
        "cloud_region": args.cloud_region,
        "instance_id": args.instance_id,
        "image_id": args.image_id,
    }

    report = {
        **common,
        "command": "gramine-sgx ./hello",
        "claims": claims.to_evidence(),
        "report_data_matches_probe": claims.report_data == report_data,
        "quote_sha256": sha256_bytes(quote),
        "quote_bytes": len(quote),
    }
    write_json(args.output / "gramine-quote-report.json", report)

    verify_evidence = {
        "command": f"{args.verifier} --quote gramine-quote.bin --json",
        "returncode": verified.returncode,
        "document": verifier_json,
        "stderr": verified.stderr.strip()[:2000],
    }
    write_json(args.output / "gramine-dcap-verify.json", verify_evidence)

    verify_status = (verifier_json or {}).get("dcap_verify_status")
    accepted = verified.returncode == 0 and verify_status == "0x0000"
    summary = {
        **common,
        "hello_marker_present": "A1_22_GRAMINE_HELLO_END" in hello_text,
        "gramine_quote_accepted": accepted,
        "dcap_verify_status": verify_status,
        "dcap_verification_result": (verifier_json or {}).get(
            "dcap_verification_result"
        ),
        "mrenclave": claims.mr_enclave.hex(),
        "mrsigner": claims.mr_signer.hex(),
        "debug_enclave": claims.debug,
        "quote_sha256": sha256_bytes(quote),
    }
    write_json(args.output / "gramine-summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

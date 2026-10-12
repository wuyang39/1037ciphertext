"""Collect the D3 KAS-sealed-release verdicts from a run directory."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from infra.evidence import write_json


class D3KASEvidenceError(ValueError):
    """The D3 KAS-release run is incomplete or a case behaved unexpectedly."""


CASE_NAMES = (
    "accept-kas-sealed-release",
    "deny-missing-sealed",
    "deny-tampered-sealed",
    "deny-wrong-epoch",
    "deny-wrong-startup",
    "deny-replay-challenge",
    "deny-second-seal",
    "deny-wrong-measurement",
)


def _read_text(path: Path) -> str:
    if not path.is_file():
        raise D3KASEvidenceError(f"missing D3 KAS-release evidence: {path.name}")
    return path.read_text(encoding="utf-8", errors="replace")


def _read_json(path: Path) -> dict:
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise D3KASEvidenceError(f"{path.name} is not valid JSON") from exc


def _refused(case: dict) -> bool:
    enclave = case.get("enclave", {})
    return enclave.get("read_ok") == 0 and enclave.get("key_installed") == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance-id", default="unknown")
    parser.add_argument("--cloud-region", default="cn-shanghai")
    parser.add_argument("--image-id", default="unknown")
    args = parser.parse_args(argv)

    out = args.output
    packaging = _read_json(out / "packaging.json")
    cases = _read_json(out / "cases.json")
    substring = _read_text(out / "host-substring-search.txt")
    host_scan = _read_json(out / "host-scan.json")
    claims = cases.get("claims", {})
    results = cases.get("cases", {})

    missing = [name for name in CASE_NAMES if name not in results]
    if missing:
        raise D3KASEvidenceError("missing cases: " + ", ".join(missing))

    share = next(
        (
            item
            for item in packaging["plaintext_files"]
            if item["name"] == "model-share-P0.bin"
        ),
        None,
    )
    if share is None:
        raise D3KASEvidenceError("the packaging record has no P0 share")

    accept = results["accept-kas-sealed-release"]
    accept_enclave = accept["enclave"]
    missing_sealed = results["deny-missing-sealed"]
    tampered = results["deny-tampered-sealed"]
    wrong_epoch = results["deny-wrong-epoch"]
    wrong_startup = results["deny-wrong-startup"]
    replay = results["deny-replay-challenge"]
    second = results["deny-second-seal"]
    wrong_measurement = results["deny-wrong-measurement"]

    verdicts = {
        "accept-kas-sealed-release": (
            accept["seal_status"] == 200
            and accept["enclave_exit_status"] == 0
            and accept["enclave_complete"] is True
            and accept_enclave.get("read_ok") == 1
            and accept_enclave.get("key_installed") == 1
            and accept_enclave.get("startup_hash_ok") == 1
            and accept_enclave.get("share_epoch_ok") == 1
            and accept_enclave.get("lease_fresh_ok") == 1
            and accept_enclave.get("content_len") == share["bytes"]
            and accept_enclave.get("content_sha256") == share["sha256"]
            and str(accept_enclave.get("startup_hash")) == str(accept["startup_hash"])
        ),
        "deny-missing-sealed": (
            missing_sealed["seal_status"] == 200
            and missing_sealed["sealed_delivered"] is False
            and _refused(missing_sealed)
            and missing_sealed["enclave"].get("sealed_seen") == 0
        ),
        "deny-tampered-sealed": (
            tampered["seal_status"] == 200
            and _refused(tampered)
            and tampered["enclave"].get("bundle_open_ok") == 0
        ),
        "deny-wrong-epoch": (
            _refused(wrong_epoch)
            and wrong_epoch["enclave"].get("key_installed") == 0
        ),
        "deny-wrong-startup": (
            _refused(wrong_startup)
            and wrong_startup["enclave"].get("startup_hash_ok") == 0
        ),
        "deny-replay-challenge": (
            replay["first_seal_status"] == 200
            and replay["second_seal_status"] in (403, 404, 409)
            and replay["enclave"].get("read_ok") == 1
        ),
        "deny-second-seal": (
            second["first_seal_status"] == 200
            and second["second_seal_status"] == 409
            and second["enclave"].get("read_ok") == 1
        ),
        "deny-wrong-measurement": (
            wrong_measurement["seal_status"] == 403
            and "MRENCLAVE" in str(wrong_measurement.get("detail"))
        ),
        "deny-host-plaintext-in-store": (
            "found_in_store=True" not in substring
            and "plaintext_share_on_host=True" not in substring
        ),
        "deny-host-plaintext-anywhere": not host_scan.get(
            "plaintext_share_found_on_host", True
        ),
    }

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    common = {
        "run_id": args.run_id,
        "phase": "D3-kas-sealed-release",
        "timestamp_utc": timestamp,
        "cloud_region": args.cloud_region,
        "instance_id": args.instance_id,
        "image_id": args.image_id,
    }

    summary = {
        **common,
        "command": "deploy/run_d3_kas_release.sh",
        "enclave_claims": {
            "mrenclave": claims.get("mrenclave"),
            "mrsigner": claims.get("mrsigner"),
            "isvsvn": claims.get("isvsvn"),
            "debug": claims.get("debug"),
            "quote_bytes": claims.get("quote_bytes"),
            "quote_sha256": claims.get("quote_sha256"),
        },
        "packaging": {
            "key_id": packaging.get("key_id"),
            "store_files": packaging.get("store_files", []),
            "plaintext_files": packaging.get("plaintext_files", []),
        },
        "share_bytes": share["bytes"],
        "share_sha256": share["sha256"],
        "cases": results,
        "host_scan_roots": host_scan.get("roots", []),
        "verdicts": verdicts,
        "accepted": all(verdicts.values()),
    }
    write_json(out / "d3-kas-summary.json", summary)
    print(
        json.dumps(
            {"accepted": summary["accepted"], "verdicts": verdicts},
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Collect the D3 Gramine encrypted-FS verdicts from a run directory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

from infra.evidence import write_json


FIELD = re.compile(r"^([a-z_]+)=(-?\d+)$", re.MULTILINE)
HEX_FIELD = re.compile(r"^content_hex=([0-9a-fA-F]*)$", re.MULTILINE)

DENY_CASES = (
    "encfs-deny-missing-key",
    "encfs-deny-wrong-key",
    "encfs-deny-tampered-store",
    "encfs-deny-copied-store",
)


class D3EvidenceError(ValueError):
    """The D3 run is incomplete or a case behaved unexpectedly."""


def parse_probe(text: str) -> dict[str, object]:
    fields = {name: int(value) for name, value in FIELD.findall(text)}
    hex_match = HEX_FIELD.search(text)
    if hex_match:
        prefix = bytes.fromhex(hex_match.group(1))
        fields["content_prefix_bytes"] = len(prefix)
        fields["content_prefix_sha256"] = hashlib.sha256(prefix).hexdigest()
    fields["marker_complete"] = "A1_22_ENCFS_END" in text
    return fields


def _read(path: Path) -> str:
    if not path.is_file():
        raise D3EvidenceError(f"missing D3 evidence file: {path.name}")
    return path.read_text(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance-id", default="unknown")
    parser.add_argument("--cloud-region", default="cn-shanghai")
    parser.add_argument("--image-id", default="unknown")
    args = parser.parse_args(argv)

    out = args.output
    shares = json.loads(_read(out / "shares.json"))
    substring = _read(out / "host-substring-search.txt")
    host_scan = json.loads(_read(out / "host-scan.json"))

    probe_results: dict[str, dict[str, object]] = {}
    for name in ("encfs-accept", *DENY_CASES):
        probe_results[name] = parse_probe(_read(out / f"{name}.txt"))

    accept = probe_results["encfs-accept"]
    verdicts = {
        "accept-encrypted-share": (
            accept.get("read_ok") == 1
            and accept.get("key_installed") == 1
            and accept.get("content_len") == shares["share_bytes"]
            and accept.get("content_prefix_sha256") == shares["share_prefix_sha256"]
            and accept.get("marker_complete") is True
        ),
        "deny-missing-key": probe_results["encfs-deny-missing-key"].get("read_ok") == 0,
        "deny-wrong-key": probe_results["encfs-deny-wrong-key"].get("read_ok") == 0,
        "deny-tampered-store": (
            probe_results["encfs-deny-tampered-store"].get("read_ok") == 0
        ),
        "deny-copied-store": (
            probe_results["encfs-deny-copied-store"].get("read_ok") == 0
        ),
        "deny-host-plaintext-in-store": "found_in_store=True" not in substring,
        "deny-host-plaintext-anywhere": not host_scan.get(
            "plaintext_share_found_on_host", True
        ),
    }

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    common = {
        "run_id": args.run_id,
        "phase": "D3-encfs",
        "timestamp_utc": timestamp,
        "cloud_region": args.cloud_region,
        "instance_id": args.instance_id,
        "image_id": args.image_id,
    }

    for name, fields in probe_results.items():
        write_json(out / f"{name}.json", {**common, "case": name, **fields})

    summary = {
        **common,
        "command": "deploy/run_d3_encfs.sh",
        "share_bytes": shares["share_bytes"],
        "share_sha256": shares["share_sha256"],
        "share_prefix_sha256": shares["share_prefix_sha256"],
        "plan_sha256": shares["plan_sha256"],
        "store_files": shares["store_files"],
        "kdk_sha256": shares["kdk_sha256"],
        "probe_cases": probe_results,
        "host_scan_roots": host_scan.get("roots", []),
        "verdicts": verdicts,
        "accepted": all(verdicts.values()),
    }
    write_json(out / "d3-summary.json", summary)

    print(json.dumps({"accepted": summary["accepted"], "verdicts": verdicts},
                     indent=2, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

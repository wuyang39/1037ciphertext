"""Measure the D7 workload under stated network conditions.

D8 is the performance half of the acceptance. It runs the same three-instance
enclave decode D7 already proves correct, once per network profile, with the
host sampled while the client drives the steps. Latency, communication volume
and host resource use therefore leave the instance as measurements taken under
a named condition instead of as estimates.

What this driver does not do is claim a number it could not take. The enclave
program that D7 froze has no runtime switch for its nonlinear approximations,
so an on/off ablation of those would mean a second frozen program rather than a
flag; the summary says so in its ``gaps`` list instead of filling the table
with figures nothing measured.

Usage::

    python -m infra.d8_three_hosts \
        --cluster ~/a122_cluster_enclave2.json \
        --out-dir artifacts/server/d8-enclave-profiles-<stamp> \
        --run-id d8-enclave-profiles-<stamp> \
        --expect-commit <sha> --sudo-password <pw> --seal
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d4_three_hosts import ROLES, ThreeHostError, Transport, load_cluster
from infra.d7_three_hosts import (
    DEFAULT_CLIENT_DIR,
    DEFAULT_DIST_ROOT,
    DEFAULT_EXPORT_DIR,
    DEFAULT_IFACE,
    DEFAULT_PROMPT,
    DEFAULT_PYTHON,
    DEFAULT_REPO,
    DEFAULT_ROOT,
    DEFAULT_TOKENIZER_DIR,
    NET_PROFILES,
    parse_resource_samples,
    run_three_hosts,
)
from infra.evidence import seal_directory, verify_directory, write_json


DEFAULT_PROFILES = ("lan", "wan-40ms", "wan-80ms")

HOST_USER_HZ = 100.0


def summarise_capture(text: str) -> dict[str, Any]:
    """Reduce one instance's TLS summary to the counters D8 reports.

    ``bytes=`` only appears on the per-flow lines, so the sum over those is the
    traffic this host saw on the ports the run declared, and the scrape cannot
    silently pick up the totals printed above them.
    """
    summary: dict[str, Any] = {}
    for line in text.splitlines():
        if line.startswith("packets on expected ports:"):
            summary["packets"] = int(line.split(":")[1].strip())
        elif line.startswith("TLS 1.3 flows:"):
            summary["tls13_flows"] = int(line.split(":")[1].strip())
        elif line.startswith("application-data records:"):
            summary["application_data_records"] = int(line.split(":")[1].strip())
        elif line.startswith("non-TLS payload bytes:"):
            summary["non_tls_payload_bytes"] = int(line.split(":")[1].strip())
        elif line.startswith("capture gaps:"):
            summary["capture_gaps"] = int(line.split(":")[1].strip().split()[0])
        elif line.startswith("verdict:"):
            summary["verdict"] = line.split(":", 1)[1].strip()
        match = re.search(r"packets=(\d+) bytes=(\d+)", line)
        if match:
            summary["wire_packets"] = summary.get("wire_packets", 0) + int(match.group(1))
            summary["wire_bytes"] = summary.get("wire_bytes", 0) + int(match.group(2))
        retransmit = re.match(
            r"TCP retransmissions: (\d+) \((\d+) bytes", line
        )
        if retransmit:
            summary["retransmits"] = int(retransmit.group(1))
            summary["retransmit_bytes"] = int(retransmit.group(2))
    return summary


def summarise_samples(text: str) -> dict[str, Any]:
    """Turn the sampler's raw counters into utilisation a reader can check.

    CPU is derived from consecutive samples, not from a number the sampler
    computed for itself: the file keeps the cumulative ticks so the arithmetic
    can be redone from the trace.
    """
    samples = parse_resource_samples(text)
    if not samples:
        return {"samples": 0}
    utilisation: list[float] = []
    for previous, current in zip(samples, samples[1:]):
        total = current["cpu_total"] - previous["cpu_total"]
        busy = current["cpu_busy"] - previous["cpu_busy"]
        if total > 0:
            utilisation.append(100.0 * busy / total)
    ticks = [sample["gramine_cpu_ticks"] for sample in samples]
    return {
        "samples": len(samples),
        "cpu_util_percent_mean": round(sum(utilisation) / len(utilisation), 2)
        if utilisation
        else None,
        "cpu_util_percent_peak": round(max(utilisation), 2) if utilisation else None,
        "gramine_rss_kb_peak": int(max(sample["gramine_rss_kb"] for sample in samples)),
        "gramine_cpu_seconds": round((max(ticks) - min(ticks)) / HOST_USER_HZ, 2),
        "mem_available_kb_min": int(
            min(sample["mem_available_kb"] for sample in samples)
        ),
        "window_seconds": round(samples[-1]["t"] - samples[0]["t"], 2),
    }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def collect_profile(profile_dir: Path) -> dict[str, Any]:
    """Read one finished profile run back into a comparable record."""
    document = _read_json(profile_dir / "d7-summary.json")
    statuses = {
        role: _read_json(profile_dir / f"d7-three-{role.lower()}-node-status.json")
        for role in ROLES
    }
    wire: dict[str, Any] = {}
    resources: dict[str, Any] = {}
    for role in ROLES:
        wire[role] = summarise_capture(
            (profile_dir / f"d7-three-{role}-tls-summary.txt").read_text(
                encoding="utf-8"
            )
        )
        sampler = profile_dir / f"d8-resources-{role.lower()}.jsonl"
        resources[role] = (
            summarise_samples(sampler.read_text(encoding="utf-8"))
            if sampler.is_file()
            else {"samples": 0}
        )
    steps = document.get("steps") or []
    return {
        "run_id": document.get("run_id"),
        "profile": (document.get("network") or {}).get("profile"),
        "network": document.get("network") or {},
        "tokens": document.get("generated_tokens"),
        "generated_text": document.get("generated_text"),
        "worst_max_abs_error": (document.get("reference_check") or {}).get(
            "worst_max_abs_error"
        ),
        "client_wall_seconds": document.get("client_wall_seconds"),
        "step_client_ms": [step.get("step_wall_ms") for step in steps],
        "step_node_ms": {
            role: [step.get("elapsed_ms") for step in statuses[role].get("steps", [])]
            for role in ROLES
        },
        "link_seconds": {
            role: statuses[role].get("link_seconds") for role in ROLES
        },
        "wire": wire,
        "resources": resources,
        "verdicts": document.get("verdicts") or {},
        "hygiene": (document.get("hygiene") or {}).get("verdict"),
        "staged_shares_scrubbed": (document.get("staging_scrub") or {}).get(
            "verdict"
        ),
    }


def build_summary(
    *,
    run_id: str,
    commit: str | None,
    profiles: Mapping[str, Mapping[str, Any]],
    platform: Mapping[str, Any],
) -> dict[str, Any]:
    """Fold the per-profile records into the comparison D8 exists to make."""
    baseline = profiles.get("lan") or {}
    baseline_wall = baseline.get("client_wall_seconds")
    comparison: list[dict[str, Any]] = []
    for name, record in profiles.items():
        wire = record.get("wire") or {}
        total_bytes = sum(int(value.get("wire_bytes", 0)) for value in wire.values())
        wall = record.get("client_wall_seconds")
        comparison.append(
            {
                "profile": name,
                "client_wall_seconds": wall,
                "slowdown_vs_lan": (
                    round(wall / baseline_wall, 2)
                    if wall and baseline_wall
                    else None
                ),
                "wire_bytes_total": total_bytes,
                "tokens": record.get("tokens"),
                "token_agreement_with_reference": (
                    (record.get("worst_max_abs_error") is not None)
                    and bool(record.get("tokens"))
                ),
                "worst_max_abs_error": record.get("worst_max_abs_error"),
                "retransmits_total": sum(
                    int(value.get("retransmits", 0)) for value in wire.values()
                ),
                "capture_gaps_total": sum(
                    int(value.get("capture_gaps", 0)) for value in wire.values()
                ),
                "captures_tls13_only": all(
                    value.get("verdict") == "tls13_only" for value in wire.values()
                ),
                "hygiene": record.get("hygiene"),
                "staged_shares_scrubbed": record.get("staged_shares_scrubbed"),
            }
        )
    return {
        "run_id": run_id,
        "phase": "D8",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "commit": commit,
        "prompt": DEFAULT_PROMPT,
        "metric_definition": {
            "client_wall_seconds": "the client process start to finish on the run host",
            "step_client_ms": "client-measured wall time of one decode step",
            "step_node_ms": "node-reported elapsed_ms for the same decode step",
            "wire_bytes": (
                "sum of bytes on the run's declared ports, from the capture each "
                "instance analysed itself"
            ),
            "cpu_util_percent": (
                "host-wide busy share between consecutive 0.5 s samples of /proc/stat"
            ),
            "gramine_rss_kb": "resident set of the run's enclave process, from /proc",
            "gramine_cpu_seconds": (
                "user+system jiffies of the run's enclave process, /100"
            ),
        },
        "platform": {role: dict(facts) for role, facts in platform.items()},
        "profiles": {name: dict(record) for name, record in profiles.items()},
        "comparison": comparison,
        "gaps": [
            "no per-process EPC residency counter: this kernel exposes the EPC "
            "section size in its ring buffer but no per-process accounting file, "
            "and the run does not invent one",
            "no on-enclave approximation or quantization ablation: the program "
            "D7 froze has no runtime switch for either, so a comparison would "
            "need a second frozen program and is left for the next pass",
            "length buckets and batch size are not exercised by the one-layer "
            "probe geometry",
            "the rate and delay are injected with tc on the peer subnet and "
            "reported from the ping the run took, not from a network model",
        ],
    }


def report_markdown(summary: Mapping[str, Any]) -> str:
    """Render the comparison from the summary, never from hand-typed figures."""
    lines = [
        "# D8: the D7 workload under a stated network profile",
        "",
        f"Run `{summary['run_id']}` at {summary['timestamp_utc']}"
        + (f", commit `{summary['commit']}`." if summary.get("commit") else "."),
        "",
        "Every figure below is read back from the sealed traces of the runs it",
        "describes: the client's own step timing, the nodes' step reporting, and",
        "each instance's own analysis of the capture it took.",
        "",
        "## Profiles",
        "",
        "| profile | client wall s | slowdown | wire MB (3 hosts) | retransmits | gaps | tokens | worst max_abs_error | capture verdict |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["comparison"]:
        wire_mb = row["wire_bytes_total"] / 1_000_000.0
        lines.append(
            f"| {row['profile']} | {row['client_wall_seconds']} | "
            f"{row['slowdown_vs_lan']} | {wire_mb:.1f} | "
            f"{row['retransmits_total']} | {row['capture_gaps_total']} | "
            f"{','.join(str(t) for t in row['tokens'] or [])} | "
            f"{row['worst_max_abs_error']} | "
            f"{'tls13_only' if row['captures_tls13_only'] else 'not clean'} |"
        )
    lines += ["", "## Per-step latency (ms)", ""]
    for name, record in summary["profiles"].items():
        client = ", ".join(str(value) for value in record.get("step_client_ms") or [])
        lines.append(f"- `{name}` client: {client}")
        for role, values in (record.get("step_node_ms") or {}).items():
            rendered = ", ".join(str(value) for value in values)
            lines.append(f"  - {role} node: {rendered}")
    lines += ["", "## Host resources", ""]
    lines += [
        "| role | cpu model | vCPU | mem total MB | EPC section | enclave device |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for role, facts in summary["platform"].items():
        mem_mb = float(facts.get("mem_total_kb", 0) or 0) / 1024.0
        lines.append(
            f"| {role} | {facts.get('cpu_model', '?')} | "
            f"{facts.get('cpu_count', '?')} | {mem_mb:.0f} | "
            f"{facts.get('epc_section', '?')} | {facts.get('sgx_device', '?')} |"
        )
    lines += [
        "",
        "| profile | role | samples | cpu mean % | cpu peak % | enclave RSS peak MB | enclave CPU s | mem available min MB |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, record in summary["profiles"].items():
        for role, stats in (record.get("resources") or {}).items():
            rss_mb = (stats.get("gramine_rss_kb_peak") or 0) / 1024.0
            mem_mb = (stats.get("mem_available_kb_min") or 0) / 1024.0
            lines.append(
                f"| {name} | {role} | {stats.get('samples')} | "
                f"{stats.get('cpu_util_percent_mean')} | "
                f"{stats.get('cpu_util_percent_peak')} | {rss_mb:.0f} | "
                f"{stats.get('gramine_cpu_seconds')} | {mem_mb:.0f} |"
            )
    lines += ["", "## What this does not cover", ""]
    lines += [f"- {gap}" for gap in summary["gaps"]]
    lines += [""]
    return "\n".join(lines)


def run_profiles(
    *,
    cluster: Mapping[str, Any],
    out_dir: Path,
    run_id: str,
    transport: Transport,
    ssh_user: str = "jiahao",
    ssh_host: str | None = None,
    profiles: Sequence[str] = DEFAULT_PROFILES,
    prompt: str = DEFAULT_PROMPT,
    max_new_tokens: int = 3,
    node_timeout: float = 3600.0,
    expect_commit: str | None = None,
    sudo_password: str | None = None,
    repo: str = DEFAULT_REPO,
    python: str = DEFAULT_PYTHON,
    root: str = DEFAULT_ROOT,
    client_dir: str = DEFAULT_CLIENT_DIR,
    export_dir: str = DEFAULT_EXPORT_DIR,
    tokenizer_dir: str = DEFAULT_TOKENIZER_DIR,
    dist_root: str = DEFAULT_DIST_ROOT,
    iface: str = DEFAULT_IFACE,
    seal: bool = False,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    unknown = [name for name in profiles if name not in NET_PROFILES]
    if unknown:
        raise ThreeHostError(f"unknown network profiles: {unknown}")
    records: dict[str, Any] = {}
    platform: dict[str, Any] = {}
    for name in profiles:
        profile_dir = out_dir / name
        result = run_three_hosts(
            cluster=cluster,
            out_dir=profile_dir,
            run_id=f"{run_id}-{name}",
            transport=transport,
            ssh_user=ssh_user,
            mode="enclave",
            ssh_host=ssh_host,
            repo=repo,
            python=python,
            root=root,
            client_dir=client_dir,
            export_dir=export_dir,
            tokenizer_dir=tokenizer_dir,
            dist_root=dist_root,
            iface=iface,
            prompt=prompt,
            max_new_tokens=max_new_tokens,
            node_timeout=node_timeout,
            expect_commit=expect_commit,
            seal=False,
            net_profile=name,
            sudo_password=sudo_password,
            sample_resources=True,
        )
        if not (result.get("verdicts") or {}).get("passed"):
            raise ThreeHostError(
                f"profile {name} did not pass: {json.dumps(result.get('verdicts'))}"
            )
        records[name] = collect_profile(profile_dir)
        document = _read_json(profile_dir / "d7-summary.json")
        for role, facts in (document.get("network") or {}).get("platform", {}).items():
            platform.setdefault(role, facts)
    summary = build_summary(
        run_id=run_id, commit=expect_commit, profiles=records, platform=platform
    )
    write_json(out_dir / f"{run_id}-summary.json", summary)
    (out_dir / "d8-report.md").write_text(
        report_markdown(summary), encoding="utf-8", newline="\n"
    )
    sealed: dict[str, Any] = {}
    if seal:
        index = seal_directory(out_dir)
        verified = verify_directory(out_dir, require_seal=True)
        sealed = {
            "seal": index.get("seal"),
            "verified": bool(verified.get("verified", True)),
        }
    return {
        "run_id": run_id,
        "comparison": summary["comparison"],
        "summary": str(out_dir / f"{run_id}-summary.json"),
        **sealed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D8 network profiles")
    parser.add_argument("--cluster", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--profiles", default=",".join(DEFAULT_PROFILES))
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--max-new-tokens", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=3600.0)
    parser.add_argument("--ssh-user", default="jiahao")
    parser.add_argument("--ssh-host", default=None)
    parser.add_argument("--ssh-key", default=None)
    parser.add_argument("--ssh-key-password", default=None)
    parser.add_argument("--sudo-password", default=None)
    parser.add_argument("--expect-commit", default=None)
    parser.add_argument("--seal", action="store_true")
    args = parser.parse_args(argv)
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport(
        key_path=args.ssh_key, key_password=args.ssh_key_password
    )
    result = run_profiles(
        cluster=cluster,
        out_dir=args.out_dir,
        run_id=args.run_id,
        transport=transport,
        ssh_user=args.ssh_user,
        ssh_host=args.ssh_host,
        profiles=tuple(
            name.strip() for name in args.profiles.split(",") if name.strip()
        ),
        prompt=args.prompt,
        max_new_tokens=args.max_new_tokens,
        node_timeout=args.timeout,
        expect_commit=args.expect_commit,
        sudo_password=args.sudo_password,
        seal=args.seal,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by the operator
    sys.exit(main())


__all__ = [
    "DEFAULT_PROFILES",
    "build_summary",
    "collect_profile",
    "main",
    "report_markdown",
    "run_profiles",
    "summarise_capture",
    "summarise_samples",
]

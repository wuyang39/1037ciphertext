"""Run the same D7 workload under controlled runtime variants, and compare.

The acceptance gate for D8 asks for a same-condition comparison of each
optimization it reports. The network profiles live in
:mod:`infra.d8_three_hosts`; this module is the other half: the *program and
runtime* is held fixed and one named knob is moved at a time.

Two kinds of arm exist, and both are real switches on the shipping stack
rather than a second program:

* a **fixed-point width** arm. The calibrated export picks one width for the
  session, and an arm pins another one. Everything the shares were split from
  is unchanged, so the arm measures what narrowing the MPC fixed point does to
  the logits, the tokens and the wall time;
* an **approximation** arm. SPU keeps its nonlinear operators behind named
  runtime switches -- ``fxp_exp_iters`` for the softmax exponential,
  ``fxp_div_goldschmidt_iters`` for the division that normalizes it,
  ``enable_lower_accuracy_rsqrt`` for the LayerNorm root. An arm turns them
  down and nothing else moves.

What this driver will not do is report an arm it could not take. Each node
echoes the runtime it actually opened with, and the summary compares that echo
against the arm that was asked for; an arm whose settings did not land fails
the run instead of appearing in the table as a measurement.

Usage::

    python -m infra.d8_ablation \
        --cluster ~/a122_cluster_enclave2.json \
        --out-dir artifacts/server/d8-ablations-<stamp> \
        --run-id d8-ablations-<stamp> --expect-commit <sha> --seal
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
    READY_MARKER,
    run_three_hosts,
)
from infra.d8_three_hosts import summarise_capture
from infra.evidence import SEAL_NAME, seal_directory, verify_directory, write_json


README = "README.md"
REPORT = "d8-ablation-report.md"

# The shipped configuration is the control; every other arm moves exactly one
# thing. ``baseline-repeat`` is the same control taken twice, so a reader can
# see the run-to-run spread before reading anything into a difference.
DEFAULT_ARMS: tuple[dict[str, Any], ...] = (
    {
        "name": "baseline",
        "fractional_bits": None,
        "options": {},
        "description": "the accepted configuration: calibrated width, default approximations",
    },
    {
        "name": "baseline-repeat",
        "fractional_bits": None,
        "options": {},
        "description": "the same configuration again, for the run-to-run spread",
    },
    {
        "name": "approx-low",
        "fractional_bits": None,
        "options": {
            "fxp_exp_iters": 2,
            "fxp_div_goldschmidt_iters": 1,
            "enable_lower_accuracy_rsqrt": True,
        },
        "description": (
            "softmax exponential and division and the LayerNorm root at "
            "reduced iteration counts"
        ),
    },
    {
        "name": "fxp-12",
        "fractional_bits": 12,
        "options": {},
        "description": "the calibrated fixed-point width narrowed from 18 to 12",
    },
)

READY_LINE = re.compile(r"A122-D7-NODE-READY (\{.*\})")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def node_runtime(text: str) -> dict[str, Any]:
    """The runtime one node said it opened with, from its own ready line."""
    for line in text.splitlines():
        match = READY_LINE.search(line)
        if match:
            document = json.loads(match.group(1))
            return dict(document.get("runtime") or {})
    return {}


def collect_arm(arm_dir: Path) -> dict[str, Any]:
    """Read one finished arm back into a comparable record."""
    document = _read_json(arm_dir / "d7-summary.json")
    result = _read_json(arm_dir / "d7-client-result.json")
    statuses = {
        role: _read_json(arm_dir / f"d7-three-{role.lower()}-node-status.json")
        for role in ROLES
    }
    wire: dict[str, Any] = {}
    for role in ROLES:
        wire[role] = summarise_capture(
            (arm_dir / f"d7-three-{role}-tls-summary.txt").read_text(
                encoding="utf-8"
            )
        )
    runtimes = {
        role: node_runtime(
            (arm_dir / f"d7-three-{role.lower()}-node.log").read_text(
                encoding="utf-8"
            )
        )
        for role in ROLES
    }
    checks = (result.get("reference_check") or {}).get("steps") or []
    return {
        "run_id": document.get("run_id"),
        "model": document.get("model"),
        "declared_arm": document.get("runtime") or {},
        "client_runtime": result.get("runtime") or {},
        "node_runtime": runtimes,
        "tokens": document.get("generated_tokens"),
        "generated_text": document.get("generated_text"),
        "client_wall_seconds": document.get("client_wall_seconds"),
        "step_client_ms": [
            step.get("step_wall_ms") for step in document.get("steps") or []
        ],
        "step_node_ms": {
            role: [step.get("elapsed_ms") for step in statuses[role].get("steps", [])]
            for role in ROLES
        },
        "worst_max_abs_error": (result.get("reference_check") or {}).get(
            "worst_max_abs_error"
        ),
        "mean_abs_error_worst": max(
            (check.get("mean_abs_error") or 0.0 for check in checks), default=None
        ),
        "step_max_abs_error": [
            check.get("max_abs_error") for check in checks
        ],
        "token_agreement": (result.get("reference_check") or {}).get(
            "token_agreement"
        ),
        "argmax_agreement": (result.get("reference_check") or {}).get(
            "argmax_agreement"
        ),
        "wire": wire,
        "verdicts": document.get("verdicts") or {},
        "hygiene": (document.get("hygiene") or {}).get("verdict"),
        "staged_shares_scrubbed": (document.get("staging_scrub") or {}).get(
            "verdict"
        ),
    }


def _arm_expectation(arm: Mapping[str, Any]) -> tuple[int | None, dict[str, Any]]:
    return (
        arm.get("fractional_bits"),
        dict(arm.get("options") or {}),
    )


def arm_checks(arm: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    """Compare the arm that was asked for against the runtimes that opened.

    The comparison is the point of the summary: an arm whose switches did not
    reach the nodes would otherwise be read as "this knob changes nothing".
    """
    want_bits, want_options = _arm_expectation(arm)
    client = record.get("client_runtime") or {}
    problems: list[str] = []
    if not client:
        problems.append("the client recorded no runtime")
    else:
        if want_bits is not None and int(client.get("fractional_bits", -1)) != int(
            want_bits
        ):
            problems.append(
                f"the client ran at {client.get('fractional_bits')} bits, "
                f"the arm asked for {want_bits}"
            )
        for name, value in sorted(want_options.items()):
            if client.get("options", {}).get(name) != value:
                problems.append(
                    f"the client did not carry {name}={value} "
                    f"(it carried {client.get('options', {}).get(name)!r})"
                )
    for role, runtime in sorted((record.get("node_runtime") or {}).items()):
        if not runtime:
            problems.append(f"{role} did not echo the runtime it opened with")
            continue
        if want_bits is not None and int(runtime.get("fraction_bits", -1)) != int(
            want_bits
        ):
            problems.append(
                f"{role} opened at {runtime.get('fraction_bits')} bits, "
                f"the arm asked for {want_bits}"
            )
        for name, value in sorted(want_options.items()):
            if runtime.get("options", {}).get(name) != value:
                problems.append(
                    f"{role} did not open with {name}={value} "
                    f"(it opened with {runtime.get('options', {}).get(name)!r})"
                )
    return {"arm_landed": not problems, "problems": problems}


def build_summary(
    *,
    run_id: str,
    commit: str | None,
    arms: Sequence[Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Any]],
    timestamp_utc: str | None = None,
) -> dict[str, Any]:
    """Fold the per-arm records into the comparison this run exists to make."""
    control = records.get("baseline") or {}
    control_wall = control.get("client_wall_seconds")
    control_error = control.get("worst_max_abs_error")
    comparison: list[dict[str, Any]] = []
    for arm in arms:
        name = str(arm["name"])
        record = records.get(name) or {}
        checks = arm_checks(arm, record)
        wire = record.get("wire") or {}
        wall = record.get("client_wall_seconds")
        error = record.get("worst_max_abs_error")
        comparison.append(
            {
                "arm": name,
                "description": arm.get("description"),
                "fractional_bits": (
                    arm.get("fractional_bits")
                    if arm.get("fractional_bits") is not None
                    else (record.get("client_runtime") or {}).get("fractional_bits")
                ),
                "options": dict(arm.get("options") or {}),
                "client_wall_seconds": wall,
                "slowdown_vs_control": (
                    round(wall / control_wall, 4)
                    if wall and control_wall
                    else None
                ),
                "wire_bytes_total": sum(
                    int(value.get("wire_bytes", 0)) for value in wire.values()
                ),
                "retransmits_total": sum(
                    int(value.get("retransmits", 0)) for value in wire.values()
                ),
                "capture_gaps_total": sum(
                    int(value.get("capture_gaps", 0)) for value in wire.values()
                ),
                "captures_tls13_only": all(
                    value.get("verdict") == "tls13_only" for value in wire.values()
                ),
                "tokens": record.get("tokens"),
                "generated_text": record.get("generated_text"),
                "worst_max_abs_error": error,
                "error_ratio_vs_control": (
                    round(error / control_error, 4) if error and control_error else None
                ),
                "token_agreement": record.get("token_agreement"),
                "argmax_agreement": record.get("argmax_agreement"),
                "hygiene": record.get("hygiene"),
                "staged_shares_scrubbed": record.get("staged_shares_scrubbed"),
                "arm_landed": checks["arm_landed"],
                "arm_problems": checks["problems"],
            }
        )
    return {
        "run_id": run_id,
        "phase": "D8-ablation",
        "timestamp_utc": timestamp_utc
        or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit,
        "prompt": DEFAULT_PROMPT,
        "network": "lan (nothing injected; every arm runs unshaped)",
        "metric_definition": {
            "client_wall_seconds": "the client process start to finish on the run host",
            "step_client_ms": "client-measured wall time of one decode step",
            "wire_bytes": (
                "sum of bytes on the run's declared ports, from the capture each "
                "instance analysed itself"
            ),
            "worst_max_abs_error": (
                "largest per-step |secure logits - float64 reference| over the "
                "candidate columns"
            ),
            "fractional_bits": (
                "the fixed-point width the session was pinned to; the export's "
                "calibrated width is 18"
            ),
        },
        "arms": {name: dict(record) for name, record in records.items()},
        "comparison": comparison,
        "gaps": [
            "one run per arm: the spread of a single take is not separated "
            "except by the repeated control arm",
            "the nonlinear arms move the SPU runtime's own approximation "
            "switches; an arm that replaces the emitted MHLO operators with a "
            "different polynomial is still a second frozen program and is not "
            "in this table",
            "no per-process EPC residency counter exists on this kernel, so "
            "the arms are compared on time, traffic and fidelity only",
            "length buckets and batch size are not exercised by the one-layer "
            "probe geometry",
        ],
    }


def _cell(value: Any) -> str:
    return "-" if value is None else str(value)


def report_markdown(summary: Mapping[str, Any]) -> str:
    """Render the arm comparison from the summary, never from typed figures."""
    lines = [
        "# D8 ablation: the same D7 workload under controlled runtime arms",
        "",
        f"Run `{summary['run_id']}`: arms recorded through "
        f"{summary['timestamp_utc']}"
        + (f", commit `{summary['commit']}`." if summary.get("commit") else "."),
        "",
        "Every arm is the D7 program, the D7 shares and the D7 geometry. Only",
        "the fixed-point width or the named SPU approximation switches differ,",
        "and nothing is injected into the network, so the arms are compared",
        "under identical conditions.",
        "",
        "| arm | what moved | client wall s | vs control | worst max_abs_error | vs control | tokens | token agreement | wire MB (3 hosts) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["comparison"]:
        moved = (
            f"fxp {row['fractional_bits']}"
            if row["options"] == {} and row["fractional_bits"] is not None
            else ", ".join(f"{k}={v}" for k, v in sorted(row["options"].items()))
            or "nothing (control)"
        )
        lines.append(
            f"| `{row['arm']}` | {moved} | {row['client_wall_seconds']} | "
            f"{_cell(row['slowdown_vs_control'])} | {row['worst_max_abs_error']} | "
            f"{_cell(row['error_ratio_vs_control'])} | "
            f"{','.join(str(t) for t in row['tokens'] or [])} | "
            f"{row['token_agreement']} | "
            f"{row['wire_bytes_total'] / 1_000_000.0:.1f} |"
        )
    lines += ["", "## Per-step latency (ms)", ""]
    for name, record in summary["arms"].items():
        client = ", ".join(
            str(value) for value in record.get("step_client_ms") or []
        )
        lines.append(f"- `{name}` client: {client}")
        for role, values in (record.get("step_node_ms") or {}).items():
            lines.append(
                f"  - {role} node: " + ", ".join(str(v) for v in values)
            )
    lines += [
        "",
        "## Per-step fidelity",
        "",
        "| arm | step 1 | step 2 | step 3 | worst mean_abs_error |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, record in summary["arms"].items():
        errors = [str(value) for value in record.get("step_max_abs_error") or []]
        while len(errors) < 3:
            errors.append("-")
        lines.append(
            f"| `{name}` | {errors[0]} | {errors[1]} | {errors[2]} | "
            f"{record.get('mean_abs_error_worst')} |"
        )
    lines += [
        "",
        "## Did each arm land?",
        "",
        "Each node echoes the runtime it opened with on its ready line, and the",
        "client records the one it was built with. An arm whose settings did not",
        "reach all four processes is listed here as a failure rather than",
        "counted as a measurement.",
        "",
        "| arm | landed | problems |",
        "| --- | --- | --- |",
    ]
    for row in summary["comparison"]:
        lines.append(
            f"| `{row['arm']}` | `{row['arm_landed']}` | "
            f"{'; '.join(row['arm_problems']) or '-'} |"
        )
    lines += [
        "",
        "## Verdicts",
        "",
        "| arm | hygiene | shares scrubbed | captures |",
        "| --- | --- | --- | --- |",
    ]
    for row in summary["comparison"]:
        lines.append(
            f"| `{row['arm']}` | {row['hygiene']} | "
            f"{row['staged_shares_scrubbed']} | "
            f"{'tls13_only' if row['captures_tls13_only'] else 'not clean'} |"
        )
    lines += ["", "## What this does not cover", ""]
    lines += [f"- {gap}" for gap in summary["gaps"]]
    lines += [""]
    return "\n".join(lines)


def _readme(summary: Mapping[str, Any]) -> str:
    """Describe the bundle from the summary, so the README is not hand-typed."""
    lines = [
        "# D8 ablation: runtime arms over one fixed program",
        "",
        f"Run `{summary['run_id']}`: arms recorded through "
        f"{summary['timestamp_utc']}"
        + (f", commit `{summary['commit']}`." if summary.get("commit") else "."),
        "",
        "## What ran",
        "",
    ]
    arms = summary.get("arms", {})
    geometry: Mapping[str, Any] = {}
    # The control arm describes the geometry every arm shares; an ablation arm
    # that moved the fixed-point width would otherwise be read as the model.
    for name in ("baseline", *sorted(arms)):
        record = arms.get(name) or {}
        if record.get("model"):
            geometry = record["model"]
            break
    if geometry:
        lines += [
            f"- Model: `{geometry.get('model_version')}` "
            f"(model hash `{geometry.get('model_hash')}`)",
            f"- Blocks stacked: {geometry.get('layers')}, candidate vocabulary: "
            f"{geometry.get('vocab_size')} ids, fixed-point width "
            f"{geometry.get('fractional_bits')} bits for the control arm",
        ]
    lines += [
        f"- Prompt: `{summary.get('prompt')}`",
        f"- Network: {summary.get('network')}",
        "- Arms: " + ", ".join(f"`{name}`" for name in sorted(summary.get("arms", {}))),
        "",
        "Each arm is a full three-instance enclave run: staging, the SPU link,",
        "three tokens, the five negative probes, the close and the scrub. The",
        "difference between arms is one runtime setting, so a difference in the",
        "table is that setting and not a different experiment.",
        "",
        "## The arms",
        "",
    ]
    for row in summary.get("comparison") or []:
        lines.append(f"- `{row['arm']}`: {row['description']}")
    lines += ["", "## What this does not cover", ""]
    lines += [f"- {gap}" for gap in summary.get("gaps") or []]
    lines += [""]
    return "\n".join(lines)


def _write_bundle(
    out_dir: Path,
    *,
    run_id: str,
    commit: str | None,
    arms: Sequence[Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Any]],
    seal: bool,
    timestamp_utc: str | None = None,
) -> dict[str, Any]:
    summary = build_summary(
        run_id=run_id,
        commit=commit,
        arms=arms,
        records=records,
        timestamp_utc=timestamp_utc,
    )
    write_json(out_dir / f"{run_id}-summary.json", summary)
    (out_dir / REPORT).write_text(report_markdown(summary), encoding="utf-8", newline="\n")
    (out_dir / README).write_text(_readme(summary), encoding="utf-8", newline="\n")
    sealed: dict[str, Any] = {}
    if seal:
        index = seal_directory(out_dir)
        verified = verify_directory(out_dir, require_seal=True)
        sealed = {
            # The detached seal is the digest of the index file, so it is read
            # back from the file the seal wrote rather than from the index.
            "seal_sha256": (out_dir / SEAL_NAME).read_text(encoding="utf-8").split()[0],
            "verified": bool(verified.get("verified", True)),
        }
    landed = all(row["arm_landed"] for row in summary["comparison"])
    return {
        "run_id": run_id,
        "comparison": summary["comparison"],
        "all_arms_landed": landed,
        "summary": str(out_dir / f"{run_id}-summary.json"),
        "report": str(out_dir / REPORT),
        **sealed,
    }


def rebuild_summary(
    out_dir: Path,
    *,
    run_id: str | None = None,
    commit: str | None = None,
    arms: Sequence[Mapping[str, Any]] | None = None,
    seal: bool = False,
) -> dict[str, Any]:
    """Re-derive the summary and report from arm directories already on disk."""
    out_dir = Path(out_dir)
    run_id = run_id or out_dir.name
    arms = tuple(arms or DEFAULT_ARMS)
    records: dict[str, Any] = {}
    stamps: list[str] = []
    for arm in arms:
        name = str(arm["name"])
        arm_dir = out_dir / name
        if not (arm_dir / "d7-summary.json").is_file():
            raise ThreeHostError(f"arm {name!r} has no trace under {arm_dir}")
        document = _read_json(arm_dir / "d7-summary.json")
        recorded = document.get("commit")
        if commit is not None and recorded and recorded != commit:
            raise ThreeHostError(
                f"{name}: the traces record commit {recorded}, not the "
                f"{commit} this rebuild was told to expect"
            )
        if commit is None:
            commit = recorded
        records[name] = collect_arm(arm_dir)
        if document.get("timestamp_utc"):
            stamps.append(str(document["timestamp_utc"]))
    return _write_bundle(
        out_dir,
        run_id=run_id,
        commit=commit,
        arms=arms,
        records=records,
        seal=seal,
        timestamp_utc=max(stamps) if stamps else None,
    )


def run_arms(
    *,
    cluster: Mapping[str, Any],
    out_dir: Path,
    run_id: str,
    transport: Transport,
    arms: Sequence[Mapping[str, Any]] = DEFAULT_ARMS,
    ssh_user: str = "jiahao",
    ssh_host: str | None = None,
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
    skip_existing: bool = False,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records: dict[str, Any] = {}
    for arm in arms:
        name = str(arm["name"])
        arm_dir = out_dir / name
        # An arm that already finished is not taken again: a pass that is
        # interrupted part way through resumes on the arm it had not reached
        # instead of repeating the ones it had.
        if skip_existing and (arm_dir / "d7-summary.json").is_file():
            records[name] = collect_arm(arm_dir)
            continue
        result = run_three_hosts(
            cluster=cluster,
            out_dir=arm_dir,
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
            net_profile="lan",
            sudo_password=sudo_password,
            sample_resources=True,
            fractional_bits=arm.get("fractional_bits"),
            runtime_options=arm.get("options"),
        )
        # An arm is allowed to disagree with the float reference -- that is a
        # result about the knob. What it may not do is fail a security gate:
        # refused negatives, a dirty hygiene scan, an unscrubbed staging tree
        # or nodes that never came off the link all invalidate the run.
        verdicts = result.get("verdicts") or {}
        security = {
            key: bool(verdicts.get(key))
            for key in (
                "two_tokens_generated",
                "negatives_refused",
                "nodes_released",
                "hygiene_clean",
                "staged_shares_scrubbed",
            )
        }
        if not all(security.values()):
            raise ThreeHostError(
                f"arm {name} did not clear its security verdicts: "
                f"{json.dumps(security)}"
            )
        records[name] = collect_arm(arm_dir)
    bundle = _write_bundle(
        out_dir,
        run_id=run_id,
        commit=expect_commit,
        arms=arms,
        records=records,
        seal=seal,
    )
    if not bundle["all_arms_landed"]:
        raise ThreeHostError(
            "an arm did not reach every process; the run is not a comparison"
        )
    return bundle


def _parse_arms(document: str | None) -> tuple[dict[str, Any], ...]:
    if not document:
        return DEFAULT_ARMS
    raw = json.loads(document)
    if not isinstance(raw, list):
        raise ThreeHostError("--arms must be a JSON list of arm objects")
    arms: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict) or "name" not in entry:
            raise ThreeHostError("every arm needs a name")
        arms.append(
            {
                "name": str(entry["name"]),
                "fractional_bits": entry.get("fractional_bits"),
                "options": dict(entry.get("options") or {}),
                "description": entry.get("description"),
            }
        )
    return tuple(arms)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D8 runtime ablation")
    parser.add_argument("--cluster", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--arms",
        default=None,
        help="JSON list of {name, fractional_bits, options, description}",
    )
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--max-new-tokens", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=3600.0)
    parser.add_argument("--ssh-user", default="jiahao")
    parser.add_argument("--ssh-host", default=None)
    parser.add_argument("--ssh-key", default=None)
    parser.add_argument("--ssh-key-password", default=None)
    parser.add_argument("--sudo-password", default=None)
    parser.add_argument("--expect-commit", default=None)
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="re-derive the summary and report from the arm directories already "
        "under --out-dir instead of running anything",
    )
    parser.add_argument("--seal", action="store_true")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="reuse an arm whose trace is already under --out-dir",
    )
    args = parser.parse_args(argv)
    arms = _parse_arms(args.arms)
    if args.rebuild:
        result = rebuild_summary(
            args.out_dir,
            run_id=args.run_id,
            commit=args.expect_commit,
            arms=arms,
            seal=args.seal,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.cluster is None:
        parser.error("--cluster is required unless --rebuild is given")
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport(key_path=args.ssh_key, key_password=args.ssh_key_password)
    result = run_arms(
        cluster=cluster,
        out_dir=args.out_dir,
        run_id=args.run_id,
        transport=transport,
        arms=arms,
        ssh_user=args.ssh_user,
        ssh_host=args.ssh_host,
        prompt=args.prompt,
        max_new_tokens=args.max_new_tokens,
        node_timeout=args.timeout,
        expect_commit=args.expect_commit,
        sudo_password=args.sudo_password,
        seal=args.seal,
        skip_existing=args.skip_existing,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by the operator
    sys.exit(main())


__all__ = [
    "DEFAULT_ARMS",
    "arm_checks",
    "build_summary",
    "collect_arm",
    "main",
    "node_runtime",
    "rebuild_summary",
    "report_markdown",
    "run_arms",
]

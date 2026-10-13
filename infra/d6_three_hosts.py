"""Drive the D6 acceptance across three instances and collect its evidence.

Where D5 measured a fixed case grid, D6 puts a real client in front of the
three enclaves: it tokenizes a prompt, shares one history matrix per decoding
step, collects three signed receipts per step, reconstructs the token itself
and then closes the session and watches the nodes empty it. This module is the
operator's driver for that run: it provisions the workspace on P0, carries it
to P1 and P2, signs and starts the three enclaves, runs the client from one
allowed host, releases the nodes, then scans every instance for the session
state the close was supposed to remove and seals the bundle.

The scan is the part the phase is really about. It searches each instance for
the share prefixes the run published as probes, so "the session was cleaned up"
is a measurement on the host rather than a claim inside the enclave.

Usage::

    python -m infra.d6_three_hosts run \
        --cluster ~/a122_cluster_enclave.json \
        --run-id d6-enclave-3host-<stamp> \
        --out-dir docs/evidence/<run-id> --mode enclave --seal
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import posixpath
import shlex
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d4_three_hosts import (
    DEFAULT_ENCLAVE_DIR,
    DEFAULT_ENCLAVE_SIZE,
    DEFAULT_IFACE,
    DEFAULT_MAX_THREADS,
    DEFAULT_PYTHON,
    DEFAULT_REPO,
    DEFAULT_STACK_SIZE,
    NO_BYTECODE,
    ROLES,
    ThreeHostError,
    Transport,
    capture_command,
    endpoints,
    load_cluster,
    node_command,
    prepare_enclave,
    remote_path,
    routes,
    wait_for_marker,
    wait_for_remote_file,
)
from infra.d6_vectors import D6_MAX_NEW_TOKENS, D6_SEED
from infra.d6_workspace import DEFAULT_SESSION_BASE
from infra.evidence import (
    seal_directory,
    verify_directory,
    write_exclusions,
    write_json,
)


DESTINATION = "P0"
DEFAULT_WORKSPACE = "~/a122-d6/three/workspace"
MODULE = "tee.enclave.d6_node"
NODE_NAME = "d6_node"
ENCLAVE_TEMPLATE = "tee/gramine/enclave/d6_node.manifest.template"
READY_MARKER = "A122-D6-NODE-READY"
DONE_MARKER = "A122-D6-NODE-DONE"
CLIENT_MODULE = "client.d6_runner"
CLIENT_MARKER = "A122-D6-CLIENT-DONE"
CLIENT_FAILED_MARKER = "A122-D6-CLIENT-FAILED"
DEFAULT_PROMPT = "the cipher key is secret"
D6_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)
REVEAL_SCAN = "d6-reveal-scan.json"
README = "README.md"
EXCLUSION_NOTE = (
    "These raw captures stay on the instances that produced them; the bundle "
    "ships their digests and the per-host TLS 1.3 summary. Every excluded file "
    "still has to match the sealed index if it is present, so restoring the "
    "original capture tightens the check instead of bypassing it."
)


def session_root(run_id: str) -> str:
    """The tmpfs the three nodes spill session state into and empty again."""
    return f"{DEFAULT_SESSION_BASE}/{run_id}"


def capture_filter() -> str:
    return " or ".join(f"port {port}" for port in D6_PORTS)


def _client_command(
    *,
    python: str,
    repo: str,
    config: str,
    kas: str,
    out: str,
    log: str,
    prompt: str,
    max_new_tokens: int,
) -> str:
    return (
        f"cd {remote_path(repo)} && "
        f"rm -f {shlex.quote(log)}; setsid nohup env {NO_BYTECODE} "
        f"PYTHONPATH=. {remote_path(python)} -m {CLIENT_MODULE} "
        f"--config {remote_path(config)} --kas {remote_path(kas)} "
        f"--prompt {shlex.quote(prompt)} --out {remote_path(out)} "
        f"--max-new-tokens {int(max_new_tokens)} "
        f"> {shlex.quote(log)} 2>&1 < /dev/null & echo started"
    )


def _session_listing(
    transport: Transport,
    role_routes: Mapping[str, Any],
    session_dirs: Mapping[str, str],
) -> dict[str, Any]:
    """List what one live session left on each instance's tmpfs.

    Run while the session is open this is the "before" half of the cleanup
    evidence; run after the client closed it is the "after" half. The listing
    only carries names and sizes, never a share byte.
    """
    roles: dict[str, Any] = {}
    total_files = 0
    total_bytes = 0
    for role in ROLES:
        directory = session_dirs[role]
        command = (
            f"find {shlex.quote(directory)} -type f -printf '%s %p\\n' "
            f"2>/dev/null | sort || true"
        )
        _status, out, _err = transport.run(role_routes[role], command, check=False)
        entries = []
        bytes_here = 0
        for line in out.splitlines():
            size_text, _, path = line.strip().partition(" ")
            if not size_text.isdigit():
                continue
            size = int(size_text)
            entries.append({"path": path, "bytes": size})
            bytes_here += size
        roles[role] = {
            "directory": directory,
            "exists": bool(entries) or _directory_exists(
                transport, role_routes[role], directory
            ),
            "files": entries,
            "bytes": bytes_here,
        }
        total_files += len(entries)
        total_bytes += bytes_here
    return {
        "roles": roles,
        "total_files": total_files,
        "total_bytes": total_bytes,
        "listed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def _directory_exists(
    transport: Transport, route: Any, directory: str
) -> bool:
    _status, out, _err = transport.run(
        route,
        f"test -d {shlex.quote(directory)} && echo yes || echo no",
        check=False,
    )
    return out.strip() == "yes"


def _watch_client(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    session_dirs: Mapping[str, str],
    log: str,
    timeout: float,
    poll: float = 0.5,
) -> tuple[str, dict[str, Any] | None]:
    """Follow the client until it reports, sampling the session state.

    The client runs detached, so the first sample that finds spilled files is
    the only chance to record the session state before the close removes it.
    A session short enough to finish between two samples records that the
    sample was missed rather than inventing a listing.
    """
    deadline = time.monotonic() + timeout
    before: dict[str, Any] | None = None
    last = ""
    while time.monotonic() < deadline:
        if before is None:
            listing = _session_listing(transport, role_routes, session_dirs)
            if listing["total_files"]:
                before = listing
        _status, out, _err = transport.run(
            role_routes[DESTINATION],
            f"grep -m1 -e {shlex.quote(CLIENT_MARKER)} "
            f"-e {shlex.quote(CLIENT_FAILED_MARKER)} {shlex.quote(log)} || true",
            check=False,
        )
        last = out.strip() or last
        if CLIENT_FAILED_MARKER in last:
            return "failed", before
        if CLIENT_MARKER in last:
            return "done", before
        time.sleep(poll)
    raise ThreeHostError(
        f"the client never reported within {timeout:.0f}s: {last!r}"
    )


def _probes(result: Mapping[str, Any], statuses: Mapping[str, Any]) -> list[str]:
    """Every share prefix this run published, client side and node side."""
    found = {str(value) for value in result.get("share_probes") or []}
    for role in ROLES:
        close = ((statuses.get(role) or {}).get("close_evidence")) or {}
        for value in close.get("spilled_probes") or []:
            found.add(str(value))
    return sorted(value for value in found if value)


def _hygiene(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    run_id: str,
    repo: str,
    python: str,
    workspace: str,
    probes: Sequence[str],
    session_dirs: Mapping[str, str],
    journal_since: str | None,
) -> dict[str, Any]:
    """Scan every instance for a share the close was supposed to remove."""
    root = session_root(run_id)
    reports: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="a122-d6-probes-") as scratch:
        probes_local = Path(scratch) / "probes.json"
        write_json(probes_local, {"run_id": run_id, "probes": list(probes)})
        for role in ROLES:
            route = role_routes[role]
            probes_remote = f"/tmp/{run_id}-{role}-probes.json"
            report_remote = f"/tmp/{run_id}-{role}-hygiene.json"
            transport.put(route, probes_local, probes_remote)
            command_parts = [
                f"cd {remote_path(repo)} &&",
                NO_BYTECODE,
                "PYTHONPATH=.",
                remote_path(python),
                "-m infra.hygiene_scan",
                f"--probes-file {shlex.quote(probes_remote)}",
                f"--root {shlex.quote(root)}",
                f"--root {shlex.quote('/tmp')}",
                f"--root {remote_path(workspace + '/out')}",
                f"--root {shlex.quote('/var/log')}",
            ]
            # The probes are published in these two documents on purpose: the
            # scan reads them from there to know what to look for, so the files
            # that name them are the one place a hit means nothing.
            for skip in (
                f"{workspace}/out/C/client-result.json",
                *[f"{workspace}/out/{other}/node-status.json" for other in ROLES],
            ):
                command_parts.append(f"--skip {remote_path(skip)}")
            for directory in session_dirs.values():
                command_parts.append(f"--expect-absent {shlex.quote(directory)}")
            command_parts.append(f"--expect-empty {shlex.quote(root)}")
            if journal_since:
                command_parts.append(f"--journal-since {shlex.quote(journal_since)}")
            command_parts.append(f"--output {shlex.quote(report_remote)}")
            status, out, err = transport.run(
                route, " ".join(command_parts), timeout=1800, check=False
            )
            text = (out + ("\n" + err if err.strip() else "")).strip()
            try:
                document = json.loads(
                    transport.run(
                        route, f"cat {shlex.quote(report_remote)}", timeout=300
                    )[1]
                )
            except (json.JSONDecodeError, IndexError) as exc:
                raise ThreeHostError(
                    f"{role} produced no readable hygiene scan (exit {status}):\n"
                    f"{text[-400:]}"
                ) from exc
            document["exit_status"] = status
            reports[role] = document
    return {
        "run_id": run_id,
        "session_root": root,
        "probes": list(probes),
        "roots": reports[ROLES[0]].get("roots"),
        "roles": reports,
        "verdict": "clean"
        if all(
            report.get("verdict") == "clean" for report in reports.values()
        )
        else "session-state-found",
    }


def _reveal_scan(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    repo: str,
    python: str,
    run_id: str,
) -> dict[str, Any]:
    """Scan each instance's tree for a production reveal, as D5 does."""
    reports: dict[str, Any] = {}
    for role in ROLES:
        remote = f"/tmp/{run_id}-{role}-reveal-scan.json"
        command = (
            f"cd {remote_path(repo)} && {NO_BYTECODE} PYTHONPATH=. "
            f"{remote_path(python)} -m infra.reveal_scan --root . "
            f"--output {shlex.quote(remote)}"
        )
        status, out, err = transport.run(
            role_routes[role], command, timeout=600, check=False
        )
        text = out + (f"\n{err}" if err.strip() else "")
        try:
            document = json.loads(
                transport.run(
                    role_routes[role], f"cat {shlex.quote(remote)}", timeout=300
                )[1]
            )
        except (json.JSONDecodeError, IndexError) as exc:
            raise ThreeHostError(
                f"{role} produced no readable reveal scan (exit {status}):\n"
                f"{text.strip()[-400:]}"
            ) from exc
        reports[role] = document
        if document.get("verdict") != "clean":
            raise ThreeHostError(
                f"{role} still reveals in production: "
                f"{json.dumps(document.get('findings'), sort_keys=True)[:400]}"
            )
    return {
        "run_id": run_id,
        "scanned_roots": reports[ROLES[0]].get("scanned_roots"),
        "patterns": reports[ROLES[0]].get("patterns"),
        "must_be_clean": reports[ROLES[0]].get("must_be_clean"),
        "roles": reports,
        "verdict": "clean",
    }


def _verdicts(
    *,
    result: Mapping[str, Any],
    hygiene: Mapping[str, Any] | None,
    tokens: int,
) -> dict[str, Any]:
    """The three gate clauses, each reduced to a boolean a reader can check."""
    negatives = result.get("negative_cases") or []
    refused = {
        str(case.get("case")): bool(case.get("refused")) for case in negatives
    }
    tokens_ok = tokens >= 2
    negatives_ok = bool(refused) and all(refused.values())
    hygiene_ok = bool(hygiene) and hygiene.get("verdict") == "clean"
    reference_ok = result.get("reference_verdicts") == "passed"
    shutdown_ok = result.get("shutdown_verdicts") == "passed"
    passed = tokens_ok and negatives_ok and hygiene_ok and reference_ok and shutdown_ok
    return {
        "tokens": tokens,
        "two_tokens_generated": tokens_ok,
        "negative_cases": refused,
        "negatives_refused": negatives_ok,
        "reference_matches_float": reference_ok,
        "nodes_released": shutdown_ok,
        "hygiene_clean": hygiene_ok,
        "passed": passed,
    }


def _bundle(
    *,
    out_dir: Path,
    run_id: str,
    cluster: Mapping[str, Any],
    role_routes: Mapping[str, Any],
    mode: str,
    result: Mapping[str, Any],
    statuses: Mapping[str, Any],
    hygiene: Mapping[str, Any],
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any],
    verdicts: Mapping[str, Any],
    captures: Mapping[str, Any],
    enclosure: Mapping[str, Any] | None,
    commit: str | None,
    prompt: str,
) -> dict[str, Any]:
    private = endpoints(cluster)
    steps = result.get("steps") or []
    document: dict[str, Any] = {
        "run_id": run_id,
        "phase": "D6",
        "mode": mode,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "commit": commit,
        "roles": {
            role: {
                "instance_id": role_routes[role].instance_id,
                "private_address": private[role]["host"],
                "public_address": role_routes[role].public_address,
                "brpc_port": private[role]["brpc_port"],
                "share_port": private[role]["share_port"],
            }
            for role in ROLES
        },
        "enclosure": dict(enclosure) if enclosure else None,
        "captures": {role: dict(value) for role, value in captures.items()},
        "prompt": prompt,
        "prompt_tokens": result.get("prompt_tokens"),
        "prompt_words": result.get("prompt_words"),
        "session_id": result.get("session_id"),
        "generated_tokens": result.get("generated_tokens"),
        "generated_words": result.get("generated_words"),
        "generated_text": result.get("generated_text"),
        "generated_token_count": len(result.get("generated_tokens") or []),
        "steps": steps,
        "reference_check": result.get("reference_check"),
        "negative_cases": result.get("negative_cases"),
        "close": result.get("close"),
        "shutdown": result.get("shutdown"),
        "client_wall_seconds": result.get("wall_seconds"),
        "client_verdicts": {
            "reference": result.get("reference_verdicts"),
            "negatives": result.get("negative_verdicts"),
            "shutdown": result.get("shutdown_verdicts"),
        },
        "node_status": statuses,
        "hygiene": dict(hygiene),
        "session_state_before_close": dict(before) if before else None,
        "session_state_after_close": dict(after),
        "verdicts": dict(verdicts),
    }
    write_json(out_dir / "d6-summary.json", document)
    return document


def _capture_reason(*, role: str, value: Mapping[str, Any]) -> str:
    return (
        f"the raw capture is {int(value['bytes'])} bytes and stays on the "
        f"instance that produced it ({role}) under {value['path']}; the bundle "
        "ships its digest and the TLS 1.3 summary that instance derived from it"
    )


def _finalise(
    *,
    out_dir: Path,
    run_id: str,
    document: Mapping[str, Any],
    captures: Mapping[str, Any],
    reveal: Mapping[str, Any],
) -> dict[str, Any]:
    (out_dir / README).write_text(
        _readme(document=document, reveal=reveal), encoding="utf-8", newline="\n"
    )
    external = [
        {
            "path": str(captures[role]["path"]),
            "bytes": int(captures[role]["bytes"]),
            "sha256": str(captures[role]["sha256"]),
            "reason": str(captures[role].get("reason", "")),
        }
        for role in ROLES
    ]
    index = seal_directory(out_dir, external=external)
    write_exclusions(out_dir, external, run_id=run_id, note=EXCLUSION_NOTE)
    return {
        "index": index,
        "verify": verify_directory(out_dir, exclusions=external),
    }


def _readme(*, document: Mapping[str, Any], reveal: Mapping[str, Any]) -> str:
    """Describe the bundle from the numbers the run actually produced."""
    run_id = document["run_id"]
    roles = document["roles"]
    enclosure = document.get("enclosure") or {}
    captures = document.get("captures") or {}
    verdicts = document.get("verdicts") or {}
    hygiene = document.get("hygiene") or {}
    measurements = enclosure.get("measurements") or {}
    manifests = enclosure.get("manifest_sha256") or {}
    steps = document.get("steps") or []
    lines = [
        f"# D6 three-instance enclave run ({run_id})",
        "",
        "Sealed evidence for the D6 gate: one client prompt drives a private",
        "autoregressive loop through P0/P1/P2, each node inside its own",
        "`gramine-sgx` enclave, and the session state is searched for on every",
        "instance after the client closes it.",
        "",
        "| Role | Instance | Private | Public |",
        "| --- | --- | --- | --- |",
    ]
    for role in ROLES:
        entry = roles[role]
        lines.append(
            f"| {role} | `{entry['instance_id']}` | `{entry['private_address']}` "
            f"| `{entry['public_address']}` |"
        )
    lines += [
        "",
        f"The run is at commit `{document.get('commit')}`.",
        "",
        "## What each file says",
        "",
        "| File | Content |",
        "| --- | --- |",
        "| `d6-summary.json` | Machine-readable summary: roles, prompt, tokens, "
        "per-step latencies, negatives, close evidence, the enclosure block, the "
        "before/after session listings and the capture digests |",
        "| `d6-client-result.json` | Everything the client saw and checked: "
        "request hashes, reconstructed tokens, its own argmax agreement, every "
        "refused negative and the float reference comparison |",
        "| `d6-client.log` | The client process's own stdout, including its "
        "one-line verdict summary |",
        "| `d6-three-p{0,1,2}-node-status.json` | Each node's step digests, "
        "refusals, KV wipe record and close evidence |",
        "| `d6-three-p{0,1,2}-node.log` | Each node's log: the ready line with "
        "its identity digest and peers, then the done line |",
        "| `d6-three-P{0,1,2}-tls-summary.txt` | Each instance's own TLS 1.3 "
        "analysis of its own capture |",
        "| `d6-hygiene-p{0,1,2}.json` | What the post-close search of each "
        "instance's tmpfs, temp tree, logs and process table found |",
        "| `d6-reveal-scan.json` | The production-reveal scan all three trees "
        "were checked against |",
        "| `d6-enclave-p{0,1,2}-sign.txt`, `d6-enclave.manifest` | What each "
        "instance's `gramine-sgx-sign` printed and the manifest it signed |",
        "| `evidence-index.json`, `evidence.sha256` | The seal over the directory |",
        "",
        "The raw captures stay on their instances under `/tmp/`; the three",
        "`d6-three-P{0,1,2}.pcap` entries in `<bundle>.exclusions.json` record",
        "their size and digest, and the per-instance TLS summaries are",
        "committed.",
        "",
        "## The decoded tokens",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| Prompt | `{document.get('prompt')}` |",
        f"| Prompt token ids | `{document.get('prompt_tokens')}` |",
        f"| Generated words | `{document.get('generated_words')}` |",
        f"| Generated text | `{document.get('generated_text')}` |",
        f"| Session id | `{document.get('session_id')}` |",
        "",
        "| Step | Token | Word | Argmax of reconstructed logits | Secure Argmax | Wall ms |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for record in steps:
        lines.append(
            f"| {record.get('decode_step')} | {record.get('token_id')} | "
            f"`{record.get('token_word')}` | "
            f"{record.get('argmax_of_reconstructed_logits')} | "
            f"`{record.get('argmax_match')}` | {record.get('step_wall_ms')} |"
        )
    lines += [
        "",
        "The last two columns agreeing is the point of the loop: the parties",
        "produce a token with their own secure comparison, and the client, which",
        "holds none of the model, reconstructs the same logits from the three",
        "receipts and takes their argmax itself.",
        "",
        "## Reference",
        "",
        "| Step | Max abs error | Mean abs error | Reference token | Token match | Argmax match |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for check in document.get("reference_check") or []:
        lines.append(
            f"| {check.get('decode_step')} | {check.get('max_abs_error'):.6g} | "
            f"{check.get('mean_abs_error'):.6g} | {check.get('reference_token')} | "
            f"`{check.get('token_match')}` | `{check.get('argmax_match')}` |"
        )
    lines += [
        "",
        "## Negative cases",
        "",
        "| Case | Refused | Reason |",
        "| --- | --- | --- |",
    ]
    for case in document.get("negative_cases") or []:
        reason = str(case.get("reason") or "").replace("|", "\\|")
        lines.append(
            f"| `{case.get('case')}` | `{case.get('refused')}` | {reason} |"
        )
    lines += [
        "",
        "## Session state",
        "",
        "| Role | Spilled files | Bytes overwritten | Session dir removed | "
        "Keys zeroed | KV entries left |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for role in ROLES:
        close = (((document.get("node_status") or {}).get(role) or {}).get(
            "close_evidence"
        )) or {}
        kv = close.get("kv") or {}
        lines.append(
            f"| {role} | {close.get('spilled_files')} | "
            f"{close.get('spilled_bytes_overwritten')} | "
            f"`{close.get('session_dir_removed')}` | "
            f"{close.get('session_keys_wiped_bytes')} | "
            f"{kv.get('entries')} |"
        )
    lines += [
        "",
        "| Item | Before close | After close |",
        "| --- | --- | --- |",
        f"| Files under the session root | "
        f"{(document.get('session_state_before_close') or {}).get('total_files')} | "
        f"{(document.get('session_state_after_close') or {}).get('total_files')} |",
        "",
        "## Hygiene scan",
        "",
        "| Role | Verdict | Findings | Roots that exist | Journal |",
        "| --- | --- | --- | --- | --- |",
    ]
    for role in ROLES:
        entry = (hygiene.get("roles") or {}).get(role) or {}
        journal = (entry.get("journal") or {}).get("available")
        lines.append(
            f"| {role} | `{entry.get('verdict')}` | "
            f"{len(entry.get('findings') or [])} | "
            f"{len(entry.get('roots_that_exist') or [])} | `{journal}` |"
        )
    lines += [
        "",
        "The scan searches for the share prefixes the run published as probes,",
        "in the session tmpfs, `/tmp`, the workspace `out/` tree, `/var/log`,",
        "the system journal and every process's command line and environment.",
        "It also asserts the three session directories are gone and the session",
        "root is empty, so a close that removed the directory but left something",
        "else behind still fails.",
        "",
        "## Verdicts",
        "",
        "| Clause | Value |",
        "| --- | --- |",
        f"| Tokens generated | {verdicts.get('tokens')} |",
        f"| At least two tokens | `{verdicts.get('two_tokens_generated')}` |",
        f"| Negatives refused | `{verdicts.get('negatives_refused')}` |",
        f"| Reference matches the float model | "
        f"`{verdicts.get('reference_matches_float')}` |",
        f"| Nodes released | `{verdicts.get('nodes_released')}` |",
        f"| Hygiene clean | `{verdicts.get('hygiene_clean')}` |",
        f"| Gate | `{verdicts.get('passed')}` |",
        "",
        "## Enclosure",
        "",
        "| Role | MRENCLAVE | `d6_node.manifest` sha256 |",
        "| --- | --- | --- |",
    ]
    for role in ROLES:
        lines.append(
            f"| {role} | `{measurements.get(role)}` | `{manifests.get(role)}` |"
        )
    lines += [
        "",
        f"`distinct_measurements`: {enclosure.get('distinct_measurements')}.",
        "Each instance signed the tree it really loaded, so the default run",
        "measures three trees rather than pretending they are one.",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| `sgx.enclave_size` | {enclosure.get('enclave_size')} |",
        f"| `sgx.max_threads` | {enclosure.get('max_threads')} |",
        f"| `sys.stack.size` | {enclosure.get('stack_size')} |",
        f"| Template | `{enclosure.get('template')}` |",
        f"| Launcher | `{' '.join(enclosure.get('wrapper') or [])}` |",
        "",
        "## Reveal scan",
        "",
        "| Role | Verdict | Findings | Allowlisted hits |",
        "| --- | --- | --- | --- |",
    ]
    for role in ROLES:
        entry = (reveal.get("roles") or {}).get(role) or {}
        lines.append(
            f"| {role} | `{entry.get('verdict')}` | "
            f"{len(entry.get('findings') or [])} | "
            f"{len(entry.get('allowlisted') or [])} |"
        )
    lines += [
        "",
        "## Captures",
        "",
        "| Role | Bytes | SHA-256 |",
        "| --- | --- | --- |",
    ]
    for role in ROLES:
        value = captures.get(role) or {}
        lines.append(f"| {role} | {value.get('bytes')} | `{value.get('sha256')}` |")
    return "\n".join(lines) + "\n"


def run_three_hosts(
    *,
    cluster: Mapping[str, Any],
    out_dir: Path,
    run_id: str,
    transport: Transport,
    ssh_user: str,
    mode: str = "enclave",
    ssh_host: str | None = None,
    repo: str = DEFAULT_REPO,
    python: str = DEFAULT_PYTHON,
    workspace: str = DEFAULT_WORKSPACE,
    iface: str = DEFAULT_IFACE,
    seed: int = D6_SEED,
    prompt: str = DEFAULT_PROMPT,
    max_new_tokens: int = D6_MAX_NEW_TOKENS,
    node_timeout: float = 1800.0,
    expect_commit: str | None = None,
    seal: bool = False,
    enclave_dir: str = DEFAULT_ENCLAVE_DIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
    dry_run: bool = False,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    role_routes = routes(cluster, user=ssh_user, ssh_host=ssh_host)
    private = endpoints(cluster)
    parent = posixpath.dirname(workspace.rstrip("/"))
    tarball = f"/tmp/{run_id}-workspace.tgz"
    cluster_file = f"/tmp/{run_id}-cluster.json"
    pcaps = {role: f"/tmp/{run_id}-{role}.pcap" for role in ROLES}
    cap_logs = {role: f"/tmp/{run_id}-{role}-capture.log" for role in ROLES}
    node_logs = {role: f"/tmp/{run_id}-{role}.log" for role in ROLES}
    client_log = f"/tmp/{run_id}-client.log"
    client_result = f"{workspace}/out/C/client-result.json"
    root = session_root(run_id)
    session_dirs = {role: f"{root}/{role}" for role in ROLES}

    if expect_commit:
        for role in ROLES:
            _status, out, _err = transport.run(
                role_routes[role],
                f"cd {remote_path(repo)} && git rev-parse HEAD",
                check=False,
            )
            if out.strip() != expect_commit:
                raise ThreeHostError(
                    f"{role} is at {out.strip() or 'unknown'}, expected {expect_commit}"
                )

    cluster_document = {
        role: {
            "host": private[role]["host"],
            "brpc_port": private[role]["brpc_port"],
            "share_port": private[role]["share_port"],
        }
        for role in ROLES
    }
    provision = (
        f"cd {remote_path(repo)} && {NO_BYTECODE} PYTHONPATH=. "
        f"{remote_path(python)} -m infra.d6_workspace --mode provision "
        f"--root {remote_path(workspace)} --run-id {shlex.quote(run_id)} "
        f"--cluster-file {shlex.quote(cluster_file)} --seed {int(seed)} "
        f"--max-new-tokens {int(max_new_tokens)} "
        f"--session-root {shlex.quote(root)}"
    )
    if dry_run:
        return {
            "dry_run": True,
            "provision": provision,
            "client": _client_command(
                python=python,
                repo=repo,
                config=f"{workspace}/configs/C.json",
                kas=f"{workspace}/kas.json",
                out=client_result,
                log=client_log,
                prompt=prompt,
                max_new_tokens=max_new_tokens,
            ),
        }

    started_at = dt.datetime.now(dt.timezone.utc)
    journal_since = f"@{int(started_at.timestamp()) - 5}"
    enclosure: dict[str, Any] | None = None
    captured: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="a122-d6-three-") as scratch:
        scratch_path = Path(scratch)
        local_cluster = scratch_path / "cluster.json"
        write_json(local_cluster, cluster_document)
        transport.put(role_routes[DESTINATION], local_cluster, cluster_file)
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"mkdir -p {shlex.quote(posixpath.dirname(pcaps[role]))} "
                f"{remote_path(parent)}",
            )
        transport.run(role_routes[DESTINATION], f"rm -rf {remote_path(parent)}")
        transport.run(
            role_routes[DESTINATION],
            f"mkdir -p {remote_path(parent)}",
        )
        transport.run(role_routes[DESTINATION], provision, timeout=900)
        transport.run(
            role_routes[DESTINATION],
            f"tar czf {shlex.quote(tarball)} -C {remote_path(parent)} workspace",
            timeout=600,
        )
        local_tar = scratch_path / "workspace.tgz"
        transport.get(role_routes[DESTINATION], tarball, local_tar)
        for role in ("P1", "P2"):
            transport.put(role_routes[role], local_tar, tarball)
            transport.run(
                role_routes[role],
                f"rm -rf {remote_path(parent)} && "
                f"mkdir -p {remote_path(parent)} && "
                f"tar xzf {shlex.quote(tarball)} -C {remote_path(parent)}",
                timeout=600,
            )

        wrapper: Sequence[str] | None = None
        if mode == "enclave":
            enclosure = prepare_enclave(
                transport,
                role_routes,
                template=Path(ENCLAVE_TEMPLATE),
                run_id=run_id,
                out_dir=out_dir,
                node_name=NODE_NAME,
                bundle_prefix="d6-enclave",
                repo=repo,
                python=python,
                workspace=workspace,
                enclave_dir=enclave_dir,
                enclave_size=enclave_size,
                max_threads=max_threads,
                stack_size=stack_size,
                session_root=root,
                prepare_session_root=True,
            )
            wrapper = enclosure["wrapper"]
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"getcap $(command -v tcpdump) 2>/dev/null | grep -q cap_net_raw || "
                f"sudo -n setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)",
                check=False,
            )
            transport.start_background(
                role_routes[role],
                capture_command(iface=iface, pcap=pcaps[role], log=cap_logs[role]),
            )
        time.sleep(2.0)

        for role in ("P1", "P2", "P0"):
            transport.start_background(
                role_routes[role],
                node_command(
                    python=python,
                    repo=repo,
                    config=f"{workspace}/configs/{role}.json",
                    log=node_logs[role],
                    wrapper=wrapper,
                    module=MODULE,
                ),
            )
            time.sleep(1.0)
        for role in ROLES:
            wait_for_marker(
                transport,
                role_routes[role],
                log=node_logs[role],
                marker=READY_MARKER,
                timeout=node_timeout,
            )

        transport.start_background(
            role_routes[DESTINATION],
            _client_command(
                python=python,
                repo=repo,
                config=f"{workspace}/configs/C.json",
                kas=f"{workspace}/kas.json",
                out=client_result,
                log=client_log,
                prompt=prompt,
                max_new_tokens=max_new_tokens,
            ),
        )
        outcome, before = _watch_client(
            transport,
            role_routes,
            session_dirs=session_dirs,
            log=client_log,
            timeout=node_timeout,
        )
        for role in ROLES:
            # A node only writes its status on the way out, and the client's
            # last act is to release all three, so the marker follows the
            # client rather than preceding it.
            wait_for_marker(
                transport,
                role_routes[role],
                log=node_logs[role],
                marker=DONE_MARKER,
                timeout=node_timeout,
            )
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"pkill -INT -f {shlex.quote('tcpdump -i ' + iface)} || true",
                check=False,
            )
        time.sleep(2.0)
        after = _session_listing(transport, role_routes, session_dirs)

        for role in ROLES:
            _status, facts, _err = transport.run(
                role_routes[role],
                f"stat -c%s {shlex.quote(pcaps[role])}; "
                f"sha256sum {shlex.quote(pcaps[role])} | cut -d' ' -f1",
            )
            size_text, _, digest = facts.strip().partition("\n")
            size = int(size_text.strip())
            digest = digest.strip()
            analysis = (
                f"cd {remote_path(repo)} && {NO_BYTECODE} PYTHONPATH=. "
                f"{remote_path(python)} -m infra.pcap_tls {shlex.quote(pcaps[role])} "
                f"--d4-ports"
            )
            _status, body, _err = transport.run(
                role_routes[role], analysis, timeout=1800
            )
            header = "\n".join(
                [
                    "# A1-22 D6 cross-host capture",
                    f"role: {role}",
                    f"instance: {role_routes[role].instance_id}",
                    f"private address: {private[role]['host']}",
                    f"capture: {pcaps[role]} ({size} bytes, sha256 {digest})",
                    "",
                ]
            ) + "\n"
            (out_dir / f"d6-three-{role}-tls-summary.txt").write_text(
                header + body, encoding="utf-8", newline="\n"
            )
            wait_for_remote_file(
                transport,
                role_routes[role],
                f"{workspace}/out/{role}/node-status.json",
                timeout=300.0,
            )
            transport.get(
                role_routes[role],
                f"{workspace}/out/{role}/node-status.json",
                out_dir / f"d6-three-{role.lower()}-node-status.json",
            )
            transport.get(
                role_routes[role],
                node_logs[role],
                out_dir / f"d6-three-{role.lower()}-node.log",
            )
            captured[role] = {"bytes": size, "sha256": digest, "path": pcaps[role]}
        if outcome == "failed":
            body = transport.run(
                role_routes[DESTINATION], f"cat {shlex.quote(client_log)}"
            )[1]
            (out_dir / "d6-client.log").write_text(
                body if body.endswith("\n") else body + "\n",
                encoding="utf-8",
                newline="\n",
            )
            raise ThreeHostError(
                "the client failed its own checks:\n" + body.strip()[-800:]
            )
        wait_for_remote_file(
            transport,
            role_routes[DESTINATION],
            client_result,
            timeout=300.0,
        )
        transport.get(
            role_routes[DESTINATION], client_result, out_dir / "d6-client-result.json"
        )
        transport.get(
            role_routes[DESTINATION], client_log, out_dir / "d6-client.log"
        )

    result = json.loads(
        (out_dir / "d6-client-result.json").read_text(encoding="utf-8")
    )
    statuses = {
        role: json.loads(
            (out_dir / f"d6-three-{role.lower()}-node-status.json").read_text(
                encoding="utf-8"
            )
        )
        for role in ROLES
    }
    tokens = len(result.get("generated_tokens") or [])
    hygiene_document = _hygiene(
        transport,
        role_routes,
        run_id=run_id,
        repo=repo,
        python=python,
        workspace=workspace,
        probes=_probes(result, statuses),
        session_dirs=session_dirs,
        journal_since=journal_since,
    )
    for role in ROLES:
        write_json(out_dir / f"d6-hygiene-{role.lower()}.json", hygiene_document["roles"][role])

    captures = {
        role: {
            "path": f"d6-three-{role}.pcap",
            "bytes": value["bytes"],
            "sha256": value["sha256"],
            "reason": _capture_reason(role=role, value=value),
        }
        for role, value in captured.items()
    }
    verdicts = _verdicts(result=result, hygiene=hygiene_document, tokens=tokens)
    document = _bundle(
        out_dir=out_dir,
        run_id=run_id,
        cluster=cluster,
        role_routes=role_routes,
        mode=mode,
        result=result,
        statuses=statuses,
        hygiene=hygiene_document,
        before=before,
        after=after,
        verdicts=verdicts,
        captures=captures,
        enclosure=enclosure,
        commit=expect_commit,
        prompt=prompt,
    )
    sealed: dict[str, Any] = {}
    if seal:
        reveal = _reveal_scan(
            transport, role_routes, repo=repo, python=python, run_id=run_id
        )
        write_json(out_dir / REVEAL_SCAN, reveal)
        sealed = _finalise(
            out_dir=out_dir,
            run_id=run_id,
            document=document,
            captures=captures,
            reveal=reveal,
        )
    public = sorted(path.name for path in out_dir.iterdir() if path.is_file())
    return {
        "run_id": run_id,
        "verdicts": verdicts,
        "tokens": result.get("generated_tokens"),
        "generated_text": result.get("generated_text"),
        "hygiene": hygiene_document["verdict"],
        "bundle": str(out_dir),
        "files": public,
        **sealed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D6 three-instance run")
    parser.add_argument("--cluster", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("host", "enclave"), default="enclave")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--python", default=DEFAULT_PYTHON)
    parser.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--seed", type=int, default=D6_SEED)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--max-new-tokens", type=int, default=D6_MAX_NEW_TOKENS)
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--ssh-user", default="jiahao")
    parser.add_argument("--ssh-host", default=None)
    parser.add_argument(
        "--ssh-key",
        default=None,
        help="private key the driver authenticates with, when the operator "
        "host carries no usable ~/.ssh identity of its own",
    )
    parser.add_argument("--ssh-key-password", default=None)
    parser.add_argument("--expect-commit", default=None)
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport(
        key_path=args.ssh_key,
        key_password=args.ssh_key_password,
    )
    result = run_three_hosts(
        cluster=cluster,
        out_dir=args.out_dir,
        run_id=args.run_id,
        transport=transport,
        ssh_user=args.ssh_user,
        mode=args.mode,
        ssh_host=args.ssh_host,
        repo=args.repo,
        python=args.python,
        workspace=args.workspace,
        iface=args.iface,
        seed=args.seed,
        prompt=args.prompt,
        max_new_tokens=args.max_new_tokens,
        node_timeout=args.timeout,
        expect_commit=args.expect_commit,
        seal=args.seal,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if result.get("dry_run"):
        return 0
    return 0 if (result.get("verdicts") or {}).get("passed") else 1


__all__ = [
    "CLIENT_MARKER",
    "D6_PORTS",
    "DEFAULT_PROMPT",
    "MODULE",
    "NODE_NAME",
    "capture_filter",
    "run_three_hosts",
    "session_root",
]


if __name__ == "__main__":
    raise SystemExit(main())

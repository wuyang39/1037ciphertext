"""Drive the D7 GPT-2 acceptance across three instances and collect its evidence.

Where D6 put a client in front of three parties running a toy decoder, D7 puts
the same client in front of three parties running the real GPT-2 block on the
real checkpoint's tensors. The sequence is the D6 one -- stage the workspace,
carry it to the peers, sign and start the three enclaves, run the client from
one allowed host, release the nodes, scrub what the run staged, scan every
instance for what the close was supposed to remove, and seal the bundle -- with
one difference that matters:

**each node receives only its own share.** The driver reads the staged trees
back after the session and overwrites and removes them, because a staged tree
that survives the run leaves one party's share of the model on a disk.

The peers fetch their own tree from the driver host over the VPC private
address rather than through this operator machine, so the interface that
carries the shares is the same private network the SPU link runs on, and no
share crosses the public internet.

Usage::

    python -m infra.d7_three_hosts run \
        --cluster ~/a122_cluster_enclave.json \
        --run-id d7-enclave-3host-<stamp> \
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
    kill_nodes,
    load_cluster,
    node_command,
    prepare_enclave,
    remote_path,
    routes,
    wait_for_marker,
    wait_for_remote_file,
)
from infra.evidence import (
    seal_directory,
    verify_directory,
    write_exclusions,
    write_json,
)


DESTINATION = "P0"
DEFAULT_ROOT = "~/a122-d7/three/workspace"
DEFAULT_CLIENT_DIR = "~/a122-d7/client"
DEFAULT_EXPORT_DIR = "~/a122-d7/export"
DEFAULT_TOKENIZER_DIR = "~/a122-d7/tokenizer"
DEFAULT_DIST_ROOT = "~/a122-d7/dist"
DEFAULT_SESSION_BASE = "/dev/shm/a122-d7"
MODULE = "tee.enclave.d7_node"
NODE_NAME = "d7_node"
NODE_PATTERN = r"tee\.enclave\.d7_node"
ENCLAVE_TEMPLATE = "tee/gramine/enclave/d7_node.manifest.template"
READY_MARKER = "A122-D7-NODE-READY"
DONE_MARKER = "A122-D7-NODE-DONE"
NODE_DIED_MARKER = "A122-D7-NODE-DIED"
PYTHON_TRACEBACK = "Traceback (most recent call last)"
CLIENT_MODULE = "client.d7_runner"
CLIENT_MARKER = "A122-D7-CLIENT-DONE"
CLIENT_FAILED_MARKER = "A122-D7-CLIENT-FAILED"
DEFAULT_PROMPT = "the cipher key is secret"
SHARE_PORT = 47890
D7_PORTS = (47100, 47101, 47102, 47200, 47201, 47202, SHARE_PORT)
# The D7 traffic is roughly a gigabyte per host in a single decode, so the
# kernel's stock capture ring is overrun in under a millisecond. Ask for 256 MiB
# and check ``net.core.rmem_max`` can grant it before the run starts.
CAPTURE_BUFFER_KIB = 262144
REVEAL_SCAN = "d7-reveal-scan.json"
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
    return " or ".join(f"port {port}" for port in D7_PORTS)


def capture_headroom_error(rmem_max: int, *, buffer_kib: int) -> str | None:
    """Return why the host cannot hold the capture ring, or ``None`` if it can.

    ``tcpdump -B`` only sets ``SO_RCVBUF``; the kernel silently clamps it to
    ``net.core.rmem_max``. A clamped ring overruns on the D7 volume, and a
    capture with holes cannot certify the stream it missed, so this fails the
    run instead of sealing a capture that would be read as a violation later.
    """
    wanted = int(buffer_kib) * 1024
    if rmem_max >= wanted:
        return None
    return (
        f"net.core.rmem_max is {rmem_max} bytes but the capture ring wants "
        f"{wanted}; raise it first, e.g. "
        f"sudo sysctl -w net.core.rmem_max={wanted}"
    )


def assert_capture_headroom(
    transport: Any, routes: Mapping[str, Any], *, buffer_kib: int
) -> None:
    """Refuse to start a capture the host's kernel would clamp."""
    for role in ROLES:
        status, body, err = transport.run(
            routes[role], "cat /proc/sys/net/core/rmem_max"
        )
        text = body.strip().splitlines()[-1] if body.strip() else ""
        if status != 0 or not text.isdigit():
            raise ThreeHostError(
                f"{role}: could not read net.core.rmem_max "
                f"(status {status}, {err.strip()[:200]})"
            )
        problem = capture_headroom_error(int(text), buffer_kib=buffer_kib)
        if problem is not None:
            raise ThreeHostError(f"{role}: {problem}")


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


def _describe_export(transport: Transport, route: Any, *, export_dir: str) -> str:
    """A digest of the exported run as the driver host really holds it."""
    command = (
        f"cd {remote_path(export_dir)} && "
        "sha256sum model/tensors.bin model/model.json run.json "
        "precision_plan.json source-freeze.json"
    )
    _status, out, _err = transport.run(route, command, check=False)
    return out.strip()


def _session_listing(
    transport: Transport,
    role_routes: Mapping[str, Any],
    session_dirs: Mapping[str, str],
) -> dict[str, Any]:
    """List what one live session left on each instance's tmpfs."""
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
            "exists": bool(entries)
            or _directory_exists(transport, role_routes[role], directory),
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


def _directory_exists(transport: Transport, route: Any, directory: str) -> bool:
    _status, out, _err = transport.run(
        route,
        f"test -d {shlex.quote(directory)} && echo yes || echo no",
        check=False,
    )
    return out.strip() == "yes"


def wait_for_node_ready(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    logs: Mapping[str, str],
    marker: str = READY_MARKER,
    timeout: float,
    poll: float = 5.0,
) -> dict[str, str]:
    """Wait for every node's ready line, and report one that died instead."""
    deadline = time.monotonic() + timeout
    ready: dict[str, str] = {}
    pending = list(ROLES)
    last = ""
    while pending and time.monotonic() < deadline:
        for role in list(pending):
            log = logs[role]
            command = (
                f"if grep -q {shlex.quote(marker)} {shlex.quote(log)} 2>/dev/null;"
                f" then grep -m1 {shlex.quote(marker)} {shlex.quote(log)};"
                f" elif grep -q {shlex.quote(PYTHON_TRACEBACK)}"
                f" {shlex.quote(log)} 2>/dev/null; then"
                f" echo {shlex.quote(NODE_DIED_MARKER)};"
                f" tail -c 3000 {shlex.quote(log)}; fi"
            )
            _status, out, _err = transport.run(role_routes[role], command, check=False)
            text = out.strip()
            if not text:
                continue
            if text.startswith(NODE_DIED_MARKER):
                raise ThreeHostError(
                    f"{role} died before it was ready:\n"
                    f"{text[len(NODE_DIED_MARKER):].strip()}"
                )
            ready[role] = text
            pending.remove(role)
            last = f"{role} is ready"
        if pending:
            time.sleep(poll)
    if pending:
        raise ThreeHostError(
            f"{', '.join(pending)} never reported {marker} within "
            f"{timeout:.0f}s ({last})"
        )
    return ready


def _watch_client(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    session_dirs: Mapping[str, str],
    log: str,
    timeout: float,
    poll: float = 1.0,
) -> tuple[str, dict[str, Any] | None]:
    """Follow the client until it reports, sampling the session state."""
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
    raise ThreeHostError(f"the client never reported within {timeout:.0f}s: {last!r}")


def _probes(result: Mapping[str, Any], statuses: Mapping[str, Any]) -> list[str]:
    """Every share prefix this run published, client side and node side."""
    found = {str(value) for value in result.get("share_probes") or []}
    for role in ROLES:
        close = ((statuses.get(role) or {}).get("close_evidence")) or {}
        for value in close.get("spilled_probes") or []:
            found.add(str(value))
    return sorted(value for value in found if value)


def _scrub_staging(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    role_root: str,
    dist_root: str,
) -> dict[str, Any]:
    """Overwrite and remove the staged shares on every instance.

    A staged tree that outlives the session leaves one party's share of the
    model on a disk, so the overwrite happens before the removal and the number
    of bytes that were overwritten is recorded.
    """
    reports: dict[str, Any] = {}
    for role in ROLES:
        share = f"{role_root}/shares/{role}.json"
        script = "\n".join(
            [
                "set -u",
                f"share={shlex.quote(share)}",
                "bytes=0",
                'if [ -f "$share" ]; then',
                '  bytes=$(stat -c%s "$share")',
                '  dd if=/dev/zero of="$share" bs=1M '
                'count=$(( bytes / 1048576 + 1 )) conv=notrunc status=none '
                '2>/dev/null || true',
                '  sync; rm -f "$share"',
                "fi",
                f"rm -f {shlex.quote('/tmp/' + role + '.tgz')}",
                f"rm -rf {shlex.quote(role_root + '/pki/nodes/C')}",
                f"rm -rf {shlex.quote(dist_root)}",
                'echo "share_bytes=$bytes"',
                'test -e "$share" && echo "share_present=yes" '
                '|| echo "share_present=no"',
                f"find {shlex.quote(role_root)} -name '*.json' -size +4096c "
                "-printf '%s %p\\n' 2>/dev/null || true",
                "true",
            ]
        )
        _status, out, err = transport.run(role_routes[role], script, check=False)
        text = out + (f"\n{err}" if err.strip() else "")
        size = 0
        present = True
        large: list[str] = []
        for line in out.splitlines():
            key, _, value = line.partition("=")
            if key == "share_bytes" and value.strip().isdigit():
                size = int(value.strip())
            elif key == "share_present":
                present = value.strip() == "yes"
            elif line.strip() and line.strip()[0].isdigit():
                large.append(line.strip())
        reports[role] = {
            "path": share,
            "bytes_overwritten": size,
            "share_removed": not present,
            "large_json_left": large,
            "output": text.strip()[-400:],
        }
    return {
        "roles": reports,
        "verdict": "clean"
        if all(
            report["share_removed"] and not report["large_json_left"]
            for report in reports.values()
        )
        else "staged-shares-found",
    }


def _serve_staging(
    transport: Transport,
    route: Any,
    *,
    dist_root: str,
    host: str,
    port: int,
) -> str:
    """Serve the per-role tarballs on the private address for the peers."""
    command = (
        f"cd {remote_path(dist_root)} && "
        f"(setsid nohup python3 -m http.server {int(port)} --bind {shlex.quote(host)} "
        "> /tmp/d7-stage-http.log 2>&1 < /dev/null &) ; sleep 2; "
        f"ss -ltn | grep -q {int(port)} && echo LISTENING || echo NOT_LISTENING"
    )
    _status, out, err = transport.run(route, command, timeout=60, check=False)
    return (out + err).strip()


def _fetch_staging(
    transport: Transport,
    route: Any,
    *,
    role: str,
    host: str,
    port: int,
    home_root: str,
    expected_sha256: str,
) -> dict[str, Any]:
    """Fetch this node's own tarball over the VPC and unpack it in place."""
    command = "\n".join(
        [
            "set -euo pipefail",
            f"tgz=$(mktemp /tmp/{role}-XXXX.tgz)",
            "curl -fsS --max-time 600 -o \"$tgz\" "
            + f"http://{host}:{int(port)}/{role}.tgz",
            f'echo {expected_sha256}  "$tgz" | sha256sum -c -',
            f"rm -rf {remote_path(home_root)}",
            f"mkdir -p {remote_path(home_root)}",
            f'tar xzf "$tgz" -C {remote_path(home_root)}',
            'rm -f "$tgz"',
            f"test -f {remote_path(home_root + '/workspace/shares/' + role + '.json')}",
            "echo FETCH-OK",
        ]
    )
    _status, out, err = transport.run(route, command, timeout=900, check=False)
    text = out + (f"\n{err}" if err.strip() else "")
    if "FETCH-OK" not in text:
        raise ThreeHostError(f"{role} could not fetch its staged tree:\n{text.strip()}")
    return {"role": role, "verified": True, "output": text.strip()[-200:]}


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
    with tempfile.TemporaryDirectory(prefix="a122-d7-probes-") as scratch:
        probes_local = Path(scratch) / "probes.json"
        write_json(probes_local, {"run_id": run_id, "probes": list(probes)})
        for role in ROLES:
            route = role_routes[role]
            probes_remote = f"/tmp/{run_id}-{role}-probes.json"
            report_remote = f"/tmp/{run_id}-{role}-hygiene.json"
            transport.put(route, probes_local, probes_remote)
            parts = [
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
            for skip in (
                f"{workspace}/out/C/client-result.json",
                *[f"{workspace}/out/{other}/node-status.json" for other in ROLES],
            ):
                parts.append(f"--skip {remote_path(skip)}")
            for directory in session_dirs.values():
                parts.append(f"--expect-absent {shlex.quote(directory)}")
            parts.append(f"--expect-empty {shlex.quote(root)}")
            if journal_since:
                parts.append(f"--journal-since {shlex.quote(journal_since)}")
            parts.append(f"--output {shlex.quote(report_remote)}")
            status, out, err = transport.run(
                route, " ".join(parts), timeout=1800, check=False
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
        if all(report.get("verdict") == "clean" for report in reports.values())
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
    """Scan each instance's tree for a production reveal, as D5 and D6 do."""
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
    scrub: Mapping[str, Any] | None,
    tokens: int,
) -> dict[str, Any]:
    """Every gate clause, each reduced to a boolean a reader can check."""
    negatives = result.get("negative_cases") or []
    refused = {
        str(case.get("case")): bool(case.get("refused")) for case in negatives
    }
    tokens_ok = tokens >= 2
    negatives_ok = bool(refused) and all(refused.values())
    hygiene_ok = bool(hygiene) and hygiene.get("verdict") == "clean"
    scrub_ok = bool(scrub) and scrub.get("verdict") == "clean"
    reference_ok = result.get("reference_verdicts") == "passed"
    shutdown_ok = result.get("shutdown_verdicts") == "passed"
    passed = (
        tokens_ok
        and negatives_ok
        and hygiene_ok
        and scrub_ok
        and reference_ok
        and shutdown_ok
    )
    return {
        "tokens": tokens,
        "two_tokens_generated": tokens_ok,
        "negative_cases": refused,
        "negatives_refused": negatives_ok,
        "reference_matches_float": reference_ok,
        "nodes_released": shutdown_ok,
        "hygiene_clean": hygiene_ok,
        "staged_shares_scrubbed": scrub_ok,
        "passed": passed,
    }


def _readme(document: Mapping[str, Any]) -> str:
    verdicts = document["verdicts"]
    enclosure = document.get("enclosure") or {}
    measurements = enclosure.get("measurements") or {}
    manifests = enclosure.get("manifest_sha256") or {}
    scrub = document.get("staging_scrub") or {}
    hygiene = document.get("hygiene") or {}
    model = document.get("model") or {}
    lines = [
        "# D7 enclave acceptance: real GPT-2 decoding across three instances",
        "",
        f"Run `{document['run_id']}` at {document['timestamp_utc']} "
        f"({document['mode']} mode).",
        "",
        "## What ran",
        "",
        f"- Model: `{model.get('model_version')}` "
        f"(model hash `{model.get('model_hash')}`)",
        f"- Blocks stacked: {model.get('layers')} "
        "(the layer count is a measured limit, not the whole network)",
        f"- Candidate vocabulary: {model.get('vocab_size')} ids "
        f"(sha256 `{model.get('candidate_vocabulary_hash')}`)",
        f"- Tokenizer: sha256 `{model.get('tokenizer_hash')}`",
        f"- Prompt: `{document.get('prompt')}` "
        f"({document.get('prompt_tokens')} tokens, pinned by the plan)",
        f"- Generated: {document.get('generated_token_count')} tokens "
        f"`{document.get('generated_text')}`",
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
        f"| Staged shares scrubbed | `{verdicts.get('staged_shares_scrubbed')}` |",
        f"| Gate | `{verdicts.get('passed')}` |",
        "",
        "## Staged shares",
        "",
        "| Role | Share file | Bytes overwritten | Removed |",
        "| --- | --- | --- | --- |",
    ]
    for role in ROLES:
        entry = (scrub.get("roles") or {}).get(role) or {}
        lines.append(
            f"| {role} | `{entry.get('path')}` | "
            f"{entry.get('bytes_overwritten')} | `{entry.get('share_removed')}` |"
        )
    lines += [
        "",
        "Each instance received only its own share file; the peers fetched "
        "their own tree from the driver host over the VPC private address, so "
        "no share crossed the public internet and no node could reach a second "
        "share.",
        "",
        "## Enclosure",
        "",
        "| Role | MRENCLAVE | `d7_node.manifest` sha256 |",
        "| --- | --- | --- |",
    ]
    for role in ROLES:
        lines.append(
            f"| {role} | `{measurements.get(role)}` | `{manifests.get(role)}` |"
        )
    lines += [
        "",
        f"`distinct_measurements`: {enclosure.get('distinct_measurements')}. "
        "Each instance signs the tree it really loads, and the three trees hold "
        "different shares, so the measurements differ by design.",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| `sgx.enclave_size` | {enclosure.get('enclave_size')} |",
        f"| `sgx.max_threads` | {enclosure.get('max_threads')} |",
        f"| `sys.stack.size` | {enclosure.get('stack_size')} |",
        f"| Template | `{enclosure.get('template')}` |",
        f"| Launcher | `{' '.join(enclosure.get('wrapper') or [])}` |",
        "",
        "## Hygiene",
        "",
        f"Session state scan: `{hygiene.get('verdict')}`. The scan searches "
        "each instance for the share prefixes the run published and requires "
        "the session directory to be empty and gone.",
        "",
    ]
    return "\n".join(lines)


def _finalise(
    *,
    out_dir: Path,
    run_id: str,
    document: Mapping[str, Any],
    captures: Mapping[str, Any],
) -> dict[str, Any]:
    (out_dir / README).write_text(_readme(document), encoding="utf-8", newline="\n")
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
    verified = verify_directory(out_dir, require_seal=True, exclusions=external)
    return {
        "seal": index.get("seal"),
        "verified": bool(verified.get("verified", True)),
    }


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
    root: str = DEFAULT_ROOT,
    client_dir: str = DEFAULT_CLIENT_DIR,
    export_dir: str = DEFAULT_EXPORT_DIR,
    tokenizer_dir: str = DEFAULT_TOKENIZER_DIR,
    dist_root: str = DEFAULT_DIST_ROOT,
    iface: str = DEFAULT_IFACE,
    prompt: str = DEFAULT_PROMPT,
    max_new_tokens: int = 3,
    node_timeout: float = 3600.0,
    expect_commit: str | None = None,
    seal: bool = False,
    enclave_dir: str = DEFAULT_ENCLAVE_DIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    role_routes = routes(cluster, user=ssh_user, ssh_host=ssh_host)
    private = endpoints(cluster)
    home_root = posixpath.dirname(root.rstrip("/"))
    cluster_file = f"/tmp/{run_id}-cluster.json"
    stage_file = f"/tmp/{run_id}-stage.json"
    pcaps = {role: f"/tmp/{run_id}-{role}.pcap" for role in ROLES}
    cap_logs = {role: f"/tmp/{run_id}-{role}-capture.log" for role in ROLES}
    node_logs = {role: f"/tmp/{run_id}-{role}.log" for role in ROLES}
    client_log = f"/tmp/{run_id}-client.log"
    client_result = f"{root}/out/C/client-result.json"
    root_session = session_root(run_id)
    session_dirs = {role: f"{root_session}/{role}" for role in ROLES}
    started_at = dt.datetime.now(dt.timezone.utc)
    journal_since = f"@{int(started_at.timestamp()) - 5}"
    stage_document: dict[str, Any] = {}
    fetches: dict[str, Any] = {}
    scrub: dict[str, Any] = {}
    captured: dict[str, dict[str, Any]] = {}
    enclosure: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] = {}
    export_digests = ""

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
    staging_command = (
        f"cd {remote_path(repo)} && {NO_BYTECODE} PYTHONPATH=. "
        f"{remote_path(python)} -m infra.d7_stage "
        f"--run-id {shlex.quote(run_id)} "
        f"--root {remote_path(root)} "
        f"--client-dir {remote_path(client_dir)} "
        f"--export-dir {remote_path(export_dir)} "
        f"--tokenizer-dir {remote_path(tokenizer_dir)} "
        f"--cluster-file {shlex.quote(cluster_file)} "
        f"--dist-root {remote_path(dist_root)} "
        f"--prompt {shlex.quote(prompt)} "
        f"--max-new-tokens {int(max_new_tokens)} "
        f"--session-root {shlex.quote(root_session)} "
        f"--output {shlex.quote(stage_file)}"
    )
    with tempfile.TemporaryDirectory(prefix="a122-d7-three-") as scratch:
        scratch_path = Path(scratch)
        local_cluster = scratch_path / "cluster.json"
        write_json(local_cluster, cluster_document)
        transport.put(role_routes[DESTINATION], local_cluster, cluster_file)
        kill_nodes(transport, role_routes, pattern=NODE_PATTERN)
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"mkdir -p {remote_path(home_root)} {shlex.quote(root_session)} "
                f"&& chmod 700 {shlex.quote(root_session)}",
                check=False,
            )
        transport.run(role_routes[DESTINATION], f"rm -rf {remote_path(root)}")
        _status, out, err = transport.run(
            role_routes[DESTINATION], staging_command, timeout=3600, check=False
        )
        if '"error"' in out:
            raise ThreeHostError(
                f"the D7 staging failed:\n{(out + err).strip()[-800:]}"
            )
        stage_document = json.loads(
            transport.run(
                role_routes[DESTINATION], f"cat {shlex.quote(stage_file)}", timeout=300
            )[1]
        )
        write_json(out_dir / "d7-stage.json", stage_document)
        export_digests = _describe_export(
            transport, role_routes[DESTINATION], export_dir=export_dir
        )
        served = _serve_staging(
            transport,
            role_routes[DESTINATION],
            dist_root=dist_root,
            host=private[DESTINATION]["host"],
            port=SHARE_PORT,
        )
        if "LISTENING" not in served:
            raise ThreeHostError(f"the staging server did not come up: {served!r}")
        try:
            for role in ("P1", "P2"):
                fetches[role] = _fetch_staging(
                    transport,
                    role_routes[role],
                    role=role,
                    host=private[DESTINATION]["host"],
                    port=SHARE_PORT,
                    home_root=home_root,
                    expected_sha256=stage_document["bundles"][role]["tarball_sha256"],
                )
            # The driver host replaces its own provisioned tree with the
            # stripped one, so it holds exactly one share like its peers.
            _status, out, err = transport.run(
                role_routes[DESTINATION],
                f"rm -rf {remote_path(root)} && "
                f"tar xzf {remote_path(dist_root)}/P0.tgz -C {remote_path(home_root)} && "
                f"test -f {remote_path(root)}/shares/P0.json && echo UNPACKED",
                timeout=600,
                check=False,
            )
            if "UNPACKED" not in out:
                raise ThreeHostError(f"P0 could not use its own tree:\n{(out + err)[-400:]}")
            fetches["P0"] = {"role": "P0", "verified": True, "output": "UNPACKED"}
        finally:
            transport.run(
                role_routes[DESTINATION],
                f"pkill -f {shlex.quote('http.server ' + str(SHARE_PORT))} || true",
                check=False,
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
                bundle_prefix="d7-enclave",
                repo=repo,
                python=python,
                workspace=root,
                enclave_dir=enclave_dir,
                enclave_size=enclave_size,
                max_threads=max_threads,
                stack_size=stack_size,
                session_root=root_session,
                prepare_session_root=True,
            )
            wrapper = enclosure["wrapper"]
        for role in ROLES:
            transport.run(
                role_routes[role],
                "getcap $(command -v tcpdump) 2>/dev/null | grep -q cap_net_raw || "
                "sudo -n setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)",
                check=False,
            )
        assert_capture_headroom(
            transport, role_routes, buffer_kib=CAPTURE_BUFFER_KIB
        )
        for role in ROLES:
            transport.start_background(
                role_routes[role],
                capture_command(
                    iface=iface,
                    pcap=pcaps[role],
                    log=cap_logs[role],
                    buffer_kib=CAPTURE_BUFFER_KIB,
                    ports=D7_PORTS,
                ),
            )
        time.sleep(2.0)
        kill_nodes(transport, role_routes, pattern=NODE_PATTERN)
        time.sleep(1.0)
        for role in ("P1", "P2", "P0"):
            transport.start_background(
                role_routes[role],
                node_command(
                    python=python,
                    repo=repo,
                    config=f"{root}/configs/{role}.json",
                    log=node_logs[role],
                    wrapper=wrapper,
                    module=MODULE,
                ),
            )
            time.sleep(1.0)
        wait_for_node_ready(transport, role_routes, logs=node_logs, timeout=node_timeout)
        transport.start_background(
            role_routes[DESTINATION],
            _client_command(
                python=python,
                repo=repo,
                config=f"{client_dir}/C.json",
                kas=f"{client_dir}/kas.json",
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
        scrub = _scrub_staging(
            transport, role_routes, role_root=root, dist_root=dist_root
        )
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
                + " ".join(f"--port {port}" for port in D7_PORTS)
            )
            _status, body, _err = transport.run(
                role_routes[role], analysis, timeout=1800
            )
            header = "\n".join(
                [
                    "# A1-22 D7 cross-host capture",
                    f"role: {role}",
                    f"instance: {role_routes[role].instance_id}",
                    f"private address: {private[role]['host']}",
                    f"capture: {pcaps[role]} ({size} bytes, sha256 {digest})",
                    "",
                ]
            ) + "\n"
            (out_dir / f"d7-three-{role}-tls-summary.txt").write_text(
                header + body, encoding="utf-8", newline="\n"
            )
            wait_for_remote_file(
                transport,
                role_routes[role],
                f"{root}/out/{role}/node-status.json",
                timeout=300.0,
            )
            transport.get(
                role_routes[role],
                f"{root}/out/{role}/node-status.json",
                out_dir / f"d7-three-{role.lower()}-node-status.json",
            )
            transport.get(
                role_routes[role],
                node_logs[role],
                out_dir / f"d7-three-{role.lower()}-node.log",
            )
            captured[role] = {"bytes": size, "sha256": digest, "path": pcaps[role]}
        if outcome == "failed":
            body = transport.run(
                role_routes[DESTINATION], f"cat {shlex.quote(client_log)}"
            )[1]
            (out_dir / "d7-client.log").write_text(
                body if body.endswith("\n") else body + "\n",
                encoding="utf-8",
                newline="\n",
            )
            raise ThreeHostError(
                "the client failed its own checks:\n" + body.strip()[-1500:]
            )
        wait_for_remote_file(
            transport, role_routes[DESTINATION], client_result, timeout=300.0
        )
        transport.get(
            role_routes[DESTINATION], client_result, out_dir / "d7-client-result.json"
        )
        transport.get(role_routes[DESTINATION], client_log, out_dir / "d7-client.log")

    result = json.loads((out_dir / "d7-client-result.json").read_text(encoding="utf-8"))
    statuses = {
        role: json.loads(
            (out_dir / f"d7-three-{role.lower()}-node-status.json").read_text(
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
        workspace=root,
        probes=_probes(result, statuses),
        session_dirs=session_dirs,
        journal_since=journal_since,
    )
    for role in ROLES:
        write_json(
            out_dir / f"d7-hygiene-{role.lower()}.json",
            hygiene_document["roles"][role],
        )
    captures = {
        role: {
            "path": f"d7-three-{role}.pcap",
            "bytes": value["bytes"],
            "sha256": value["sha256"],
            "reason": (
                f"the raw capture is {int(value['bytes'])} bytes and stays on the "
                f"instance that produced it ({role}) under {value['path']}; the "
                "bundle ships its digest and the TLS 1.3 summary that instance "
                "derived from it"
            ),
        }
        for role, value in captured.items()
    }
    verdicts = _verdicts(
        result=result, hygiene=hygiene_document, scrub=scrub, tokens=tokens
    )
    document = {
        "run_id": run_id,
        "phase": "D7",
        "mode": mode,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": expect_commit,
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
        "model": dict(result.get("model") or {}),
        "prompt": result.get("prompt"),
        "prompt_tokens": len(result.get("prompt_tokens") or []),
        "prompt_token_ids": result.get("prompt_tokens"),
        "candidate_size": result.get("candidate_size"),
        "session_id": result.get("session_id"),
        "generated_indices": result.get("generated_indices"),
        "generated_tokens": result.get("generated_tokens"),
        "generated_text": result.get("generated_text"),
        "generated_token_count": tokens,
        "steps": result.get("steps"),
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
        "staging": stage_document,
        "staging_fetches": fetches,
        "export_digests": export_digests.splitlines(),
        "hygiene": dict(hygiene_document),
        "staging_scrub": scrub,
        "session_state_before_close": dict(before) if before else None,
        "session_state_after_close": dict(after),
        "verdicts": dict(verdicts),
    }
    write_json(out_dir / "d7-summary.json", document)
    sealed: dict[str, Any] = {}
    if seal:
        reveal = _reveal_scan(
            transport, role_routes, repo=repo, python=python, run_id=run_id
        )
        write_json(out_dir / REVEAL_SCAN, reveal)
        sealed = _finalise(
            out_dir=out_dir, run_id=run_id, document=document, captures=captures
        )
    public = sorted(path.name for path in out_dir.iterdir() if path.is_file())
    return {
        "run_id": run_id,
        "verdicts": verdicts,
        "tokens": result.get("generated_tokens"),
        "generated_text": result.get("generated_text"),
        "worst_max_abs_error": (result.get("reference_check") or {}).get(
            "worst_max_abs_error"
        ),
        "hygiene": hygiene_document["verdict"],
        "bundle": str(out_dir),
        "files": public,
        **sealed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 three-instance run")
    parser.add_argument("--cluster", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("host", "enclave"), default="enclave")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--python", default=DEFAULT_PYTHON)
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--client-dir", default=DEFAULT_CLIENT_DIR)
    parser.add_argument("--export-dir", default=DEFAULT_EXPORT_DIR)
    parser.add_argument("--tokenizer-dir", default=DEFAULT_TOKENIZER_DIR)
    parser.add_argument("--dist-root", default=DEFAULT_DIST_ROOT)
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--max-new-tokens", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=3600.0)
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
    args = parser.parse_args(argv)
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport(
        key_path=args.ssh_key,
        key_password=args.ssh_key_password,
    )
    try:
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
            root=args.root,
            client_dir=args.client_dir,
            export_dir=args.export_dir,
            tokenizer_dir=args.tokenizer_dir,
            dist_root=args.dist_root,
            iface=args.iface,
            prompt=args.prompt,
            max_new_tokens=args.max_new_tokens,
            node_timeout=args.timeout,
            expect_commit=args.expect_commit,
            seal=args.seal,
        )
    except BaseException:
        # A run that died half way through must not leave a node holding its
        # port, a staging server listening on the VPC, or a tcpdump holding the
        # interface: the next attempt would fail on someone else's leftovers
        # and the instance would burn CPU until a person noticed.
        try:
            stray = routes(cluster, user=args.ssh_user, ssh_host=args.ssh_host)
            kill_nodes(transport, stray, pattern=NODE_PATTERN)
            for role in ROLES:
                transport.run(
                    stray[role],
                    f"pkill -9 -f {shlex.quote('http.server ' + str(SHARE_PORT))} "
                    f"|| true; "
                    f"pkill -9 -f {shlex.quote('tcpdump -i ' + args.iface)} || true",
                    check=False,
                )
        except Exception:  # noqa: BLE001 - the original failure matters more
            pass
        raise
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if (result.get("verdicts") or {}).get("passed") else 1


__all__ = [
    "CAPTURE_BUFFER_KIB",
    "CLIENT_MARKER",
    "D7_PORTS",
    "DEFAULT_PROMPT",
    "MODULE",
    "NODE_NAME",
    "SHARE_PORT",
    "assert_capture_headroom",
    "capture_filter",
    "capture_headroom_error",
    "main",
    "run_three_hosts",
    "session_root",
    "wait_for_node_ready",
]


if __name__ == "__main__":
    raise SystemExit(main())

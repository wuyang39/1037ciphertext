"""Drive the D5 acceptance across three instances and collect its evidence.

The single-host loopback runner in :mod:`infra.d5_acceptance` proves the
programs and the wiring, but on one machine. This module runs the same
workspace with P0, P1 and P2 on three separate instances so the SPU/YACL/BRPC
TLS 1.3 traffic crosses the VPC private network, and each host captures its own
leg. It reuses the D4 transport, capture and enclave-signing helpers; only the
node module and the collected documents differ.

The operator machine is only a driver: it provisions the workspace on P0,
carries the tarball to P1 and P2, optionally signs the enclave, starts the
capture and the node on each host, waits for the grid to finish, then pulls
back the operator error table, the case results, the communication trace and
the logs and seals the bundle.

Usage::

    python -m infra.d5_three_hosts run \
        --cluster ~/a122_cluster_enclave.json \
        --run-id d5-enclave-3host-<stamp> \
        --out-dir docs/evidence/<run-id> --mode enclave
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import posixpath
import shlex
import sys
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
    ENCLAVE_TEMPLATE,
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
from infra.d5_vectors import D5_SEED
from infra.evidence import (
    seal_directory,
    verify_directory,
    write_exclusions,
    write_json,
)


DESTINATION = "P0"
DEFAULT_WORKSPACE = "~/a122-d5/three/workspace"
MODULE = "tee.enclave.d5_node"
NODE_NAME = "d5_node"
READY_MARKER = "A122-D5-NODE-READY"
DONE_MARKER = "A122-D5-NODE-DONE"
D5_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)
REVEAL_SCAN = "d5-reveal-scan.json"
README = "README.md"
EXCLUSION_NOTE = (
    "These raw captures stay on the instances that produced them; the bundle "
    "ships their digests and the per-host TLS 1.3 summary. Every excluded file "
    "still has to match the sealed index if it is present, so restoring the "
    "original capture tightens the check instead of bypassing it."
)


def capture_filter() -> str:
    return " or ".join(f"port {port}" for port in D5_PORTS)


def _bundle(
    *,
    out_dir: Path,
    run_id: str,
    cluster: Mapping[str, Any],
    role_routes: Mapping[str, Any],
    mode: str,
    summary: Mapping[str, Any],
    captures: Mapping[str, Any],
    enclosure: Mapping[str, Any] | None,
    expect_commit: str | None,
) -> dict[str, Any]:
    private = endpoints(cluster)
    document = {
        "run_id": run_id,
        "phase": "D5",
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
        "verdicts": summary.get("verdicts"),
        "cases": summary.get("cases"),
        "passed": summary.get("passed"),
        "failed": summary.get("failed"),
        "grid_digest": summary.get("grid_digest"),
        "by_program": summary.get("by_program"),
        "seed": summary.get("seed"),
        "share_bytes": summary.get("share_bytes"),
        **_interlock(out_dir),
    }
    write_json(out_dir / "d5-summary.json", document)
    return document


def _capture_reason(*, role: str, value: Mapping[str, Any]) -> str:
    """Say why a raw capture is recorded rather than committed.

    The size is read back from the run so the note cannot claim a limit the
    file does not exceed.
    """
    return (
        f"the raw capture is {int(value['bytes'])} bytes and stays on the "
        f"instance that produced it ({role}) under {value['path']}; the bundle "
        "ships its digest and the TLS 1.3 summary that instance derived from it"
    )


def _interlock(out_dir: Path) -> dict[str, Any]:
    """Check that every role authenticated its peers as those peers' identities.

    Each node writes the digest of the certificate it presented and the digests
    of the certificates it accepted, so the three files together say whether
    the mesh authenticated one identity per role or three unrelated ones.
    """
    statuses: dict[str, Any] = {}
    for role in ROLES:
        path = Path(out_dir) / f"d5-three-{role.lower()}-node-status.json"
        try:
            statuses[role] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ThreeHostError(f"the {role} node status is unreadable: {exc}") from exc
    mismatches: list[str] = []
    for role in ROLES:
        peers = statuses[role].get("peer_certificates") or {}
        for peer, digest in peers.items():
            if digest != statuses.get(peer, {}).get("identity_sha256"):
                mismatches.append(f"{role}->{peer}")
    return {
        "peer_certificates_match": not mismatches,
        "certificate_mismatches": sorted(mismatches),
        "identity_sha256": {
            role: statuses[role].get("identity_sha256") for role in ROLES
        },
    }


def _reveal_scan(
    transport: Transport,
    role_routes: Mapping[str, Any],
    *,
    repo: str,
    python: str,
    run_id: str,
) -> dict[str, Any]:
    """Scan each instance's tree for a production reveal and return the verdicts.

    The D5 gate is about the tree the enclave evaluated, so the scan runs on
    every instance instead of on the driver's checkout, and a hit on any of
    them fails the run rather than being sealed as a footnote.
    """
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
                    role_routes[role],
                    f"cat {shlex.quote(remote)}",
                    timeout=300,
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


def _finalise(
    *,
    out_dir: Path,
    run_id: str,
    document: Mapping[str, Any],
    captures: Mapping[str, Any],
    reveal: Mapping[str, Any],
) -> dict[str, Any]:
    """Add the last two artifacts, then seal and verify the bundle.

    The raw captures are recorded as external so a restorer who puts them back
    is checked against their digests instead of being let off, and the README
    is written from the sealed summary so it cannot drift from it.
    """
    trace_path = out_dir / "d5-communication-trace.json"
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    (out_dir / README).write_text(
        _readme(run_id=run_id, document=document, reveal=reveal, trace=trace),
        encoding="utf-8",
        newline="\n",
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


def _readme(
    *,
    run_id: str,
    document: Mapping[str, Any],
    reveal: Mapping[str, Any],
    trace: Mapping[str, Any],
) -> str:
    """Describe the bundle from the numbers the run actually produced."""
    roles = document["roles"]
    enclosure = document.get("enclosure") or {}
    captures = document.get("captures") or {}
    by_program = document.get("by_program") or {}
    measurements = enclosure.get("measurements") or {}
    manifests = enclosure.get("manifest_sha256") or {}
    lines = [
        f"# D5 three-instance enclave run ({run_id})",
        "",
        "Sealed evidence for the D5 gate: the private Tiny Decoder Transformer",
        "Block, its non-linear operators and their secure Argmax evaluated by",
        "P0/P1/P2 on three separate instances with every node inside its own",
        "`gramine-sgx` enclave.",
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
        "| `d5-summary.json` | Machine-readable summary: roles, block geometry, "
        "per-program errors, the enclosure block and the capture digests |",
        "| `d5-operator-errors.json` | The per-program and per-run error table "
        "the operator machine read back from P0 |",
        "| `d5-case-results.json` | One record per case: max/mean/relative "
        "error, overflow count, tolerance, verdict, peer RTTs and TLS version |",
        "| `d5-communication-trace.json` | Per-case elapsed milliseconds and "
        "share bytes, the link settings, and the attestation facts |",
        "| `d5-reveal-scan.json` | The production-reveal scan each of the three "
        "trees was checked against |",
        "| `d5-enclave-p{0,1,2}-sign.txt`, `d5-enclave.manifest` | What each "
        "instance's `gramine-sgx-sign` printed and the manifest it signed |",
        "| `d5-three-<role>-tls-summary.txt` | Each instance's own TLS analysis "
        "of its own capture |",
        "| `d5-three-p{0,1,2}-node.log`, `d5-three-p{0,1,2}-node-status.json` | "
        "The node log and status of each role |",
        "| `evidence-index.json`, `evidence.sha256` | The seal over the "
        "directory |",
        "",
        "The raw captures stay on their instances under `/tmp/`; the three",
        "`d5-three-P{0,1,2}.pcap` entries in `<bundle>.exclusions.json` record",
        "their size and digest, and the per-instance TLS summaries are",
        "committed.",
        "",
        "## Results",
        "",
        "| Item | Result |",
        "| --- | --- |",
        f"| Cases | {document.get('cases')} total, {document.get('passed')} "
        f"passed, {document.get('failed')} failed |",
        f"| Verdict | `{document.get('verdicts')}` |",
        f"| Grid digest | `{document.get('grid_digest')}` |",
    ]
    for program in sorted(by_program):
        stats = by_program[program]
        lines.append(
            f"| `{program}` | {stats['passed']}/{stats['cases']} passed, "
            f"max_abs_error {stats['max_abs_error']:.6g}, overflow_count "
            f"{stats['overflow_count']} |"
        )
    lines += [
        "",
        "Every tolerance the cases were judged against is carried in",
        "`d5-case-results.json`; the two-sided budget of the GELU tail is in its",
        "`tail_error_per_input` and `approximation_error` fields.",
        "",
        "## Runtime",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| `inside_enclave` | `{trace.get('inside_enclave')}` |",
        f"| `attestation_available` | `{trace.get('attestation_available')}` |",
        f"| Link setup | {trace.get('link_seconds')} s, share bytes "
        f"{document.get('share_bytes')} |",
        f"| Cases traced | {len(trace.get('runs') or [])} |",
        f"| Peer certificates match | "
        f"`{document.get('peer_certificates_match')}` |",
        f"| Certificate mismatches | "
        f"{len(document.get('certificate_mismatches') or [])} |",
        "",
        "## Enclosure",
        "",
        "| Role | MRENCLAVE | `d5_node.manifest` sha256 |",
        "| --- | --- | --- |",
    ]
    for role in ROLES:
        lines.append(
            f"| {role} | `{measurements.get(role)}` | `{manifests.get(role)}` |"
        )
    lines += [
        "",
        f"`distinct_measurements`: {enclosure.get('distinct_measurements')}.",
        "Each instance signed the tree it really loaded, so the driver's",
        "default run measures three trees rather than pretending they are one;",
        "`infra/d4_three_hosts.py` is what stages a byte-identical tree across",
        "the three instances when a single shared measurement is the point.",
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
        "The scan runs on every instance against the tree that instance signed,",
        "so a plaintext reveal left in the production path on any one of them",
        "fails the run instead of being sealed as a footnote.",
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
    seed: int = D5_SEED,
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
        f"{remote_path(python)} -m infra.d5_workspace --mode provision "
        f"--root {remote_path(workspace)} --run-id {shlex.quote(run_id)} "
        f"--cluster-file {shlex.quote(cluster_file)} --seed {int(seed)}"
    )
    if dry_run:
        return {"dry_run": True, "provision": provision}

    enclosure: dict[str, Any] | None = None
    captured: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="a122-d5-three-") as scratch:
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
        transport.run(role_routes[DESTINATION], provision, timeout=600)
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
                f"rm -rf {remote_path(parent)} && mkdir -p {remote_path(parent)} && "
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
                bundle_prefix="d5-enclave",
                repo=repo,
                python=python,
                workspace=workspace,
                enclave_dir=enclave_dir,
                enclave_size=enclave_size,
                max_threads=max_threads,
                stack_size=stack_size,
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
        for role in ("P1", "P2"):
            wait_for_marker(
                transport,
                role_routes[role],
                log=node_logs[role],
                marker=READY_MARKER,
                timeout=node_timeout,
            )
        wait_for_marker(
            transport,
            role_routes[DESTINATION],
            log=node_logs[DESTINATION],
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
                    "# A1-22 D5 cross-host capture",
                    f"role: {role}",
                    f"instance: {role_routes[role].instance_id}",
                    f"private address: {private[role]['host']}",
                    f"capture: {pcaps[role]} ({size} bytes, sha256 {digest})",
                    "",
                ]
            ) + "\n"
            (out_dir / f"d5-three-{role}-tls-summary.txt").write_text(
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
                out_dir / f"d5-three-{role.lower()}-node-status.json",
            )
            transport.get(
                role_routes[role],
                node_logs[role],
                out_dir / f"d5-three-{role.lower()}-node.log",
            )
            if role == DESTINATION:
                for name in ("operator-errors.json", "case-results.json", "communication-trace.json"):
                    transport.get(
                        role_routes[role],
                        f"{workspace}/out/{role}/{name}",
                        out_dir / f"d5-{name}",
                    )
            captured[role] = {"bytes": size, "sha256": digest, "path": pcaps[role]}

    summary_path = out_dir / "d5-operator-errors.json"
    summary = (
        json.loads(summary_path.read_text(encoding="utf-8"))
        if summary_path.is_file()
        else {}
    )
    captures = {
        role: {
            "path": f"d5-three-{role}.pcap",
            "bytes": value["bytes"],
            "sha256": value["sha256"],
            "reason": _capture_reason(role=role, value=value),
        }
        for role, value in captured.items()
    }
    document = _bundle(
        out_dir=out_dir,
        run_id=run_id,
        cluster=cluster,
        role_routes=role_routes,
        mode=mode,
        summary=summary,
        captures=captures,
        enclosure=enclosure,
        expect_commit=expect_commit,
    )
    sealed: dict[str, Any] = {}
    if seal:
        reveal = _reveal_scan(
            transport,
            role_routes,
            repo=repo,
            python=python,
            run_id=run_id,
        )
        write_json(out_dir / REVEAL_SCAN, reveal)
        sealed = _finalise(
            out_dir=out_dir,
            run_id=run_id,
            document=document,
            captures=captures,
            reveal=reveal,
        )
    public = sorted(
        path.name for path in out_dir.iterdir() if path.is_file()
    )
    return {
        "run_id": run_id,
        "verdicts": summary.get("verdicts"),
        "cases": summary.get("cases"),
        "passed": summary.get("passed"),
        "failed": summary.get("failed"),
        "bundle": str(out_dir),
        "files": public,
        **sealed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D5 three-instance run")
    parser.add_argument("--cluster", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("host", "enclave"), default="enclave")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--python", default=DEFAULT_PYTHON)
    parser.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--seed", type=int, default=D5_SEED)
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
        node_timeout=args.timeout,
        expect_commit=args.expect_commit,
        seal=args.seal,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("verdicts") in (None, "passed") else 1


__all__ = [
    "D5_PORTS",
    "MODULE",
    "NODE_NAME",
    "capture_filter",
    "run_three_hosts",
]


if __name__ == "__main__":
    raise SystemExit(main())

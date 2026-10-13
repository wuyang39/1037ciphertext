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
from infra.evidence import seal_directory, verify_directory, write_json


DESTINATION = "P0"
DEFAULT_WORKSPACE = "~/a122-d5/three/workspace"
MODULE = "tee.enclave.d5_node"
NODE_NAME = "d5_node"
READY_MARKER = "A122-D5-NODE-READY"
DONE_MARKER = "A122-D5-NODE-DONE"
D5_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)


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
    }
    write_json(out_dir / "d5-summary.json", document)
    return document


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
            "reason": (
                "GitHub rejects blobs above 100 MB; the raw capture stays on "
                f"{role_routes[role].instance_id} under {value['path']} and only "
                "its digest and the derived summary are committed"
            ),
        }
        for role, value in captured.items()
    }
    _bundle(
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
    parser.add_argument("--expect-commit", default=None)
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport()
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
        dry_run=args.dry_run,
    )
    if args.seal and not args.dry_run:
        result["seal"] = seal_directory(args.out_dir)
        result["verify"] = verify_directory(args.out_dir)
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

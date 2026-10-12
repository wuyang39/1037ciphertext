"""Drive the D4 acceptance across three instances and collect its evidence.

The single-host runner in :mod:`infra.d4_acceptance` proves the transport, the
grid and every refusal case, but on one machine. This module runs the same
workspace with P0, P1 and P2 on three separate instances so the SPU/YACL/BRPC
TLS 1.3 traffic crosses the VPC private network, and each host captures its own
leg.

The operator machine is only a driver: it provisions the workspace on P0,
carries the tarball to P1 and P2, starts the capture and the node on each host,
waits for the grid to finish, then pulls back the per-role summaries, node
status, logs, vectors and communication trace and seals them with
:func:`infra.d4_evidence.finalise_cross_host`. Nothing larger than a summary
leaves the instances; the raw captures stay where they were written and the
bundle records their digests.

Nodes are started as ordinary processes over ssh. Running them under
``gramine-sgx`` is the next step and does not change this sequence: only the
command that starts a node changes.

Usage::

    python -m infra.d4_three_hosts run \
        --cluster deploy/d4-three-hosts.example.json \
        --run-id d4-3host-$(date -u +%Y%m%dT%H%M%SZ) \
        --out-dir artifacts/server/<run-id>/d4-three
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import posixpath
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d4_evidence import (
    CROSS_HOST_ROLES,
    finalise_cross_host,
)
from infra.d4_workspace import DEFAULT_BATCH, ROLES
from infra.d4_vectors import DEFAULT_COUNT
from infra.evidence import write_json


DEFAULT_IFACE = "eth0"
DEFAULT_REPO = "~/1037ciphertext"
DEFAULT_PYTHON = "~/a122-venv311/bin/python"
DEFAULT_WORKSPACE = "~/a122-d4/three/workspace"
READY_MARKER = "A122-D4-NODE-READY"
DONE_MARKER = "A122-D4-NODE-DONE"
D4_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)


class ThreeHostError(RuntimeError):
    """A step of the three-instance run failed."""


@dataclass(frozen=True)
class SSHRoute:
    """Where one role's instance lives and how to reach it."""

    role: str
    host: str
    ssh_target: str
    user: str
    instance_id: str = "unset"
    public_address: str = ""
    brpc_port: int = 0
    share_port: int = 0

    @classmethod
    def from_document(
        cls,
        role: str,
        document: Mapping[str, Any],
        *,
        user: str,
        ssh_host: str | None = None,
    ) -> "SSHRoute":
        host = str(document.get("host", "")).strip()
        if not host:
            raise ThreeHostError(f"the cluster entry for {role} has no host")
        route_user = str(document.get("user") or user)
        target_host = (
            document.get("ssh_host")
            or ssh_host
            or document.get("public_address")
            or (str(document["ssh"]).split("@")[-1] if document.get("ssh") else None)
            or host
        )
        target_host = str(target_host)
        return cls(
            role=role,
            host=host,
            user=route_user,
            ssh_target=f"{route_user}@{target_host}",
            instance_id=str(document.get("instance_id", "unset")),
            public_address=str(document.get("public_address", target_host)),
            brpc_port=int(document.get("brpc_port", 47100 + ROLES.index(role))),
            share_port=int(document.get("share_port", 47200 + ROLES.index(role))),
        )


def load_cluster(path: Path, *, user: str, ssh_host: str | None = None) -> dict[str, Any]:
    """Read the cluster description and validate the three roles are covered."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ThreeHostError(f"the cluster file is unreadable: {exc}") from exc
    missing = [role for role in ROLES if role not in document]
    if missing:
        raise ThreeHostError(
            "the cluster file is missing: " + ", ".join(missing)
        )
    return dict(document)


def routes(
    cluster: Mapping[str, Any],
    *,
    user: str,
    ssh_host: str | None = None,
) -> dict[str, SSHRoute]:
    return {
        role: SSHRoute.from_document(role, cluster[role], user=user, ssh_host=ssh_host)
        for role in ROLES
    }


def endpoints(cluster: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The private endpoints the nodes actually bind and connect to."""
    return {
        role: {
            "host": str(cluster[role]["host"]),
            "brpc_port": int(cluster[role].get("brpc_port", 47100 + ROLES.index(role))),
            "share_port": int(
                cluster[role].get("share_port", 47200 + ROLES.index(role))
            ),
        }
        for role in ROLES
    }


class Transport:
    """Run commands and move files on one instance."""

    def __init__(
        self,
        *,
        key_path: str | None = None,
        key_password: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.key_path = key_path
        self.key_password = key_password
        self.timeout = timeout
        self._clients: dict[str, Any] = {}

    def _connect(self, route: SSHRoute) -> Any:
        if route.ssh_target in self._clients:
            return self._clients[route.ssh_target]
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - operator environment
            raise ThreeHostError(
                "the three-instance runner needs paramiko: pip install paramiko"
            ) from exc
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "username": route.user,
            "timeout": 20,
            "banner_timeout": 30,
            "auth_timeout": 30,
            "look_for_keys": True,
            "allow_agent": True,
        }
        if self.key_path:
            kwargs["key_filename"] = self.key_path
            kwargs["passphrase"] = self.key_password
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = False
        client.connect(route.ssh_target.split("@")[-1], **kwargs)
        self._clients[route.ssh_target] = client
        return client

    def run(
        self,
        route: SSHRoute,
        command: str,
        *,
        timeout: float | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        """Run a command to completion and return its output.

        The exit status decides when the command is done, not end of file: a
        command that leaves a detached process behind keeps the channel open
        long after it has returned, so waiting for EOF would hang here.
        """
        client = self._connect(route)
        seconds = timeout or self.timeout
        _stdin, stdout, _stderr = client.exec_command(command, timeout=seconds)
        channel = stdout.channel
        out = bytearray()
        err = bytearray()
        deadline = time.monotonic() + seconds
        quiet_since = time.monotonic()
        while True:
            if channel.recv_ready():
                out += channel.recv(65536)
                quiet_since = time.monotonic()
                continue
            if channel.recv_stderr_ready():
                err += channel.recv_stderr(65536)
                quiet_since = time.monotonic()
                continue
            if time.monotonic() > deadline:
                channel.close()
                raise ThreeHostError(
                    f"{route.role}: command did not finish within {seconds:.0f}s: "
                    f"{command}"
                )
            # Exit status can be ready before the last bytes are readable.
            if channel.exit_status_ready() and time.monotonic() - quiet_since > 0.3:
                break
            time.sleep(0.05)
        status = channel.recv_exit_status()
        channel.close()
        text_out = out.decode("utf-8", "replace")
        text_err = err.decode("utf-8", "replace")
        if check and status != 0:
            raise ThreeHostError(
                f"{route.role}: command failed with {status}: {command}\n"
                f"{text_err.strip()}"
            )
        return status, text_out, text_err

    def start_background(
        self,
        route: SSHRoute,
        command: str,
        *,
        settle: float = 3.0,
    ) -> str:
        """Start a detached process and stop reading as soon as it is up.

        The process is ``setsid``-ed with its own stdio, so closing the channel
        ends this shell session without touching it. Whether the shell itself
        exits immediately is not worth waiting for; the caller confirms the
        process came up by watching its log.
        """
        client = self._connect(route)
        _stdin, stdout, _stderr = client.exec_command(command, timeout=settle)
        channel = stdout.channel
        collected = bytearray()
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            if channel.recv_ready():
                collected += channel.recv(65536)
            elif channel.exit_status_ready():
                break
            else:
                time.sleep(0.05)
        channel.close()
        return collected.decode("utf-8", "replace")

    def get(self, route: SSHRoute, remote: str, local: Path) -> None:
        sftp = self._connect(route).open_sftp()
        try:
            Path(local).parent.mkdir(parents=True, exist_ok=True)
            sftp.get(self._expand(sftp, remote), str(local))
        finally:
            sftp.close()

    def put(self, route: SSHRoute, local: Path, remote: str) -> None:
        sftp = self._connect(route).open_sftp()
        try:
            sftp.put(str(local), self._expand(sftp, remote))
        finally:
            sftp.close()

    @staticmethod
    def _expand(sftp: Any, remote: str) -> str:
        """Resolve a leading ``~``: sftp itself does not understand it."""
        if remote == "~" or remote.startswith("~/"):
            return sftp.normalize(".") + remote[1:]
        return remote

    def close(self) -> None:
        for client in self._clients.values():
            try:
                client.close()
            except OSError:  # pragma: no cover - transport dependent
                pass
        self._clients.clear()


def capture_filter() -> str:
    return " or ".join(f"port {port}" for port in D4_PORTS)


def remote_path(value: str) -> str:
    """Quote a path for the remote shell, expanding a leading ``~``.

    ``shlex.quote`` would freeze ``~`` into a literal directory name, so a home
    relative default has to go through ``$HOME`` and stay in double quotes.
    """
    if value == "~" or value.startswith("~/"):
        rest = value[1:].replace("\\", "\\\\").replace('"', '\\"')
        return f'"$HOME{rest}"'
    return shlex.quote(value)


def capture_command(*, iface: str, pcap: str, log: str) -> str:
    """Start a background capture that survives the ssh session ending."""
    return (
        f"rm -f {shlex.quote(pcap)}; "
        f"setsid nohup tcpdump -i {shlex.quote(iface)} -s 0 -w {shlex.quote(pcap)} "
        f"{shlex.quote(capture_filter())} > {shlex.quote(log)} 2>&1 < /dev/null & "
        f"echo started"
    )


def node_command(*, python: str, repo: str, config: str, log: str) -> str:
    return (
        f"cd {remote_path(repo)} && "
        f"setsid nohup {remote_path(python)} -m tee.enclave.spu_node "
        f"--config {remote_path(config)} > {shlex.quote(log)} 2>&1 < /dev/null & "
        f"echo started"
    )


def summary_header(
    *,
    role: str,
    instance_id: str,
    private_address: str,
    peers: Sequence[str],
    capture: str,
    size: int,
    digest: str,
) -> str:
    """The provenance block every per-host capture summary starts with."""
    return "\n".join(
        [
            "# A1-22 D4 cross-host capture",
            f"role: {role}",
            f"instance: {instance_id}",
            f"private address: {private_address}",
            f"peers configured: {' '.join(peers)}",
            f"capture: {capture} ({size} bytes, sha256 {digest})",
            "this host sees only its own legs; the three captures together cover the mesh",
            "",
        ]
    ) + "\n"


def wait_for_marker(
    transport: Transport,
    route: SSHRoute,
    *,
    log: str,
    marker: str,
    timeout: float,
    poll: float = 2.0,
) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        _status, out, _err = transport.run(
            route,
            f"grep -m1 {shlex.quote(marker)} {shlex.quote(log)} 2>/dev/null || true",
            check=False,
        )
        last = out.strip()
        if last:
            return last
        time.sleep(poll)
    raise ThreeHostError(
        f"{route.role} never reported {marker} within {timeout:.0f}s: {last!r}"
    )


def _local_head(repo: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover
        return ""


def run_three_hosts(
    *,
    cluster: Mapping[str, Any],
    out_dir: Path,
    run_id: str,
    transport: Transport,
    ssh_user: str,
    ssh_host: str | None = None,
    repo: str = DEFAULT_REPO,
    python: str = DEFAULT_PYTHON,
    workspace: str = DEFAULT_WORKSPACE,
    iface: str = DEFAULT_IFACE,
    vector_count: int = DEFAULT_COUNT,
    batch: int = DEFAULT_BATCH,
    node_timeout: float = 900.0,
    expect_commit: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Provision, distribute, run, collect and seal one three-instance run."""
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
                    f"{role} is at {out.strip() or 'unknown'}, expected {expect_commit}; "
                    "fetch and check out that commit on every instance first"
                )

    cluster_document = {
        role: {
            "host": private[role]["host"],
            "brpc_port": private[role]["brpc_port"],
            "share_port": private[role]["share_port"],
        }
        for role in ROLES
    }

    with tempfile.TemporaryDirectory(prefix="a122-d4-three-") as scratch:
        scratch_path = Path(scratch)
        local_cluster = scratch_path / "cluster.json"
        write_json(local_cluster, cluster_document)
        transport.put(role_routes["P0"], local_cluster, cluster_file)
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"mkdir -p {shlex.quote(posixpath.dirname(pcaps[role]))} "
                f"{remote_path(parent)}",
            )

        provision = (
            f"cd {remote_path(repo)} && PYTHONPATH=. {remote_path(python)} "
            f"-m infra.d4_acceptance --mode provision "
            f"--workspace {remote_path(workspace)} --run-id {shlex.quote(run_id)} "
            f"--cluster-file {shlex.quote(cluster_file)} "
            f"--vectors {int(vector_count)} --batch {int(batch)}"
        )
        captured: dict[str, dict[str, Any]] = {}
        transport.run(role_routes["P0"], f"rm -rf {remote_path(parent)}")
        transport.run(role_routes["P0"], provision, timeout=600)
        transport.run(
            role_routes["P0"],
            f"tar czf {shlex.quote(tarball)} -C {remote_path(parent)} workspace",
            timeout=600,
        )
        local_tar = scratch_path / "workspace.tgz"
        transport.get(role_routes["P0"], tarball, local_tar)
        for role in ("P1", "P2"):
            transport.put(role_routes[role], local_tar, tarball)
            transport.run(
                role_routes[role],
                f"rm -rf {remote_path(parent)} && mkdir -p {remote_path(parent)} && "
                f"tar xzf {shlex.quote(tarball)} -C {remote_path(parent)}",
                timeout=600,
            )

        if not dry_run:
            for role in ROLES:
                transport.run(
                    role_routes[role],
                    f"getcap $(command -v tcpdump) 2>/dev/null | grep -q cap_net_raw || "
                    f"sudo -n setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)",
                    check=False,
                )
                transport.start_background(
                    role_routes[role],
                    capture_command(
                        iface=iface, pcap=pcaps[role], log=cap_logs[role]
                    ),
                )
            time.sleep(2.0)

            # All three ranks join one collective: a peer's link only comes up
            # once every rank is running, so P0 must start together with the
            # others instead of after their ready markers.
            for role in ("P1", "P2", "P0"):
                transport.start_background(
                    role_routes[role],
                    node_command(
                        python=python,
                        repo=repo,
                        config=f"{workspace}/configs/{role}.json",
                        log=node_logs[role],
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
                role_routes["P0"],
                log=node_logs["P0"],
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
                peers = [peer for peer in CROSS_HOST_ROLES if peer != role]
                _status, facts, _err = transport.run(
                    role_routes[role],
                    f"stat -c%s {shlex.quote(pcaps[role])}; "
                    f"sha256sum {shlex.quote(pcaps[role])} | cut -d' ' -f1",
                )
                size_text, _, digest = facts.strip().partition("\n")
                size = int(size_text.strip())
                digest = digest.strip()
                header = summary_header(
                    role=role,
                    instance_id=role_routes[role].instance_id,
                    private_address=private[role]["host"],
                    peers=peers,
                    capture=pcaps[role],
                    size=size,
                    digest=digest,
                )
                analysis = (
                    f"cd {remote_path(repo)} && PYTHONPATH=. {remote_path(python)} "
                    f"-m infra.pcap_tls {shlex.quote(pcaps[role])} --d4-ports"
                )
                _status, body, _err = transport.run(
                    role_routes[role], analysis, timeout=1800
                )
                (out_dir / f"d4-three-{role}-tls-summary.txt").write_text(
                    header + body, encoding="utf-8"
                )
                transport.get(
                    role_routes[role],
                    f"{workspace}/out/{role}/node-status.json",
                    out_dir / f"d4-three-{role.lower()}-node-status.json",
                )
                transport.get(
                    role_routes[role],
                    node_logs[role],
                    out_dir / f"d4-three-{role.lower()}-node.log",
                )
                if role == "P0":
                    transport.get(
                        role_routes[role],
                        f"{workspace}/out/P0/rss-vectors.json",
                        out_dir / "d4-three-rss-vectors.json",
                    )
                    transport.get(
                        role_routes[role],
                        f"{workspace}/out/P0/communication-trace.json",
                        out_dir / "d4-three-communication-trace.json",
                    )
                captured[role] = {"bytes": size, "sha256": digest}

    captures = {
        role: {
            "path": f"d4-three-{role}.pcap",
            "bytes": captured.get(role, {}).get("bytes", 0),
            "sha256": captured.get(role, {}).get("sha256", ""),
            "reason": (
                "GitHub rejects blobs above 100 MB; the raw capture stays on "
                f"{role_routes[role].instance_id} under {pcaps[role]} and only "
                "its digest and the derived summary are committed"
            ),
        }
        for role in ROLES
    }
    if dry_run:
        return {"dry_run": True, "captures": captures, "provision": provision}
    return finalise_cross_host(
        out_dir,
        run_id=run_id,
        roles={
            role: {
                "instance_id": role_routes[role].instance_id,
                "private_address": private[role]["host"],
                "public_address": role_routes[role].public_address,
                "brpc_port": private[role]["brpc_port"],
                "share_port": private[role]["share_port"],
            }
            for role in ROLES
        },
        captures=captures,
        details={"commit": expect_commit or None},
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the D4 acceptance across three instances"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="provision, run, collect and seal")
    run.add_argument("--cluster", required=True, type=Path)
    run.add_argument("--out-dir", required=True, type=Path)
    run.add_argument("--run-id", default=None)
    run.add_argument("--ssh-user", default="jiahao")
    run.add_argument("--ssh-host", default=None)
    run.add_argument("--ssh-key", default=None)
    run.add_argument("--ssh-key-password", default=None)
    run.add_argument("--repo", default=DEFAULT_REPO)
    run.add_argument("--python", default=DEFAULT_PYTHON)
    run.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    run.add_argument("--iface", default=DEFAULT_IFACE)
    run.add_argument("--vectors", type=int, default=DEFAULT_COUNT)
    run.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    run.add_argument("--node-timeout", type=float, default=900.0)
    run.add_argument(
        "--expect-commit",
        default="HEAD",
        help="commit every instance must be on, or 'HEAD' for this checkout",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="provision, distribute, then report what would run",
    )
    args = parser.parse_args(argv)

    run_id = args.run_id or (
        "d4-3host-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    expect_commit = args.expect_commit
    if expect_commit == "HEAD":
        expect_commit = _local_head(Path(__file__).resolve().parents[1])
    cluster = load_cluster(args.cluster, user=args.ssh_user, ssh_host=args.ssh_host)
    transport = Transport(
        key_path=args.ssh_key,
        key_password=args.ssh_key_password,
    )
    try:
        result = run_three_hosts(
            cluster=cluster,
            out_dir=args.out_dir,
            run_id=run_id,
            transport=transport,
            ssh_user=args.ssh_user,
            ssh_host=args.ssh_host,
            repo=args.repo,
            python=args.python,
            workspace=args.workspace,
            iface=args.iface,
            vector_count=args.vectors,
            batch=args.batch,
            node_timeout=args.node_timeout,
            expect_commit=expect_commit or None,
            dry_run=args.dry_run,
        )
    except ThreeHostError as exc:
        print(f"[d4-three] FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()
    print(json.dumps(result.get("summary", result), ensure_ascii=True, sort_keys=True, indent=2))
    return 0


__all__ = [
    "D4_PORTS",
    "DEFAULT_IFACE",
    "DEFAULT_PYTHON",
    "DEFAULT_REPO",
    "DEFAULT_WORKSPACE",
    "DONE_MARKER",
    "READY_MARKER",
    "SSHRoute",
    "ThreeHostError",
    "Transport",
    "capture_command",
    "capture_filter",
    "endpoints",
    "load_cluster",
    "main",
    "node_command",
    "remote_path",
    "routes",
    "run_three_hosts",
    "summary_header",
    "wait_for_marker",
]


if __name__ == "__main__":
    raise SystemExit(main())

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
from infra.d4_workspace import (
    DEFAULT_BATCH,
    EXPECTED_REFUSALS,
    NEGATIVE_CASES,
    ROLES,
)
from infra.d4_vectors import DEFAULT_COUNT
from infra.evidence import seal_directory, verify_directory, write_json
from infra.d4_acceptance import REFUSED_MARKER


DEFAULT_IFACE = "eth0"
DEFAULT_REPO = "~/1037ciphertext"
DEFAULT_PYTHON = "~/a122-venv311/bin/python"
DEFAULT_WORKSPACE = "~/a122-d4/three/workspace"
DEFAULT_ENCLAVE_DIR = "~/a122-enclave"
# The enclave the D4 nodes run in is described once, by a template that both
# this runner and deploy/run_d4_gramine.sh render on the instance that will
# sign it, so the loopback and the cross-host runs measure the same thing.
ENCLAVE_NODE = "spu_node"
ENCLAVE_TEMPLATE = "tee/gramine/enclave/spu_node.manifest.template"
DEFAULT_ARCH_LIBDIR = "/lib/x86_64-linux-gnu"
DEFAULT_USR_LIBDIR = "/usr/lib/x86_64-linux-gnu"
DEFAULT_ENCLAVE_SIZE = "4G"
DEFAULT_MAX_THREADS = 64
DEFAULT_STACK_SIZE = "2M"
# Every host-side helper runs the interpreter against the same tree a manifest
# measures, so it must not drop ``__pycache__`` into that tree: one extra
# bytecode file changes the trusted-file list, and the instances stop
# measuring the same enclave.
NO_BYTECODE = "PYTHONDONTWRITEBYTECODE=1"
ENCLAVE_SIGNED_MARKER = "A122-D4-ENCLAVE-SIGNED"
MEASUREMENT_PREFIX = "Measurement:"
# ``plaintext`` is the probe of the live listeners, not a mutated config, so it
READY_MARKER = "A122-D4-NODE-READY"
DONE_MARKER = "A122-D4-NODE-DONE"
D4_PORTS = (47100, 47101, 47102, 47200, 47201, 47202)
# Matches every node process whatever its role or configuration. The dots are
# escaped so the pattern cannot match the shell that runs ``pkill`` itself.
NODE_PATTERN = r"tee\.enclave\.spu_node"
DRIVER = "P0"
# ``plaintext`` is the probe of the live listeners, not a mutated config, so it
# is played by the probe step rather than by a driver run.
CONFIGURED_CASES: tuple[str, ...] = tuple(
    case for case in NEGATIVE_CASES if case != "plaintext"
)


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
        return self._client(route.ssh_target, route)

    def _client(self, key: str, route: SSHRoute) -> Any:
        if key in self._clients:
            return self._clients[key]
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
        self._clients[key] = client
        return client

    def _sftp_client(self, route: SSHRoute) -> Any:
        """A connection of the ssh session family reserved for file transfer.

        The exec connection sometimes wedges -- paramiko has been seen to block
        opening a channel on a connection whose session the peer has not
        finished with -- and a transfer that shared it would hang with it.
        Keeping the transfers on their own connection means a stuck exec
        channel can no longer take the evidence with it.
        """
        return self._client(f"{route.ssh_target}#sftp", route)

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
            # Exit status can be ready before the last bytes are readable, and
            # closing the channel while the server still has output queued
            # wedges it: the peer blocks writing to a window nobody drains and
            # then cannot answer the channel opens that follow, so the next
            # sftp get on the same connection never returns. Wait for the
            # server's EOF, and fall back to a drained quiet window for a
            # server that does not send one.
            if channel.exit_status_ready() and not channel.recv_ready():
                if not channel.recv_stderr_ready():
                    if channel.eof_received or time.monotonic() - quiet_since > 2.0:
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
        sftp = self._open_sftp(route)
        try:
            Path(local).parent.mkdir(parents=True, exist_ok=True)
            sftp.get(self._expand(sftp, remote), str(local))
        finally:
            sftp.close()

    def put(self, route: SSHRoute, local: Path, remote: str) -> None:
        sftp = self._open_sftp(route)
        try:
            sftp.put(str(local), self._expand(sftp, remote))
        finally:
            sftp.close()

    def _open_sftp(self, route: SSHRoute) -> Any:
        """Open an sftp session on the transfer connection, retrying once."""
        try:
            return self._sftp_client(route).open_sftp()
        except Exception:  # noqa: BLE001 - retried on a new connection
            self._clients.pop(f"{route.ssh_target}#sftp", None)
            return self._sftp_client(route).open_sftp()

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


def node_command(
    *,
    python: str,
    repo: str,
    config: str,
    log: str,
    wrapper: Sequence[str] | None = None,
    module: str = "tee.enclave.spu_node",
) -> str:
    """Start one node, optionally under ``gramine-sgx``.

    A wrapper replaces the interpreter instead of prefixing it. Gramine hands
    the app ``[entrypoint, *argv]``, so ``gramine-sgx <manifest>`` has to
    receive the node as its own arguments, exactly as
    :mod:`infra.d4_acceptance` builds it for the loopback run.
    """
    launcher = (
        " ".join(remote_path(token) for token in wrapper)
        if wrapper
        else f"env {NO_BYTECODE} {remote_path(python)}"
    )
    return (
        f"cd {remote_path(repo)} && "
        f"setsid nohup {launcher} -m {module} "
        f"--config {remote_path(config)} > {shlex.quote(log)} 2>&1 < /dev/null & "
        f"echo started"
    )


def enclave_sign_command(
    *,
    enclave_dir: str,
    python: str,
    repo: str,
    workspace: str,
    node_name: str = ENCLAVE_NODE,
    arch_libdir: str = DEFAULT_ARCH_LIBDIR,
    usr_libdir: str = DEFAULT_USR_LIBDIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
    session_root: str = "",
) -> str:
    """Render and sign the node manifest on the instance that will run it.

    Every value the template carries is a path the instance resolves itself, so
    the measurement describes the interpreter, the venv, the repo and the
    workspace that are really there rather than a laptop's guess at them.

    ``session_root`` only matters for a template that names ``@SESSION_ROOT@``
    -- the D6 node mounts and empties one session directory -- and the sed pass
    is a no-op for the D4/D5 templates that do not carry the token, so the
    three phases keep signing the same manifests they signed before.
    """
    substitutions = [
        ("@PYTHON@", "$PY"),
        ("@ARCH_LIBDIR@", arch_libdir),
        ("@USR_LIBDIR@", usr_libdir),
        ("@UV_ROOT@", "$UV_ROOT"),
        ("@SITE@", "$SITE"),
        ("@REPO@", repo),
        ("@WORKSPACE@", workspace),
        ("@LIBSPU@", "$LIBSPU"),
        ("@ENCLAVE_SIZE@", enclave_size),
        ("@MAX_THREADS@", str(int(max_threads))),
        ("@STACK_SIZE@", stack_size),
        ("@SESSION_ROOT@", session_root),
    ]
    sed_flags = " ".join(
        f'-e "s|{token}|{value}|g"' for token, value in substitutions
    )
    return "\n".join(
        [
            "set -euo pipefail",
            f"cd {remote_path(enclave_dir)}",
            f'PY="$(readlink -f {remote_path(python)})"',
            f'VENV="$(dirname "$(dirname {remote_path(python)})")"',
            # The ABI probe runs the interpreter inside the tree the manifest
            # is about to hash, and a bytecode file left behind would be
            # measured: same flag as every other host-side helper.
            f"export {NO_BYTECODE}",
            'ABI="$("$PY" -c "import sys; print(\'python%d.%d\' % sys.version_info[:2])")"',
            'SITE="$VENV/lib/$ABI/site-packages"',
            'UV_ROOT="$(dirname "$(dirname "$PY")")"',
            'LIBSPU="$SITE/spu/libspu.so"',
            'test -f "$LIBSPU"',
            f"sed {sed_flags} {node_name}.manifest.template "
            f"> {node_name}.manifest.rendered",
            f"gramine-manifest {node_name}.manifest.rendered "
            f"> {node_name}.manifest",
            "[ -f sign.pem ] || gramine-sgx-gen-private-key sign.pem",
            f"gramine-sgx-sign --manifest {node_name}.manifest "
            f"--output {node_name}.manifest.sgx --key sign.pem",
            f"test -f {node_name}.manifest.sgx",
            # The digest lets a reader check the peers signed the same manifest
            # as the one the bundle ships.
            f"sha256sum {node_name}.manifest {node_name}.manifest.sgx",
            f"echo {ENCLAVE_SIGNED_MARKER}",
        ]
    )


def _absolute_paths(
    transport: Transport,
    route: SSHRoute,
    *,
    repo: str,
    python: str,
    workspace: str,
    enclave_dir: str,
) -> dict[str, str]:
    """Ask the instance what the ``~``-relative defaults really point at."""
    command = "\n".join(
        [
            f'echo "repo=$(cd {remote_path(repo)} && pwd)"',
            f'echo "python=$(readlink -f {remote_path(python)})"',
            f'echo "workspace=$(cd {remote_path(workspace)} && pwd)"',
            f'echo "enclave=$(mkdir -p {remote_path(enclave_dir)} && '
            f'cd {remote_path(enclave_dir)} && pwd)"',
        ]
    )
    _status, out, _err = transport.run(route, command)
    resolved: dict[str, str] = {}
    for line in out.splitlines():
        key, separator, value = line.partition("=")
        if separator and value.strip():
            resolved[key.strip()] = value.strip()
    missing = {"repo", "python", "workspace", "enclave"} - set(resolved)
    if missing:
        raise ThreeHostError(
            "could not resolve the enclave paths on "
            f"{route.role}: missing {', '.join(sorted(missing))}"
        )
    return resolved


def parse_sign_output(text: str, *, node_name: str = ENCLAVE_NODE) -> dict[str, str]:
    """Read the measurement and manifest digest out of ``gramine-sgx-sign``.

    The signer prints ``Measurement:`` on its own line with the value indented
    underneath it, then the digests of the sealed manifest.
    """
    lines = [line.strip() for line in text.splitlines()]
    measurement = ""
    for index, line in enumerate(lines):
        if line == MEASUREMENT_PREFIX and index + 1 < len(lines):
            measurement = lines[index + 1]
            break
    manifest_sha256 = ""
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[1] == f"{node_name}.manifest":
            manifest_sha256 = parts[0]
            break
    return {"measurement": measurement, "manifest_sha256": manifest_sha256}


def prepare_enclave(
    transport: Transport,
    role_routes: Mapping[str, SSHRoute],
    *,
    template: Path,
    run_id: str,
    out_dir: Path,
    node_name: str = ENCLAVE_NODE,
    bundle_prefix: str = "d4-enclave",
    repo: str = DEFAULT_REPO,
    python: str = DEFAULT_PYTHON,
    workspace: str = DEFAULT_WORKSPACE,
    enclave_dir: str = DEFAULT_ENCLAVE_DIR,
    arch_libdir: str = DEFAULT_ARCH_LIBDIR,
    usr_libdir: str = DEFAULT_USR_LIBDIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
    session_root: str = "",
    prepare_session_root: bool = False,
) -> dict[str, Any]:
    """Sign the node enclave on every instance and return how to start it.

    One signing key is generated on the driver's host and copied to the peers,
    so all three ranks measure the same enclave: both the manifest contents and
    the key's hash end up inside the measurement.

    A template that names ``@SESSION_ROOT@`` needs its directory to exist before
    Gramine resolves the manifest, so ``prepare_session_root`` creates it on
    every instance first. It is left empty, and the node fills and empties it.
    """
    template = Path(template)
    if not template.is_file():
        raise ThreeHostError(f"the enclave template is missing: {template}")
    if prepare_session_root:
        if not session_root:
            raise ThreeHostError("a session root is required to prepare one")
        for role in ROLES:
            transport.run(
                role_routes[role],
                f"mkdir -p {shlex.quote(session_root)} && "
                f"chmod 700 {shlex.quote(session_root)}",
                check=False,
            )
    resolved = _absolute_paths(
        transport,
        role_routes[DRIVER],
        repo=repo,
        python=python,
        workspace=workspace,
        enclave_dir=enclave_dir,
    )
    enclave = f"{resolved['enclave']}/{run_id}"
    command = enclave_sign_command(
        enclave_dir=enclave,
        python=python,
        repo=resolved["repo"],
        workspace=resolved["workspace"],
        node_name=node_name,
        arch_libdir=arch_libdir,
        usr_libdir=usr_libdir,
        enclave_size=enclave_size,
        max_threads=max_threads,
        stack_size=stack_size,
        session_root=session_root,
    )
    out_dir = Path(out_dir)
    measurements: dict[str, str] = {}
    digests: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="a122-enclave-") as scratch:
        key_local = Path(scratch) / "sign.pem"
        key_remote = f"{enclave}/sign.pem"
        for role in ROLES:
            route = role_routes[role]
            transport.run(route, f"mkdir -p {shlex.quote(enclave)}")
            transport.put(
                route, template, f"{enclave}/{node_name}.manifest.template"
            )
            if role != DRIVER:
                # The peers sign with the driver's key so the measurement is
                # the same on all three, not three unrelated enclaves.
                transport.put(route, key_local, key_remote)
            _status, out, err = transport.run(route, command, timeout=900)
            text = out + (f"\n{err}" if err.strip() else "")
            if ENCLAVE_SIGNED_MARKER not in text:
                raise ThreeHostError(
                    f"{role} could not sign the node enclave:\n{text.strip()}"
                )
            (out_dir / f"{bundle_prefix}-{role.lower()}-sign.txt").write_text(
                text if text.endswith("\n") else text + "\n",
                encoding="utf-8",
                newline="\n",
            )
            parsed = parse_sign_output(text, node_name=node_name)
            measurements[role] = parsed["measurement"]
            digests[role] = parsed["manifest_sha256"]
            if not parsed["measurement"] or not parsed["manifest_sha256"]:
                raise ThreeHostError(
                    f"{role} signed the enclave but reported no measurement:\n"
                    f"{text.strip()[-400:]}"
                )
            if role == DRIVER:
                transport.get(route, key_remote, key_local)
                # The three manifests have to be byte-identical, which the
                # measurements and the per-host digests in the sign logs
                # already show, so the bundle ships one copy rather than three.
                transport.get(
                    route,
                    f"{enclave}/{node_name}.manifest",
                    out_dir / f"{bundle_prefix}.manifest",
                )
    # Each instance signs the manifest it will load, and Gramine hashes whole
    # trusted directories, so the measurements agree only when the trees agree.
    # They do not have to: what the acceptance needs is that every rank ran
    # under a measurement, and the summary records all three rather than
    # pretending they are one enclave.
    distinct = sorted(set(measurements.values()))
    return {
        "directory": enclave,
        "wrapper": ["gramine-sgx", f"{enclave}/{node_name}"],
        "measurements": dict(measurements),
        "manifest_sha256": dict(digests),
        "shared_measurement": len(distinct) == 1,
        "distinct_measurements": len(distinct),
        "enclave_size": enclave_size,
        "max_threads": int(max_threads),
        "stack_size": stack_size,
        "template": template.name,
    }


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


def wait_for_remote_file(
    transport: Transport,
    route: SSHRoute,
    remote: str,
    *,
    timeout: float = 180.0,
    poll: float = 2.0,
) -> None:
    """Block until a file on the instance is written and not empty.

    A rank writes its status after its own teardown finishes, which on a slow
    or busy host happens after the driver has already stopped capturing. A
    bounded wait keeps that lag from turning into a bare ``FileNotFoundError``
    from sftp, and reports which role never got there.
    """
    deadline = time.monotonic() + timeout
    while True:
        _status, out, _err = transport.run(
            route,
            f"test -s {remote_path(remote)} && echo present || echo missing",
            check=False,
        )
        if out.strip().endswith("present"):
            return
        if time.monotonic() > deadline:
            raise ThreeHostError(
                f"{route.role} never wrote {remote} within {timeout:.0f}s"
            )
        time.sleep(poll)


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
    node_status_timeout: float = 240.0,
    expect_commit: str | None = None,
    enclave_template: Path | None = None,
    enclave_dir: str = DEFAULT_ENCLAVE_DIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
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
            f"cd {remote_path(repo)} && {NO_BYTECODE} "
            f"PYTHONPATH=. {remote_path(python)} "
            f"-m infra.d4_acceptance --mode provision "
            f"--workspace {remote_path(workspace)} --run-id {shlex.quote(run_id)} "
            f"--cluster-file {shlex.quote(cluster_file)} "
            f"--vectors {int(vector_count)} --batch {int(batch)}"
        )
        captured: dict[str, dict[str, Any]] = {}
        enclosure: dict[str, Any] | None = None
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
            wrapper: Sequence[str] | None = None
            if enclave_template is not None:
                # Sign after the workspace has landed on all three: the
                # manifest trusts it, so it has to be the real tree.
                enclosure = prepare_enclave(
                    transport,
                    role_routes,
                    template=Path(enclave_template),
                    run_id=run_id,
                    out_dir=out_dir,
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
                        wrapper=wrapper,
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
                    f"cd {remote_path(repo)} && {NO_BYTECODE} "
                    f"PYTHONPATH=. {remote_path(python)} "
                    f"-m infra.pcap_tls {shlex.quote(pcaps[role])} --d4-ports"
                )
                _status, body, _err = transport.run(
                    role_routes[role], analysis, timeout=1800
                )
                # The bundle is sealed over these bytes, so they have to be
                # the same bytes a checkout hands back: write LF, not the
                # platform default newline.
                (out_dir / f"d4-three-{role}-tls-summary.txt").write_text(
                    header + body, encoding="utf-8", newline="\n"
                )
                # Every rank reports its own link facts, but a rank only
                # writes them once its share channel and collective teardown
                # have finished, so wait for the peer instead of racing it.
                wait_for_remote_file(
                    transport,
                    role_routes[role],
                    f"{workspace}/out/{role}/node-status.json",
                    timeout=node_status_timeout,
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
        details={
            "commit": expect_commit or None,
            "enclosure": enclosure,
        },
    )


def probe_command(*, python: str, repo: str, host: str, port: int) -> str:
    """Probe one listener from the driver's own host.

    The probe runs on P0 so the bytes travel the same VPC path the mesh uses;
    it reuses the single-host probe so both runs classify a refusal the same
    way.
    """
    payload = (
        "import json;"
        "from infra.d4_acceptance import _plaintext_probe as p;"
        f"print(json.dumps(p({host!r}, {port})))"
    )
    return (
        f"cd {remote_path(repo)} && {NO_BYTECODE} "
        f"PYTHONPATH=. {remote_path(python)} -c "
        f"{shlex.quote(payload)}"
    )


def kill_nodes(transport: Transport, role_routes: Mapping[str, SSHRoute]) -> None:
    """Stop every node process on every instance."""
    for role in ROLES:
        transport.run(
            role_routes[role],
            f"pkill -f {shlex.quote(NODE_PATTERN)} || true",
            check=False,
        )


def require_workspace(
    transport: Transport,
    role_routes: Mapping[str, SSHRoute],
    *,
    workspace: str,
    cases: Sequence[str],
) -> None:
    """Refuse to start when an instance is missing the run's workspace."""
    checks = [
        f"test -f {remote_path(f'{workspace}/configs/{role}.json')}"
        for role in ROLES
    ]
    checks += [
        f"test -f {remote_path(f'{workspace}/negative/{case}.json')}"
        for case in cases
    ]
    command = " && ".join(checks)
    for role in ROLES:
        status, _out, _err = transport.run(role_routes[role], command, check=False)
        if status != 0:
            raise ThreeHostError(
                f"{role} has no usable workspace at {workspace}; run the "
                "three-instance acceptance first so all three share it"
            )


def probe_live_listeners(
    *,
    transport: Transport,
    role_routes: Mapping[str, SSHRoute],
    cluster: Mapping[str, Any],
    workspace: str,
    repo: str,
    python: str,
    run_id: str,
    probe_timeout: float = 45.0,
    poll: float = 2.0,
    wrapper: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Send plaintext at every peer listener while it is really serving.

    Only P1 and P2 run: each opens its BRPC and share listeners and then waits
    for the rest of the mesh, so the listeners are up and idle while the
    driver stays out of the way and the probes cannot race the grid. A probe
    that the peer refuses is recorded as it is, and the run waits for the
    ports to accept a connection first so a refusal is not credited to a node
    that had not finished starting.
    """
    peers = ("P1", "P2")
    logs = {role: f"/tmp/{run_id}-probe-{role}.log" for role in peers}
    kill_nodes(transport, role_routes)
    try:
        for role in (peers[1], peers[0]):
            transport.start_background(
                role_routes[role],
                node_command(
                    python=python,
                    repo=repo,
                    config=f"{workspace}/configs/{role}.json",
                    log=logs[role],
                    wrapper=wrapper,
                ),
            )
            time.sleep(0.5)
        deadline = time.monotonic() + probe_timeout
        probes: list[dict[str, Any]] = []
        for role in peers:
            for kind, key in (("brpc", "brpc_port"), ("share", "share_port")):
                port = int(cluster[role][key])
                command = probe_command(
                    python=python,
                    repo=repo,
                    host=str(cluster[role]["host"]),
                    port=port,
                )
                probe = _probe_once(transport, role_routes[DRIVER], command, role, port)
                while not probe.get("connected") and time.monotonic() < deadline:
                    time.sleep(poll)
                    probe = _probe_once(
                        transport, role_routes[DRIVER], command, role, port
                    )
                probes.append({**probe, "role": role, "listener": kind})
        return probes
    finally:
        kill_nodes(transport, role_routes)
        time.sleep(1.0)


def _probe_once(
    transport: Transport,
    route: SSHRoute,
    command: str,
    role: str,
    port: int,
) -> dict[str, Any]:
    _status, out, _err = transport.run(route, command, timeout=60)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise ThreeHostError(
            f"the probe of {role} port {port} returned nothing usable: "
            f"{out.strip()[-200:]!r}"
        ) from exc


def run_one_negative_case(
    *,
    case: str,
    transport: Transport,
    role_routes: Mapping[str, SSHRoute],
    workspace: str,
    repo: str,
    python: str,
    run_id: str,
    out_dir: Path,
    node_timeout: float,
    wrapper: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Play one fail-closed case with the peers live on their own instances."""
    expected = EXPECTED_REFUSALS[case]
    driver_config = f"{workspace}/negative/{case}.json"
    peer_logs = {role: f"/tmp/{run_id}-{case}-{role}.log" for role in ("P1", "P2")}
    kill_nodes(transport, role_routes)
    try:
        for role in ("P1", "P2"):
            transport.start_background(
                role_routes[role],
                node_command(
                    python=python,
                    repo=repo,
                    config=f"{workspace}/configs/{role}.json",
                    log=peer_logs[role],
                    wrapper=wrapper,
                ),
            )
            time.sleep(0.5)
        # Give the peers time to open their listeners before the driver
        # rejects them: a refusal has to hold against a reachable peer.
        time.sleep(2.0)
        started = time.monotonic()
        # The driver is a node too, so it runs under the same measurements as
        # its peers when the run is an enclave run.
        driver_launcher = (
            " ".join(remote_path(token) for token in wrapper)
            if wrapper
            else f"{NO_BYTECODE} PYTHONPATH=. {remote_path(python)}"
        )
        status, out, err = transport.run(
            role_routes[DRIVER],
            f"cd {remote_path(repo)} && {driver_launcher} "
            f"-m tee.enclave.spu_node --config {remote_path(driver_config)}",
            timeout=node_timeout,
            check=False,
        )
        elapsed = round(time.monotonic() - started, 3)
        driver_text = out + (f"\n{err}" if err.strip() else "")
        peers: dict[str, str] = {}
        for role in ("P1", "P2"):
            _peer_status, peer_out, _peer_err = transport.run(
                role_routes[role],
                f"tail -c 4000 {shlex.quote(peer_logs[role])} 2>/dev/null || true",
                check=False,
            )
            peers[role] = peer_out
    finally:
        kill_nodes(transport, role_routes)
        time.sleep(1.0)

    refused = REFUSED_MARKER in driver_text
    matched = expected in driver_text
    # The missing-client-certificate case is refused by the handshake rather
    # than by a certificate check, so its message names the link, not the cert.
    verdict = (
        "refused"
        if refused and status != 0 and (matched or case == "no-client-cert")
        else "unexpected"
    )
    (out_dir / f"d4-negative-{case}-p0.log").write_text(
        "\n".join(
            [
                f"# {case} driver (P0)",
                f"config: {driver_config}",
                f"exit status: {status}",
                f"expected refusal: {expected}",
                "",
            ]
        )
        + driver_text,
        encoding="utf-8",
        newline="\n",
    )
    for role, text in peers.items():
        (out_dir / f"d4-negative-{case}-{role.lower()}.log").write_text(
            "\n".join(
                [
                    f"# {case} peer {role}",
                    "the peer ran its strict configuration against the driver's",
                    "mutated one; this is the tail of its own log when the case ended",
                    "",
                ]
            )
            + text,
            encoding="utf-8",
            newline="\n",
        )
    return {
        "case": case,
        "expected": expected,
        "verdict": verdict,
        "exit_status": status,
        "elapsed_seconds": elapsed,
        "refusal_line": next(
            (line for line in driver_text.splitlines() if REFUSED_MARKER in line),
            "",
        ),
        "output_tail": "\n".join(driver_text.strip().splitlines()[-8:]),
        "peers": {
            role: {
                "bytes": len(text),
                "reported_failure": (
                    REFUSED_MARKER in text or "could not be established" in text
                ),
            }
            for role, text in peers.items()
        },
    }


def run_negative_cases(
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
    cases: Sequence[str] = CONFIGURED_CASES,
    node_timeout: float = 300.0,
    probe_timeout: float = 45.0,
    expect_commit: str | None = None,
    include_probes: bool = True,
    enclave_template: Path | None = None,
    enclave_dir: str = DEFAULT_ENCLAVE_DIR,
    enclave_size: str = DEFAULT_ENCLAVE_SIZE,
    max_threads: int = DEFAULT_MAX_THREADS,
    stack_size: str = DEFAULT_STACK_SIZE,
) -> dict[str, Any]:
    """Run every fail-closed case with the peers on their own instances.

    The positive grid proves the mesh works across the private network; this
    proves the same mesh refuses when one side is mutated: the driver runs the
    mutated configuration on P0 while P1 and P2 stay strict on their own hosts,
    and every listener is probed with plaintext while it is really serving.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    unknown = [case for case in cases if case not in CONFIGURED_CASES]
    if unknown:
        raise ThreeHostError(
            "these cases have no mutated configuration to run: "
            + ", ".join(unknown)
            + "; the plaintext case is the probe of the live listeners"
        )
    role_routes = routes(cluster, user=ssh_user, ssh_host=ssh_host)
    private = endpoints(cluster)
    if expect_commit:
        for role in ROLES:
            _status, out, _err = transport.run(
                role_routes[role],
                f"cd {remote_path(repo)} && git rev-parse HEAD",
                check=False,
            )
            if out.strip() != expect_commit:
                raise ThreeHostError(
                    f"{role} is at {out.strip() or 'unknown'}, expected "
                    f"{expect_commit}; fetch and check out that commit first"
                )
    require_workspace(
        transport, role_routes, workspace=workspace, cases=tuple(cases)
    )

    wrapper: Sequence[str] | None = None
    enclosure: dict[str, Any] | None = None
    if enclave_template is not None:
        enclosure = prepare_enclave(
            transport,
            role_routes,
            template=Path(enclave_template),
            run_id=run_id,
            out_dir=out_dir,
            repo=repo,
            python=python,
            workspace=workspace,
            enclave_dir=enclave_dir,
            enclave_size=enclave_size,
            max_threads=max_threads,
            stack_size=stack_size,
        )
        wrapper = enclosure["wrapper"]

    try:
        probes = (
            probe_live_listeners(
                transport=transport,
                role_routes=role_routes,
                cluster=private,
                workspace=workspace,
                repo=repo,
                python=python,
                run_id=run_id,
                probe_timeout=probe_timeout,
                wrapper=wrapper,
            )
            if include_probes
            else []
        )
        results = {
            case: run_one_negative_case(
                case=case,
                transport=transport,
                role_routes=role_routes,
                workspace=workspace,
                repo=repo,
                python=python,
                run_id=run_id,
                out_dir=out_dir,
                node_timeout=node_timeout,
                wrapper=wrapper,
            )
            for case in cases
        }
    finally:
        kill_nodes(transport, role_routes)

    plaintext_probes = {
        "marker": "A1-22-PLAINTEXT-PROBE",
        "driver": DRIVER,
        "probes": probes,
        "all_listeners_connected": bool(probes)
        and all(probe.get("connected") for probe in probes),
        "any_plaintext_service": any(
            probe.get("outcome") == "plaintext_service_answered" for probe in probes
        ),
    }
    write_json(out_dir / "d4-negatives-plaintext-probes.json", plaintext_probes)

    failed = [
        case for case, entry in results.items() if entry["verdict"] != "refused"
    ]
    summary = {
        "run_id": run_id,
        "phase": "D4",
        "mode": "three-instances-negatives",
        "commit": expect_commit or None,
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
        "workspace": workspace,
        "enclosure": enclosure,
        "plaintext_probes": plaintext_probes,
        "cases": results,
        "all_refused": not failed,
        "unexpected_cases": failed,
    }
    write_json(out_dir / "d4-negatives-summary.json", summary)
    index = seal_directory(out_dir)
    verify_directory(out_dir)
    if failed:
        raise ThreeHostError(
            "the fail-closed cases did not all refuse: " + ", ".join(failed)
        )
    return {"summary": summary, "index": index}


def _add_enclave_arguments(parser: argparse.ArgumentParser) -> None:
    """Let a run put the nodes in ``gramine-sgx`` instead of bare processes."""
    parser.add_argument(
        "--enclave-template",
        type=Path,
        default=None,
        help=(
            "gramine manifest template to render and sign on every instance; "
            "without it the nodes run as ordinary host processes"
        ),
    )
    parser.add_argument(
        "--enclave-dir",
        default=DEFAULT_ENCLAVE_DIR,
        help="where each instance keeps the signed manifest for this run",
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
    _add_enclave_arguments(run)
    negatives = subparsers.add_parser(
        "negatives",
        help="replay the fail-closed cases with the peers on their own hosts",
    )
    negatives.add_argument("--cluster", required=True, type=Path)
    negatives.add_argument("--out-dir", required=True, type=Path)
    negatives.add_argument("--run-id", default=None)
    negatives.add_argument("--ssh-user", default="jiahao")
    negatives.add_argument("--ssh-host", default=None)
    negatives.add_argument("--ssh-key", default=None)
    negatives.add_argument("--ssh-key-password", default=None)
    negatives.add_argument("--repo", default=DEFAULT_REPO)
    negatives.add_argument("--python", default=DEFAULT_PYTHON)
    negatives.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    negatives.add_argument("--node-timeout", type=float, default=300.0)
    negatives.add_argument(
        "--probe-timeout",
        type=float,
        default=45.0,
        help="how long to wait for the peers' listeners to accept a connection",
    )
    negatives.add_argument(
        "--no-probes",
        action="store_true",
        help="skip the plaintext probe of the live listeners",
    )
    negatives.add_argument(
        "--expect-commit",
        default="HEAD",
        help="commit every instance must be on, or 'HEAD' for this checkout",
    )
    _add_enclave_arguments(negatives)
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
        if args.command == "negatives":
            result = run_negative_cases(
                cluster=cluster,
                out_dir=args.out_dir,
                run_id=run_id,
                transport=transport,
                ssh_user=args.ssh_user,
                ssh_host=args.ssh_host,
                repo=args.repo,
                python=args.python,
                workspace=args.workspace,
                node_timeout=args.node_timeout,
                probe_timeout=args.probe_timeout,
                expect_commit=expect_commit or None,
                include_probes=not args.no_probes,
                enclave_template=args.enclave_template,
                enclave_dir=args.enclave_dir,
            )
        else:
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
                enclave_template=args.enclave_template,
                enclave_dir=args.enclave_dir,
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
    "CONFIGURED_CASES",
    "D4_PORTS",
    "DEFAULT_ENCLAVE_DIR",
    "DEFAULT_IFACE",
    "DEFAULT_PYTHON",
    "DEFAULT_REPO",
    "DEFAULT_WORKSPACE",
    "DONE_MARKER",
    "ENCLAVE_TEMPLATE",
    "READY_MARKER",
    "SSHRoute",
    "ThreeHostError",
    "Transport",
    "capture_command",
    "capture_filter",
    "enclave_sign_command",
    "endpoints",
    "kill_nodes",
    "load_cluster",
    "main",
    "node_command",
    "probe_command",
    "probe_live_listeners",
    "prepare_enclave",
    "remote_path",
    "require_workspace",
    "routes",
    "run_negative_cases",
    "run_one_negative_case",
    "run_three_hosts",
    "summary_header",
    "wait_for_marker",
    "wait_for_remote_file",
]


if __name__ == "__main__":
    raise SystemExit(main())

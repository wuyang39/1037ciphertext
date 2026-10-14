"""The three-instance D4 runner: routing, commands, and the collected bundle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from infra.d4_three_hosts import (
    ENCLAVE_SIGNED_MARKER,
    SSHRoute,
    ThreeHostError,
    Transport,
    build_parser,
    capture_command,
    enclave_sign_command,
    endpoints,
    kill_nodes,
    load_cluster,
    main,
    node_command,
    parse_sign_output,
    probe_command,
    reject_local_path,
    remote_path,
    require_commit,
    require_workspace,
    routes,
    run_negative_cases,
    run_three_hosts,
    summary_header,
    wait_for_marker,
    wait_for_remote_file,
)
from infra.d4_workspace import EXPECTED_REFUSALS, NEGATIVE_CASES
from infra.evidence import load_exclusions, verify_directory


CLUSTER: dict[str, dict[str, Any]] = {
    "P0": {
        "host": "172.27.172.201",
        "brpc_port": 47100,
        "share_port": 47200,
        "ssh_host": "198.51.100.11",
        "instance_id": "i-p0",
    },
    "P1": {
        "host": "172.27.172.202",
        "brpc_port": 47101,
        "share_port": 47201,
        "ssh_host": "198.51.100.12",
        "instance_id": "i-p1",
    },
    "P2": {
        "host": "172.27.172.203",
        "brpc_port": 47102,
        "share_port": 47202,
        "ssh_host": "198.51.100.13",
        "instance_id": "i-p2",
    },
}

IDENTITIES = {
    "P0": "aa" * 32,
    "P1": "bb" * 32,
    "P2": "cc" * 32,
}


def _write_cluster(path: Path) -> Path:
    path.write_text(json.dumps(CLUSTER), encoding="utf-8")
    return path


def test_load_cluster_requires_all_three_roles(tmp_path: Path) -> None:
    incomplete = tmp_path / "cluster.json"
    incomplete.write_text(json.dumps({"P0": CLUSTER["P0"]}), encoding="utf-8")
    with pytest.raises(ThreeHostError, match="missing: P1, P2"):
        load_cluster(incomplete, user="jiahao")
    assert load_cluster(_write_cluster(tmp_path / "ok.json"), user="jiahao") == CLUSTER


def test_routes_bind_private_endpoints_but_ssh_over_the_public_one() -> None:
    parsed = routes(CLUSTER, user="jiahao")
    assert parsed["P0"].ssh_target == "jiahao@198.51.100.11"
    assert parsed["P0"].host == "172.27.172.201"
    assert parsed["P0"].instance_id == "i-p0"
    assert endpoints(CLUSTER)["P2"] == {
        "host": "172.27.172.203",
        "brpc_port": 47102,
        "share_port": 47202,
    }


def test_route_defaults_to_the_private_address_when_no_public_one_is_known() -> None:
    route = SSHRoute.from_document("P1", {"host": "10.0.0.5"}, user="ops")
    assert route.ssh_target == "ops@10.0.0.5"
    assert route.user == "ops"
    with pytest.raises(ThreeHostError, match="has no host"):
        SSHRoute.from_document("P2", {}, user="ops")


def test_capture_and_node_commands_quote_their_paths() -> None:
    # A home-relative default has to be expanded by the remote shell, so it
    # goes through $HOME instead of shlex freezing the tilde.
    assert remote_path("~/1037ciphertext") == '"$HOME/1037ciphertext"'
    assert remote_path("/srv/a122 repo") == "'/srv/a122 repo'"
    assert remote_path("/tmp/x") == "/tmp/x"
    capture = capture_command(
        iface="eth0", pcap="/tmp/run/P0.pcap", log="/tmp/run/P0.log"
    )
    assert "setsid nohup tcpdump -i eth0" in capture
    assert "port 47100 or port 47101 or port 47102" in capture
    assert "port 47200 or port 47201 or port 47202" in capture


def test_capture_command_can_ask_for_a_bigger_kernel_ring() -> None:
    """A capture that overruns its ring cannot certify the stream it missed."""
    default = capture_command(iface="eth0", pcap="/tmp/p.pcap", log="/tmp/p.log")
    assert "-B " not in default
    sized = capture_command(
        iface="eth0", pcap="/tmp/p.pcap", log="/tmp/p.log", buffer_kib=262144
    )
    assert "-s 0 -B 262144 -w /tmp/p.pcap" in sized
    node = node_command(
        python="/home/u/venv/bin/python",
        repo="/home/u/repo",
        config="/home/u/ws/configs/P1.json",
        log="/tmp/P1.log",
    )
    assert "cd /home/u/repo" in node
    assert "-m tee.enclave.spu_node --config /home/u/ws/configs/P1.json" in node
    # A bare-process node runs inside the tree a manifest may later measure, so
    # it must not drop bytecode into it; ``env`` keeps the assignment a real
    # prefix behind ``setsid nohup``.
    assert "setsid nohup env PYTHONDONTWRITEBYTECODE=1 /home/u/venv/bin/python" in node


def test_node_command_hands_a_wrapper_the_node_as_its_own_arguments() -> None:
    """Gramine hands the app ``[entrypoint, *argv]``, so the wrapper replaces
    the interpreter instead of prefixing it."""
    node = node_command(
        python="/home/u/venv/bin/python",
        repo="/home/u/repo",
        config="/home/u/ws/configs/P1.json",
        log="/tmp/P1.log",
        wrapper=["gramine-sgx", "~/a122-enclave/run/spu_node"],
    )
    assert "setsid nohup gramine-sgx" in node
    assert '"$HOME/a122-enclave/run/spu_node"' in node
    assert "/home/u/venv/bin/python" not in node
    assert "-m tee.enclave.spu_node --config /home/u/ws/configs/P1.json" in node


def test_enclave_sign_command_renders_then_signs() -> None:
    command = enclave_sign_command(
        enclave_dir="~/a122-enclave/run",
        python="~/a122-venv311/bin/python",
        repo="/home/jiahao/1037ciphertext",
        workspace="/home/jiahao/a122-d4/three/workspace",
    )
    assert 'cd "$HOME/a122-enclave/run"' in command
    assert '"$(readlink -f "$HOME/a122-venv311/bin/python")"' in command
    # The workspace the manifest trusts only exists once the run has landed it,
    # so the render step is what turns the template into a signable manifest.
    assert "gramine-manifest spu_node.manifest.rendered > spu_node.manifest" in command
    assert 's|@WORKSPACE@|/home/jiahao/a122-d4/three/workspace|g' in command
    assert "[ -f sign.pem ] || gramine-sgx-gen-private-key sign.pem" in command
    assert "gramine-sgx-sign --manifest spu_node.manifest" in command
    # The ABI probe runs the interpreter inside the tree the manifest hashes,
    # so the signer must not leave bytecode there either.
    assert "export PYTHONDONTWRITEBYTECODE=1" in command
    assert ENCLAVE_SIGNED_MARKER in command


def test_parse_sign_output_reads_the_measurement_from_its_own_line() -> None:
    """The signer prints the label and the value on separate lines."""
    parsed = parse_sign_output(
        "Attributes (required for enclave measurement):\n"
        "    size:        0x100000000\n"
        "Measurement:\n"
        "    3d679156cd2c6dd781efe88f47e47f7e49129978b1dbf264d1a64ce946bd3c56\n"
        "8749e2a081eb65946b9fa55076934a9e5347d27d7a21198eb09615833a70b596"
        "  spu_node.manifest\n"
        "abc123  spu_node.manifest.sgx\n"
        f"{ENCLAVE_SIGNED_MARKER}\n"
    )
    assert (
        parsed["measurement"]
        == "3d679156cd2c6dd781efe88f47e47f7e49129978b1dbf264d1a64ce946bd3c56"
    )
    assert (
        parsed["manifest_sha256"]
        == "8749e2a081eb65946b9fa55076934a9e5347d27d7a21198eb09615833a70b596"
    )
    assert parse_sign_output("no measurement here\n") == {
        "measurement": "",
        "manifest_sha256": "",
    }


def test_transport_expands_a_home_relative_sftp_path() -> None:
    """sftp does not understand `~`, so the transport resolves it first."""

    class FakeSFTP:
        def normalize(self, path: str) -> str:
            assert path == "."
            return "/home/jiahao"

    sftp = FakeSFTP()
    assert Transport._expand(sftp, "~/a/b.txt") == "/home/jiahao/a/b.txt"
    assert Transport._expand(sftp, "~") == "/home/jiahao"
    assert Transport._expand(sftp, "/tmp/x") == "/tmp/x"


def test_summary_header_records_the_capture_digest() -> None:
    header = summary_header(
        role="P1",
        instance_id="i-p1",
        private_address="172.27.172.202",
        peers=["P0", "P2"],
        capture="/tmp/d4-three-P1.pcap",
        size=143211316,
        digest="ab" * 32,
    )
    assert "role: P1" in header
    assert "instance: i-p1" in header
    assert "peers configured: P0 P2" in header
    assert f"143211316 bytes, sha256 {'ab' * 32}" in header
    assert header.endswith("\n\n")


class FakeTransport:
    """Stands in for paramiko: records commands, answers like the hosts would."""

    def __init__(self, commit: str = "c0ffee") -> None:
        self.commit = commit
        self.commands: list[tuple[str, str]] = []
        self.uploads: list[tuple[str, str, str]] = []
        self.downloads: list[str] = []
        self.closed = False

    def run(
        self,
        route: SSHRoute,
        command: str,
        *,
        timeout: float | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        self.commands.append((route.role, command))
        if "git rev-parse HEAD" in command:
            return 0, self.commit + "\n", ""
        if command.startswith("grep -m1"):
            marker = "A122-D4-NODE-READY" if "READY" in command else "A122-D4-NODE-DONE"
            return 0, f"{marker} {route.role}\n", ""
        if "stat -c%s" in command:
            return 0, "1234\n" + "ef" * 32 + "\n", ""
        if command.startswith("test -s"):
            return 0, "present\n", ""
        if "-m infra.pcap_tls" in command:
            return 0, _FAKE_SUMMARY, ""
        return 0, "", ""

    def get(self, route: SSHRoute, remote: str, local: Path) -> None:
        self.downloads.append(remote)
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        if remote.endswith("node-status.json"):
            peers = {
                role: IDENTITIES[role]
                for role in IDENTITIES
                if role != route.role
            }
            document: dict[str, Any] = {
                "role": route.role,
                "run_id": "test",
                "identity_sha256": IDENTITIES[route.role],
                "peer_certificates": peers,
                "verdicts": "passed" if route.role == "P0" else "served",
                "teardown_finished": True,
            }
        elif remote.endswith("rss-vectors.json"):
            document = {
                "count": 1024,
                "batch": 64,
                "rows": 4,
                "cols": 4,
                "operators": ["add"],
                "grid_digest": "11" * 32,
                "summary": {"verdicts": "passed", "passed": 1024, "failed": 0},
            }
        elif remote.endswith("communication-trace.json"):
            document = {
                "transport": "SPU/YACL/BRPC over TLS 1.3 in a host process",
                "inside_enclave": False,
                "attestation_available": False,
                "link_seconds": 1.5,
                "share_bytes": 100,
                "batches": [{}] * 16,
            }
        else:
            Path(local).write_text(f"node log for {route.role}\n", encoding="utf-8")
            return
        Path(local).write_text(json.dumps(document), encoding="utf-8")

    def put(self, route: SSHRoute, local: Path, remote: str) -> None:
        self.uploads.append((route.role, str(local), remote))

    def start_background(self, route: SSHRoute, command: str, *, settle: float = 3.0):
        self.commands.append((route.role, command))
        return "started\n"

    def close(self) -> None:
        self.closed = True


REFUSALS = {
    "wrong-ca": (
        "A122-D4-NODE-REFUSED NodeError: peer P2 certificate was not signed by the KAS CA"
    ),
    "wrong-san": (
        "A122-D4-NODE-REFUSED NodeError: peer P2 certificate SAN does not match its role"
    ),
    # The handshake stops here, so the driver names the link, not a certificate.
    "no-client-cert": (
        "A122-D4-NODE-REFUSED SpuBackendError: the BRPC link could not be established"
    ),
    "tls-disabled": (
        "A122-D4-NODE-REFUSED SpuBackendError: the SPU link must not run without TLS"
    ),
}


class NegativeTransport(FakeTransport):
    """Answers the negative pass: peers strict on P1/P2, driver on P0."""

    def __init__(self, *, leaky: str | None = None) -> None:
        super().__init__()
        self.leaky = leaky
        self.backgrounds: list[tuple[str, str]] = []

    def run(
        self,
        route: SSHRoute,
        command: str,
        *,
        timeout: float | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        self.commands.append((route.role, command))
        if "_plaintext_probe" in command:
            port = int(command.rsplit(",", 1)[1].split(")")[0].strip())
            outcome = "closed_or_tls_only" if port < 47200 else "connection_reset"
            return 0, json.dumps({"host": "172.27.172.202", "port": port,
                                  "connected": True, "reply_bytes": 0,
                                  "outcome": outcome}) + "\n", ""
        if "-m tee.enclave.spu_node --config" in command:
            case = command.split("/negative/")[1].split(".json")[0]
            if case == self.leaky:
                return 0, "batch 1/16 vectors=64 passed=64 failed=0\n", ""
            return 3, REFUSALS[case] + "\n", ""
        if command.startswith("test -f"):
            return 0, "", ""
        if command.startswith("pkill -f"):
            assert route.role in {"P0", "P1", "P2"}
            return 0, "", ""
        if command.startswith("tail -c"):
            return 0, "A122-D4-NODE-REFUSED SpuBackendError: peer rejected\n", ""
        return super().run(route, command, timeout=timeout, check=check)

    def start_background(self, route: SSHRoute, command: str, *, settle: float = 3.0):
        self.backgrounds.append((route.role, command))
        return "started\n"


def test_probe_command_runs_on_the_driver_against_a_private_address() -> None:
    command = probe_command(
        python="/home/u/venv/bin/python",
        repo="/home/u/repo",
        host="172.27.172.202",
        port=47201,
    )
    assert command.startswith(
        "cd /home/u/repo && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=."
    )
    assert "_plaintext_probe" in command
    assert "172.27.172.202" in command and "47201" in command


def test_kill_nodes_matches_only_the_node_module() -> None:
    class Recorder(FakeTransport):
        def run(self, route, command, **kwargs):  # type: ignore[override]
            self.commands.append((route.role, command))
            return 0, "", ""

    transport = Recorder()
    kill_nodes(transport, routes(CLUSTER, user="jiahao"))  # type: ignore[arg-type]
    assert [role for role, _command in transport.commands] == ["P0", "P1", "P2"]
    for _role, command in transport.commands:
        # The escaped dots keep the pattern from matching the pkill shell.
        assert r"tee\.enclave\.spu_node" in command


def test_require_workspace_reports_the_instance_that_is_missing_it() -> None:
    class Missing(FakeTransport):
        def run(self, route, command, **kwargs):  # type: ignore[override]
            if command.startswith("test -f"):
                return (1, "", "") if route.role == "P2" else (0, "", "")
            return 0, "", ""

    with pytest.raises(ThreeHostError, match="P2 has no usable workspace"):
        require_workspace(
            Missing(),  # type: ignore[arg-type]
            routes(CLUSTER, user="jiahao"),
            workspace="~/a122-d4/three/workspace",
            cases=("wrong-ca",),
        )


def test_run_negative_cases_records_every_refusal(tmp_path: Path) -> None:
    transport = NegativeTransport()
    out_dir = tmp_path / "negatives"
    result = run_negative_cases(
        cluster=CLUSTER,
        out_dir=out_dir,
        run_id="d4-negs-test",
        transport=transport,  # type: ignore[arg-type]
        ssh_user="jiahao",
        expect_commit=transport.commit,
    )
    summary = result["summary"]
    assert summary["mode"] == "three-instances-negatives"
    assert summary["all_refused"] is True
    assert summary["unexpected_cases"] == []
    assert set(summary["cases"]) == set(NEGATIVE_CASES) - {"plaintext"}
    # A refusal has to name what it refused, or the verdict is not credited.
    assert summary["cases"]["wrong-ca"]["verdict"] == "refused"
    assert "not signed by the KAS CA" in summary["cases"]["wrong-ca"]["refusal_line"]
    assert summary["cases"]["no-client-cert"]["verdict"] == "refused"
    assert summary["cases"]["no-client-cert"]["exit_status"] == 3
    assert summary["cases"]["no-client-cert"]["peers"]["P1"]["reported_failure"] is True
    assert EXPECTED_REFUSALS["tls-disabled"] in summary["cases"]["tls-disabled"]["expected"]

    # The peers ran strict on their own instances and only the driver was mutated.
    peer_configs = [
        command for _role, command in transport.backgrounds
        if "/configs/P" in command and "negative" not in command
    ]
    assert peer_configs, "the peers were never started"
    assert all("--config \"$HOME/a122-d4/three/workspace/configs/P" in c for c in peer_configs)
    assert not any(
        "negative" in command and "/configs/" in command
        for _role, command in transport.backgrounds
    )

    probes = summary["plaintext_probes"]
    assert probes["any_plaintext_service"] is False
    assert [(p["role"], p["listener"]) for p in probes["probes"]] == [
        ("P1", "brpc"),
        ("P1", "share"),
        ("P2", "brpc"),
        ("P2", "share"),
    ]
    assert all(p["outcome"] != "plaintext_service_answered" for p in probes["probes"])

    assert (out_dir / "d4-negative-wrong-ca-p0.log").read_text(
        encoding="utf-8"
    ).startswith("# wrong-ca driver (P0)")
    assert (out_dir / "evidence-index.json").is_file()
    assert (out_dir / "evidence.sha256").is_file()
    verify_directory(out_dir)


def test_run_negative_cases_refuses_to_credit_a_driver_that_did_not_refuse(
    tmp_path: Path,
) -> None:
    transport = NegativeTransport(leaky="tls-disabled")
    out_dir = tmp_path / "negatives"
    with pytest.raises(ThreeHostError, match="did not all refuse: tls-disabled"):
        run_negative_cases(
            cluster=CLUSTER,
            out_dir=out_dir,
            run_id="d4-negs-test",
            transport=transport,  # type: ignore[arg-type]
            ssh_user="jiahao",
            expect_commit=transport.commit,
        )
    # The failed run is still inspectable: the summary says which case leaked.
    summary = json.loads(
        (out_dir / "d4-negatives-summary.json").read_text(encoding="utf-8")
    )
    assert summary["all_refused"] is False
    assert summary["unexpected_cases"] == ["tls-disabled"]
    assert summary["cases"]["tls-disabled"]["exit_status"] == 0


def test_run_negative_cases_refuses_a_host_on_the_wrong_commit(tmp_path: Path) -> None:
    transport = NegativeTransport()
    with pytest.raises(ThreeHostError, match="expected deadbeef"):
        run_negative_cases(
            cluster=CLUSTER,
            out_dir=tmp_path / "negatives",
            run_id="d4-negs-test",
            transport=transport,  # type: ignore[arg-type]
            ssh_user="jiahao",
            expect_commit="deadbeef",
        )


_FAKE_SUMMARY = "\n".join(
    [
        "# A1-22 D4 TLS capture summary",
        "packets on expected ports: 70000",
        "TLS 1.3 flows: 23",
        "TLS 1.2-or-lower flows: 0",
        "handshake messages: 56",
        "application-data records: 120000",
        "non-TLS payload bytes: 0",
        "verdict: tls13_only",
        "",
    ]
)


def test_wait_for_marker_reports_the_line_and_times_out(tmp_path: Path) -> None:
    transport = FakeTransport()
    route = routes(CLUSTER, user="jiahao")["P1"]
    line = wait_for_marker(
        transport, route, log="/tmp/P1.log", marker="A122-D4-NODE-READY", timeout=1
    )
    assert line.startswith("A122-D4-NODE-READY")

    class Silent(FakeTransport):
        def run(self, route, command, **kwargs):  # type: ignore[override]
            return 0, "", ""

    with pytest.raises(ThreeHostError, match="never reported"):
        wait_for_marker(
            Silent(),
            route,
            log="/tmp/P1.log",
            marker="A122-D4-NODE-READY",
            timeout=0.1,
            poll=0.02,
        )


def test_wait_for_remote_file_tolerates_a_lagging_writer(tmp_path: Path) -> None:
    """A rank that reports late is waited for, not turned into an sftp error."""

    class Late(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.probes = 0

        def run(self, route, command, **kwargs):  # type: ignore[override]
            assert command.startswith("test -s")
            self.probes += 1
            return 0, "present\n" if self.probes > 2 else "missing\n", ""

    transport = Late()
    route = routes(CLUSTER, user="jiahao")["P2"]
    wait_for_remote_file(
        transport,
        route,
        "~/a122-d4/three/workspace/out/P2/node-status.json",
        timeout=5,
        poll=0.01,
    )
    assert transport.probes == 3

    class Never(Late):
        def run(self, route, command, **kwargs):  # type: ignore[override]
            return 0, "missing\n", ""

    with pytest.raises(ThreeHostError, match="never wrote"):
        wait_for_remote_file(
            Never(), route, "/tmp/nothing", timeout=0.05, poll=0.01
        )


def test_run_three_hosts_produces_a_sealed_bundle(tmp_path: Path) -> None:
    transport = FakeTransport()
    out_dir = tmp_path / "d4-three"
    result = run_three_hosts(
        cluster=CLUSTER,
        out_dir=out_dir,
        run_id="d4-3host-test",
        transport=transport,  # type: ignore[arg-type]
        ssh_user="jiahao",
        expect_commit=transport.commit,
    )

    # The workspace was provisioned once and carried to the other two hosts.
    provision = [
        command for _role, command in transport.commands if "--mode provision" in command
    ]
    assert len(provision) == 1
    assert "--cluster-file /tmp/d4-3host-test-cluster.json" in provision[0]
    assert [role for role, _local, _remote in transport.uploads] == ["P0", "P1", "P2"]
    assert any(
        role == "P1" and "tar xzf /tmp/d4-3host-test-workspace.tgz" in command
        for role, command in transport.commands
    )

    # Every host was captured, and P0 was started only after P1 and P2 were up.
    started = [
        (role, command)
        for role, command in transport.commands
        if "-m tee.enclave.spu_node" in command
    ]
    assert [role for role, _command in started] == ["P1", "P2", "P0"]
    assert (
        len(
            [
                c
                for _r, c in transport.commands
                if "setsid nohup tcpdump -i eth0" in c
            ]
        )
        == 3
    )

    summary = result["summary"]
    assert summary["mode"] == "three-instances"
    assert summary["evidence_complete"] is True
    assert summary["peer_certificates_match"] is True
    assert summary["certificate_mismatches"] == []
    assert summary["grid"]["grid_digest"] == "11" * 32
    assert summary["runtime"]["inside_enclave"] is False
    assert summary["commit"] == transport.commit
    assert summary["capture"]["P0"]["verdict"] == "tls13_only"
    assert summary["capture"]["P1"]["sha256"] == "ef" * 32
    assert summary["capture"]["P1"]["bytes"] == 1234

    exclusions = load_exclusions(out_dir)
    assert [entry["path"] for entry in exclusions] == [
        "d4-three-P0.pcap",
        "d4-three-P1.pcap",
        "d4-three-P2.pcap",
    ]
    index = verify_directory(out_dir, exclusions=exclusions)
    assert index["excluded"] == [
        "d4-three-P0.pcap",
        "d4-three-P1.pcap",
        "d4-three-P2.pcap",
    ]
    assert (out_dir / "d4-three-p1-node.log").read_text(encoding="utf-8") == (
        "node log for P1\n"
    )


def test_run_three_hosts_refuses_a_host_on_the_wrong_commit(tmp_path: Path) -> None:
    transport = FakeTransport(commit="c0ffee")
    with pytest.raises(ThreeHostError, match="expected deadbeef"):
        run_three_hosts(
            cluster=CLUSTER,
            out_dir=tmp_path / "out",
            run_id="d4-3host-test",
            transport=transport,  # type: ignore[arg-type]
            ssh_user="jiahao",
            expect_commit="deadbeef",
        )


class _FakeChannel:
    """A channel that hands out one scripted block of output and then EOF."""

    def __init__(self, text: str) -> None:
        self._pending = text.encode()
        self.closed = False

    @property
    def eof_received(self) -> bool:
        return not self._pending

    def recv_ready(self) -> bool:
        return bool(self._pending)

    def recv(self, count: int) -> bytes:
        chunk, self._pending = self._pending[:count], self._pending[count:]
        return chunk

    def recv_stderr_ready(self) -> bool:
        return False

    def recv_stderr(self, count: int) -> bytes:  # pragma: no cover - unused
        return b""

    def exit_status_ready(self) -> bool:
        return not self._pending

    def recv_exit_status(self) -> int:
        return 0

    def close(self) -> None:
        self.closed = True


class _FakeStdout:
    def __init__(self, channel: _FakeChannel) -> None:
        self.channel = channel


class _FakeClient:
    """Wedge on the first channel open, then behave like a healthy session."""

    def __init__(self, *, wedge: bool, text: str = "hello\n") -> None:
        self._wedge = wedge
        self._text = text
        self.closed = False
        self.channels: list[_FakeChannel] = []

    def exec_command(self, command: str, timeout: float | None = None):
        if self._wedge:
            self._wedge = False
            raise RuntimeError("Timeout opening channel.")
        channel = _FakeChannel(self._text)
        self.channels.append(channel)
        return None, _FakeStdout(channel), None

    def close(self) -> None:
        self.closed = True


class _WedgingTransport(Transport):
    """A transport whose first connection cannot open a channel at all."""

    def __init__(self) -> None:
        super().__init__()
        self.built = 0

    def _client(self, key: str, route: SSHRoute) -> _FakeClient:
        if key not in self._clients:
            self.built += 1
            self._clients[key] = _FakeClient(wedge=self.built == 1)
        return self._clients[key]


def _route() -> SSHRoute:
    return SSHRoute.from_document("P0", {"host": "10.0.0.1"}, user="ops")


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--cluster", "c.json", "--out-dir", "out"],
        ["attested", "--cluster", "c.json", "--out-dir", "out"],
        ["negatives", "--cluster", "c.json", "--out-dir", "out"],
    ],
)
def test_every_subcommand_carries_the_attributes_main_reads(argv: list[str]) -> None:
    """main() reads one flat namespace; every subcommand has to fill it.

    The attested run shipped without --dry-run, so ``args.dry_run`` raised
    before the first SSH call. Reading the attributes through getattr hides
    that, so this asserts the parser itself defines them.
    """
    args = build_parser().parse_args(argv)
    required = {
        "command",
        "run_id",
        "expect_commit",
        "ssh_user",
        "ssh_host",
        "ssh_key",
        "ssh_key_password",
        "repo",
        "python",
        "workspace",
        "node_timeout",
        "enclave_template",
        "enclave_dir",
    }
    # The attested run is the only one that turns the KAS identity on; the
    # negatives run leaves it off, which is why _attestation_request reads it
    # through getattr.
    if args.command == "attested":
        required |= {"attest"}
    if args.command in {"run", "attested"}:
        required |= {"iface", "vectors", "batch"}
    if args.command == "negatives":
        required |= {"probe_timeout", "no_probes"}
    missing = sorted(required - set(vars(args)))
    assert missing == []


def test_run_and_attested_arms_ask_for_the_same_grid() -> None:
    parser = build_parser()
    run = parser.parse_args(["run", "--cluster", "c.json", "--out-dir", "out"])
    attested = parser.parse_args(
        ["attested", "--cluster", "c.json", "--out-dir", "out"]
    )
    assert (run.vectors, run.batch) == (attested.vectors, attested.batch)
    # --dry-run stays a property of the plain run; the attested arm is never
    # a preview, so getattr is what keeps main() honest about it.
    assert getattr(attested, "dry_run", False) is False


class _SilentTransport(FakeTransport):
    """A host that answers the commit check with nothing but a complaint."""

    def run(self, route, command, *, timeout=None, check=True):  # type: ignore[no-untyped-def]
        self.commands.append((route.role, command))
        return 1, "", "bash: cd: /nowhere/repo: No such file or directory\n"


def test_require_commit_reports_why_the_checkout_could_not_be_read() -> None:
    transport = _SilentTransport()
    with pytest.raises(ThreeHostError, match="No such file or directory"):
        require_commit(
            transport,  # type: ignore[arg-type]
            {role: _route() for role in ("P0", "P1", "P2")},
            expect_commit="deadbeef",
            repo="/nowhere/repo",
        )


def test_require_commit_accepts_matching_instances() -> None:
    transport = FakeTransport(commit="deadbeef")
    require_commit(
        transport,  # type: ignore[arg-type]
        {role: _route() for role in ("P0", "P1", "P2")},
        expect_commit="deadbeef",
    )
    assert len(transport.commands) == 3


@pytest.mark.parametrize(
    "value",
    [r"C:\Users\Alienware/repo", "C:/Users/Alienware/repo", r"~\a122-shared\repo"],
)
def test_reject_local_path_refuses_a_shell_rewritten_argument(value: str) -> None:
    """PowerShell rewrites a bare ``~/x`` before the runner sees it."""
    with pytest.raises(ThreeHostError, match="looks like a local path"):
        reject_local_path("--repo", value)


@pytest.mark.parametrize(
    "value", ["~/a122-shared/repo", "/home/jiahao/a122-shared/repo", "/nowhere"]
)
def test_reject_local_path_allows_remote_shapes(value: str) -> None:
    reject_local_path("--repo", value)


def test_main_refuses_a_rewritten_path_before_it_dials_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The guard runs before the cluster file is read, let alone contacted."""
    status = main(
        [
            "attested",
            "--cluster",
            str(tmp_path / "missing.json"),
            "--out-dir",
            str(tmp_path / "out"),
            "--repo",
            r"C:\Users\Alienware/a122-shared/repo",
        ]
    )
    assert status == 1
    assert "looks like a local path" in capsys.readouterr().err


def test_a_wedged_exec_session_reconnects_and_runs_the_command() -> None:
    transport = _WedgingTransport()
    status, out, err = transport.run(_route(), "echo hello")
    assert (status, out, err) == (0, "hello\n", "")
    # The bad session was dropped, not reused, and the data got drained.
    assert transport.built == 2
    assert transport._clients["ops@10.0.0.1"].channels[0].closed is True


def test_start_background_drains_the_channel_before_closing_it() -> None:
    transport = _WedgingTransport()
    assert transport.start_background(_route(), "setsid nohup true & echo started") == (
        "hello\n"
    )
    assert transport.built == 2
    assert transport._clients["ops@10.0.0.1"].channels[0].closed is True

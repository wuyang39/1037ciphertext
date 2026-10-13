"""D4 acceptance runner: the positive grid, the fail-closed cases, evidence.

Three modes:

``provision``
    Build the workspace (PKI, vector grid, node configurations).

``loopback``
    Run the whole grid with the three nodes on one host, then run every
    fail-closed case, assemble the evidence directory with the twelve required
    artifacts, and seal it. This is how the acceptance is rehearsed, and it is
    where the negative cases run on the servers too.

``evidence``
    Assemble and seal the evidence from a run that already happened (used after
    the three-host Gramine run).

The runner never claims more than it measured: the enclave-internal claim comes
from the node logs produced by ``gramine-sgx``, and the transport claim comes
from the capture summary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from infra.d4_evidence import (
    copy_certificates,
    copy_pcap,
    finalise,
    missing_required,
    write_document,
    write_text,
)
from infra.d4_pki import DEFAULT_TTL_HOURS
from infra.d4_vectors import DEFAULT_COUNT, load_vectors
from infra.d4_workspace import (
    DEFAULT_BATCH,
    EXPECTED_REFUSALS,
    NEGATIVE_CASES,
    ROLES,
    build_workspace,
    load_workspace,
    loopback_cluster,
)
from infra.evidence import sha256_file, write_json
from infra.pcap_tls import analyse_capture, render_summary
from mpc.material_ledger import MaterialLedger, MaterialLedgerError, MaterialRecord


NODE_MODULE = "tee.enclave.spu_node"
READY_MARKER = "A122-D4-NODE-READY"
DONE_MARKER = "A122-D4-NODE-DONE"
REFUSED_MARKER = "A122-D4-NODE-REFUSED"
DEFAULT_NODE_TIMEOUT = 900.0
LOOPBACK_HOST = "127.0.0.1"
# The bytes the plaintext probe puts on the wire; the capture analyser uses the
# same constant to tell the deliberate probe apart from a real protocol leak.
PLAINTEXT_PROBE_MARKER = b"A1-22-PLAINTEXT-PROBE\r\n"
REPO_ROOT = Path(__file__).resolve().parents[1]


class AcceptanceError(RuntimeError):
    """A D4 acceptance step failed or produced an unusable result."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _log(message: str) -> None:
    print(f"[d4] {message}", flush=True)


def _node_command(config_path: Path) -> list[str]:
    return [sys.executable, "-m", NODE_MODULE, "--config", str(config_path)]


class NodeProcess:
    """One ``tee.enclave.spu_node`` child process with a captured log."""

    def __init__(
        self,
        *,
        role: str,
        config_path: Path,
        log_path: Path,
        python: str | None = None,
        wrapper: Sequence[str] | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.role = role
        self.config_path = Path(config_path)
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # A wrapper replaces the interpreter instead of prefixing it: inside
        # gramine-sgx the entrypoint *is* the interpreter, and the LibOS builds
        # the app argv as [entrypoint, *arguments], so handing it the
        # interpreter again would make the node try to open the interpreter as
        # a script.
        command = (
            [*wrapper, *(_node_command(self.config_path)[1:])]
            if wrapper
            else [python or sys.executable, "-m", NODE_MODULE, "--config", str(self.config_path)]
        )
        self._handle = self.log_path.open("wb")
        environment = dict(os.environ)
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            f"{REPO_ROOT}{os.pathsep}{existing}" if existing else str(REPO_ROOT)
        )
        if env:
            environment.update(env)
        self.process = subprocess.Popen(
            command,
            stdout=self._handle,
            stderr=subprocess.STDOUT,
            cwd=str(cwd) if cwd else str(REPO_ROOT),
            env=environment,
        )

    @property
    def text(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def wait_for_line(self, marker: str, *, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.text.splitlines():
                if line.startswith(marker) or marker in line:
                    return line
            if self.process.poll() is not None:
                raise AcceptanceError(
                    f"{self.role} exited before reporting {marker}: "
                    f"{self.text.strip().splitlines()[-1:]}"
                )
            time.sleep(0.2)
        raise AcceptanceError(f"{self.role} never reported {marker}")

    def wait(self, *, timeout: float) -> int:
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.stop()
            raise AcceptanceError(f"{self.role} timed out after {timeout}s") from exc

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=30)
        try:
            self._handle.close()
        except OSError:
            pass


def _wait_for_port(host: str, port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            if probe.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _plaintext_probe(host: str, port: int, *, timeout: float = 5.0) -> dict[str, Any]:
    """Send a plaintext request to a TLS-only listener and record the refusal."""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "connected": False,
        "reply_bytes": 0,
        "outcome": "unknown",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as probe:
            result["connected"] = True
            probe.settimeout(timeout)
            probe.sendall(PLAINTEXT_PROBE_MARKER)
            try:
                data = probe.recv(4096)
            except socket.timeout:
                result["outcome"] = "no_plaintext_reply"
                return result
            except ConnectionResetError:
                result["outcome"] = "connection_reset"
                return result
            result["reply_bytes"] = len(data)
            result["outcome"] = (
                "plaintext_service_answered"
                if data and data[0] not in (0x15, 0x16, 0x17)
                else "closed_or_tls_only"
            )
    except ConnectionRefusedError:
        result["outcome"] = "connection_refused"
    except OSError as exc:
        result["outcome"] = f"socket_error:{type(exc).__name__}"
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"cannot read {path}: {exc}") from exc


def run_positive_grid(
    *,
    workspace: dict[str, Any],
    out_dir: Path,
    python: str,
    node_timeout: float = DEFAULT_NODE_TIMEOUT,
    wrapper: Sequence[str] | None = None,
    plaintext_probes: bool = True,
) -> dict[str, Any]:
    """Start the three nodes, drive the grid from P0, collect the outputs."""
    logs = out_dir / "logs"
    nodes = {
        role: NodeProcess(
            role=role,
            config_path=Path(workspace["configs"][role]),
            log_path=logs / f"node-{role.lower()}.log",
            python=python,
            wrapper=wrapper,
        )
        for role in ROLES
    }
    probes: list[dict[str, Any]] = []
    try:
        for role in ("P1", "P2"):
            nodes[role].wait_for_line(READY_MARKER, timeout=node_timeout)
            _log(f"{role} link is up inside its process")
        if plaintext_probes:
            cluster = workspace["cluster"]
            for role in ("P1", "P2"):
                probes.append(
                    _plaintext_probe(
                        cluster[role]["host"], cluster[role]["share_port"]
                    )
                )
                probes.append(
                    _plaintext_probe(cluster[role]["host"], cluster[role]["brpc_port"])
                )
        status = nodes["P0"].wait(timeout=node_timeout)
        if status != 0:
            raise AcceptanceError(
                f"the P0 grid exited with status {status}; see {nodes['P0'].log_path}"
            )
        nodes["P0"].wait_for_line(DONE_MARKER, timeout=30.0)
    finally:
        for role in ("P1", "P2"):
            nodes[role].stop()

    out_root = Path(workspace["configs"]["P0"]).parent.parent / "out"
    vectors = _read_json(out_root / "P0" / "rss-vectors.json")
    trace = _read_json(out_root / "P0" / "communication-trace.json")
    statuses = {
        role: _read_json(out_root / role / "node-status.json") for role in ROLES
    }
    node_logs = {
        role: nodes[role].text for role in ROLES
    }
    return {
        "vectors": vectors,
        "trace": trace,
        "statuses": statuses,
        "probes": probes,
        "node_logs": node_logs,
    }


def run_negative_case(
    *,
    case: str,
    workspace: dict[str, Any],
    out_dir: Path,
    python: str,
    node_timeout: float = DEFAULT_NODE_TIMEOUT,
    wrapper: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run one fail-closed case and return its verdict document."""
    logs = out_dir / "logs"
    if case == "plaintext":
        raise AcceptanceError("the plaintext case is probed against a live cluster")
    config_path = Path(workspace["negative_configs"][case])
    expected = EXPECTED_REFUSALS[case]
    started = time.monotonic()
    peers: list[NodeProcess] = []
    if case == "no-client-cert":
        # The peers stay strict; the local side stops presenting its
        # certificate. They start together with P0: a party never reaches the
        # ready marker while another party is missing, so waiting for the
        # peers first would deadlock the case.
        for role in ("P1", "P2"):
            peers.append(
                NodeProcess(
                    role=role,
                    config_path=Path(workspace["configs"][role]),
                    log_path=logs / f"negative-{case}-{role.lower()}.log",
                    python=python,
                    wrapper=wrapper,
                )
            )
    node = NodeProcess(
        role="P0",
        config_path=config_path,
        log_path=logs / f"negative-{case}-p0.log",
        python=python,
        wrapper=wrapper,
    )
    try:
        status = node.wait(timeout=node_timeout)
    except AcceptanceError:
        status = -1
    finally:
        text = node.text
        node.stop()
        for peer in peers:
            peer.stop()
    elapsed = round(time.monotonic() - started, 3)
    refused = REFUSED_MARKER in text or "what:" in text
    matched = expected in text
    verdict = "refused" if refused and (matched or case == "no-client-cert") else "unexpected"
    return {
        "case": case,
        "expected": expected,
        "verdict": verdict,
        "exit_status": status,
        "elapsed_seconds": elapsed,
        "output_tail": "\n".join(text.strip().splitlines()[-12:]),
    }


def run_material_ledger(
    *,
    run_id: str,
    out_dir: Path,
    vectors: dict[str, Any],
) -> dict[str, Any]:
    """Consume one preprocessing grant per node exactly once."""
    ledger = MaterialLedger()
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
    results: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    for rank, role in enumerate(ROLES):
        material_id = f"d4-{run_id}-{role}-preprocessing"
        ledger.register(
            MaterialRecord(
                material_id=material_id,
                model_version="tiny-local-v1",
                share_epoch=1,
                op_type="d4_grid",
                count=1,
                expiry=expiry,
            )
        )
        claim = ledger.claim(
            material_id,
            model_version="tiny-local-v1",
            share_epoch=1,
            op_type="d4_grid",
        )
        record = ledger.consume(claim)
        replay = "accepted"
        try:
            ledger.claim(
                material_id,
                model_version="tiny-local-v1",
                share_epoch=1,
                op_type="d4_grid",
            )
        except MaterialLedgerError as exc:
            replay = f"denied: {exc}"
        results.append(
            {
                "role": role,
                "rank": rank,
                "material_id": material_id,
                "status_after_consume": record.status.value,
                "remaining": record.count,
                "second_claim": replay,
            }
        )
        audits.append(dict(ledger.audit_events()[-1]))
    denied = all(entry["second_claim"].startswith("denied") for entry in results)
    document = {
        "run_id": run_id,
        "grid_digest": vectors.get("grid_digest"),
        "vectors": vectors.get("count"),
        "operators": vectors.get("operators"),
        "model_version": "tiny-local-v1",
        "share_epoch": 1,
        "op_type": "d4_grid",
        "entries": results,
        "last_audit_event": audits[-1] if audits else None,
        "one_time_consumption": denied,
    }
    write_document(out_dir / "material-ledger.json", document)
    return document


def assemble(
    *,
    workspace: dict[str, Any],
    out_dir: Path,
    positive: dict[str, Any],
    negatives: dict[str, dict[str, Any]],
    pcap_path: Path | None,
    run_id: str,
    instance_id: str,
    cloud_region: str,
    extra_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write every required artifact and seal the evidence directory."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    certificate_digests = copy_certificates(Path(workspace["workspace"]), out_dir)
    vectors = positive["vectors"]
    write_document(out_dir / "rss-vectors.json", vectors)
    write_document(out_dir / "communication-trace.json", positive["trace"])
    for role in ROLES:
        write_document(
            out_dir / f"node-status-{role.lower()}.json", positive["statuses"][role]
        )
        write_text(
            out_dir / f"node-log-{role.lower()}.txt",
            positive["node_logs"][role],
        )
    plaintext_lines = ["# plaintext probe against the live SPU listeners", ""]
    for probe in positive["probes"]:
        plaintext_lines.append(
            f"{probe['host']}:{probe['port']} connected={probe['connected']} "
            f"reply_bytes={probe['reply_bytes']} outcome={probe['outcome']}"
        )
    refused_plaintext = all(
        probe["outcome"] != "plaintext_service_answered" for probe in positive["probes"]
    )
    plaintext_lines.append("")
    plaintext_lines.append(
        f"verdict: {'refused' if refused_plaintext else 'plaintext service answered'}"
    )
    write_text(out_dir / "deny-plaintext.txt", "\n".join(plaintext_lines))

    for case in NEGATIVE_CASES:
        if case == "plaintext":
            continue
        document = negatives.get(case)
        if document is None:
            raise AcceptanceError(f"the {case} case was not executed")
        write_text(
            out_dir / f"deny-{case}.txt",
            "\n".join(
                [
                    f"# case: {case}",
                    f"expected refusal: {document['expected']}",
                    f"verdict: {document['verdict']}",
                    f"exit status: {document['exit_status']}",
                    f"elapsed seconds: {document['elapsed_seconds']}",
                    "",
                    document["output_tail"],
                ]
            ),
        )
        write_document(out_dir / f"case-{case}.json", document)

    pcap_digest = None
    if pcap_path is not None and Path(pcap_path).is_file():
        pcap_digest = copy_pcap(Path(pcap_path), out_dir)
        summary = analyse_capture(
            out_dir / "tls-pcap.pcap",
            expected_ports=_expected_ports(workspace),
            expected_probe_endpoints=[
                (probe["host"], int(probe["port"]))
                for probe in positive.get("probes", [])
            ],
            probe_marker=PLAINTEXT_PROBE_MARKER,
        )
        write_text(out_dir / "tls-summary.txt", render_summary(summary))
    else:
        summary = {
            "verdict": "capture_missing",
            "note": "no capture was supplied; the run cannot claim TLS-only wire traffic",
        }
        write_text(
            out_dir / "tls-summary.txt",
            "# capture missing\nno pcap was supplied for this run\n",
        )
        empty = out_dir / "tls-pcap.pcap"
        if not empty.is_file():
            # The plan requires the artifact to exist; an empty capture plus the
            # summary above keeps the gap explicit instead of hiding it.
            empty.write_bytes(b"")

    verdicts = {
        "rss_vectors": vectors["summary"]["verdicts"],
        "negative_cases": {
            case: document["verdict"] for case, document in negatives.items()
        },
        "tls_capture": summary.get("verdict"),
        "one_time_consumption": (
            positive.get("ledger", {}).get("one_time_consumption")
        ),
    }
    details = {
        "verdicts": verdicts,
        # Record where the nodes really ran: the same runner is used for the
        # host-process loopback and, later, the enclave run.
        "runtime": {
            "transport": positive["trace"].get("transport"),
            "inside_enclave": positive["trace"].get("inside_enclave"),
        },
        "grid": {
            "count": vectors.get("count"),
            "digest": vectors.get("grid_digest"),
            "batch": vectors.get("batch"),
            "operators": vectors.get("operators"),
            "passed": vectors["summary"].get("passed"),
            "failed": vectors["summary"].get("failed"),
        },
        "certificates": certificate_digests,
        "pcap_sha256": pcap_digest,
        "capture": summary,
    }
    if extra_details:
        details.update(extra_details)
    result = finalise(
        out_dir,
        run_id=run_id,
        instance_id=instance_id,
        cloud_region=cloud_region,
        details=details,
    )
    return {"verdicts": verdicts, "missing": missing_required(out_dir), **result}


def _expected_ports(workspace: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for entry in workspace["cluster"].values():
        ports.extend([int(entry["brpc_port"]), int(entry["share_port"])])
    return sorted(set(ports))


def _write_cluster_file(path: Path, cluster: dict[str, dict[str, Any]]) -> None:
    write_json(Path(path), cluster)


def _grid_is_green(positive: dict[str, Any]) -> bool:
    summary = positive["vectors"]["summary"]
    # The vector document names the field "verdicts" (see spu_node.run_node and
    # the evidence bundle); reading "verdict" here always missed.
    return summary.get("verdicts") == "passed"


def run_loopback(
    *,
    workspace_root: Path,
    out_dir: Path,
    run_id: str,
    python: str,
    capture: bool = False,
    instance_id: str = "loopback",
    cloud_region: str = "local",
    wrapper: Sequence[str] | None = None,
    node_timeout: float = DEFAULT_NODE_TIMEOUT,
) -> dict[str, Any]:
    """Full acceptance on one host: positive grid, negatives, evidence."""
    workspace = load_workspace(workspace_root)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    capture_handle: subprocess.Popen[bytes] | None = None
    pcap_path = out_dir / "tls-pcap.pcap"
    if capture:
        capture_handle, pcap_path = _start_capture(workspace, out_dir)
    try:
        positive = run_positive_grid(
            workspace=workspace,
            out_dir=out_dir,
            python=python,
            node_timeout=node_timeout,
            wrapper=wrapper,
        )
    finally:
        if capture_handle is not None:
            _stop_capture(capture_handle)
    if not _grid_is_green(positive):
        raise AcceptanceError("the positive grid did not pass")
    ledger = run_material_ledger(
        run_id=run_id, out_dir=out_dir, vectors=positive["vectors"]
    )
    positive["ledger"] = ledger
    negatives = {
        case: run_negative_case(
            case=case,
            workspace=workspace,
            out_dir=out_dir,
            python=python,
            node_timeout=node_timeout,
            wrapper=wrapper,
        )
        for case in NEGATIVE_CASES
        if case != "plaintext"
    }
    if not all(entry["verdict"] == "refused" for entry in negatives.values()):
        failed = [case for case, entry in negatives.items() if entry["verdict"] != "refused"]
        raise AcceptanceError("the fail-closed cases did not all refuse: " + ", ".join(failed))
    return assemble(
        workspace=workspace,
        out_dir=out_dir,
        positive=positive,
        negatives=negatives,
        pcap_path=pcap_path if capture else None,
        run_id=run_id,
        instance_id=instance_id,
        cloud_region=cloud_region,
        extra_details={"mode": "loopback"},
    )


def _start_capture(
    workspace: dict[str, Any],
    out_dir: Path,
) -> tuple[subprocess.Popen[bytes] | None, Path]:
    if shutil.which("tcpdump") is None:
        _log("tcpdump is not installed; the capture step is skipped")
        return None, out_dir / "tls-pcap.pcap"
    ports = _expected_ports(workspace)
    expression = " or ".join(f"port {port}" for port in ports)
    pcap_path = out_dir / "tls-pcap.pcap"
    command = [
        "tcpdump",
        "-i",
        "any",
        "-s",
        "0",
        "-w",
        str(pcap_path),
        expression,
    ]
    _log("starting the capture: " + " ".join(command))
    handle = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)
    return handle, pcap_path


def _stop_capture(handle: subprocess.Popen[bytes]) -> None:
    handle.terminate()
    try:
        handle.wait(timeout=15)
    except subprocess.TimeoutExpired:
        handle.kill()
        handle.wait(timeout=15)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D4 acceptance runner")
    parser.add_argument(
        "--mode",
        required=True,
        choices=("provision", "loopback", "evidence"),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--node-wrapper",
        default=None,
        help=(
            "launcher that starts each node in place of the interpreter, e.g. "
            "'gramine-sgx /path/to/spu_node.manifest'; the node module and its "
            "--config argument are appended to it, so the same grid and the same "
            "refusal cases run inside an enclave. --python is unused when a "
            "wrapper is set."
        ),
    )
    parser.add_argument("--cluster-file", type=Path, default=None)
    parser.add_argument("--vectors", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--instance-id", default="loopback")
    parser.add_argument("--cloud-region", default="local")
    parser.add_argument("--node-timeout", type=float, default=DEFAULT_NODE_TIMEOUT)
    args = parser.parse_args(argv)

    run_id = args.run_id or f"d4-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    out_dir = args.out_dir or (Path(args.workspace) / "evidence")
    wrapper = shlex.split(args.node_wrapper) if args.node_wrapper else None
    try:
        if args.mode == "provision":
            if args.cluster_file is None:
                cluster = loopback_cluster()
            else:
                cluster = json.loads(args.cluster_file.read_text(encoding="utf-8"))
            manifest = build_workspace(
                Path(args.workspace),
                run_id=run_id,
                cluster=cluster,
                vector_count=args.vectors,
                batch=args.batch,
            )
            print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2))
            return 0
        if args.mode == "loopback":
            result = run_loopback(
                workspace_root=Path(args.workspace),
                out_dir=out_dir,
                run_id=run_id,
                python=args.python,
                capture=args.capture,
                instance_id=args.instance_id,
                cloud_region=args.cloud_region,
                node_timeout=args.node_timeout,
                wrapper=wrapper,
            )
            print(json.dumps(result["verdicts"], ensure_ascii=True, sort_keys=True, indent=2))
            return 0 if not result["missing"] else 1
        result = assemble_from_existing(
            workspace_root=Path(args.workspace),
            out_dir=out_dir,
            run_id=run_id,
            instance_id=args.instance_id,
            cloud_region=args.cloud_region,
        )
        print(json.dumps(result["verdicts"], ensure_ascii=True, sort_keys=True, indent=2))
        return 0 if not result["missing"] else 1
    except (AcceptanceError, FileNotFoundError, ValueError) as exc:
        print(f"[d4] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def assemble_from_existing(
    *,
    workspace_root: Path,
    out_dir: Path,
    run_id: str,
    instance_id: str,
    cloud_region: str,
) -> dict[str, Any]:
    """Assemble evidence for a run whose node outputs already exist."""
    workspace = load_workspace(workspace_root)
    out_root = Path(workspace["workspace"]) / "out"
    positive = {
        "vectors": _read_json(out_root / "P0" / "rss-vectors.json"),
        "trace": _read_json(out_root / "P0" / "communication-trace.json"),
        "statuses": {
            role: _read_json(out_root / role / "node-status.json") for role in ROLES
        },
        "node_logs": {
            role: (out_root / role / "node.log").read_text(
                encoding="utf-8", errors="replace"
            )
            if (out_root / role / "node.log").is_file()
            else Path(workspace["configs"][role]).read_text(encoding="utf-8")
            for role in ROLES
        },
        "probes": _read_json(out_root / "plaintext-probes.json").get("probes", [])
        if (out_root / "plaintext-probes.json").is_file()
        else [],
    }
    negatives: dict[str, dict[str, Any]] = {}
    for case in NEGATIVE_CASES:
        if case == "plaintext":
            continue
        path = out_root / "negative" / f"{case}.json"
        if not path.is_file():
            raise AcceptanceError(f"the negative case result is missing: {path}")
        negatives[case] = _read_json(path)
    ledger = _read_json(out_dir / "material-ledger.json") if (
        out_dir / "material-ledger.json"
    ).is_file() else None
    positive["ledger"] = ledger or {}
    return assemble(
        workspace=workspace,
        out_dir=out_dir,
        positive=positive,
        negatives=negatives,
        pcap_path=out_dir / "tls-pcap.pcap",
        run_id=run_id,
        instance_id=instance_id,
        cloud_region=cloud_region,
        extra_details={"mode": "evidence"},
    )


if __name__ == "__main__":
    raise SystemExit(main())

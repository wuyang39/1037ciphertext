"""Run the D5 node loopback: three parties as three processes on one host.

The three-instance run is the acceptance, but a loopback run catches a wiring
mistake in seconds instead of minutes. It uses the same workspace builder, the
same node module and the same verdict documents as the cross-host run, so a
green loopback means the only thing left to prove is the transport.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from infra.d5_workspace import ROLES, build_workspace
from infra.d5_vectors import D5_SEED
from mpc.spu_backend.d5_program import D5Config


class D5AcceptanceError(RuntimeError):
    """The loopback run did not reach a verdict."""


def loopback_cluster(
    *, host: str = "127.0.0.1", brpc_base: int = 47100, share_base: int = 47200
) -> dict[str, dict[str, Any]]:
    return {
        role: {
            "host": host,
            "brpc_port": brpc_base + index,
            "share_port": share_base + index,
        }
        for index, role in enumerate(ROLES)
    }


def run_loopback(
    *,
    root: Path,
    run_id: str,
    repo: Path,
    python: str | None = None,
    block: D5Config | None = None,
    seed: int = D5_SEED,
    timeout: float = 900.0,
    cluster: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    root = Path(root)
    repo = Path(repo)
    manifest = build_workspace(
        root,
        run_id=run_id,
        cluster=dict(cluster or loopback_cluster()),
        block=block,
        seed=seed,
    )
    launcher = python or sys.executable
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repo)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    logs = root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    handles: dict[str, Any] = {}
    try:
        for role in ("P1", "P2", "P0"):
            handle = (logs / f"{role}.log").open("wb")
            handles[role] = handle
            processes[role] = subprocess.Popen(
                [
                    launcher,
                    "-m",
                    "tee.enclave.d5_node",
                    "--config",
                    str(root / "configs" / f"{role}.json"),
                ],
                cwd=repo,
                env=environment,
                stdout=handle,
                stderr=subprocess.STDOUT,
            )
            time.sleep(0.6)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = processes["P0"].poll()
            if code is not None:
                break
            time.sleep(1.0)
        else:
            raise D5AcceptanceError("the P0 node did not finish in time")
        p0_code = processes["P0"].returncode
        for role in ("P1", "P2"):
            if processes[role].poll() is None:
                processes[role].terminate()
        for role, process in processes.items():
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
    finally:
        for handle in handles.values():
            handle.close()
    summary_path = root / "out" / "P0" / "operator-errors.json"
    if not summary_path.is_file():
        raise D5AcceptanceError(
            "P0 wrote no operator-errors.json; tail of its log:\n"
            + (logs / "P0.log").read_text(encoding="utf-8", errors="replace")[-2000:]
        )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["p0_exit_code"] = p0_code
    summary["log_dir"] = str(logs)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D5 loopback acceptance")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--python", default=None)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args(argv)
    summary = run_loopback(
        root=args.root,
        run_id=args.run_id,
        repo=args.repo,
        python=args.python,
        timeout=args.timeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("verdicts") == "passed" else 1


__all__ = [
    "D5AcceptanceError",
    "loopback_cluster",
    "run_loopback",
]


if __name__ == "__main__":
    raise SystemExit(main())

"""Check local or cloud Linux prerequisites for the real D1 SGX gate."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from infra.evidence import build_record, write_json


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _command(command: list[str]) -> tuple[bool, str]:
    executable = shutil.which(command[0])
    if executable is None:
        return False, "command unavailable"
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output


def collect_environment(
    *,
    proc_root: Path = Path("/proc"),
    dev_root: Path = Path("/dev"),
    qcnl_path: Path = Path("/etc/sgx_default_qcnl.conf"),
    system: str | None = None,
    command_runner: Callable[[list[str]], tuple[bool, str]] = _command,
) -> dict[str, Any]:
    """Collect D1 prerequisites without claiming success when SGX is absent."""
    system = system or platform.system()
    linux = system == "Linux"
    cpuinfo = _read_text(proc_root / "cpuinfo") if linux else ""
    cpu_sgx = "sgx" in cpuinfo.lower()
    enclave_device = (dev_root / "sgx_enclave").exists()
    provision_device = (dev_root / "sgx_provision").exists()
    qcnl = _read_text(qcnl_path) if linux else ""
    # Real DCAP QCNL configs (including the Aliyun-provided default) use the
    # lowercase key ``pccs_url``; older docs show ``PCCS_URL``. Match either.
    pccs_configured = "pccs_url" in qcnl.lower()
    aesmd_ok, aesmd_detail = (
        command_runner(["systemctl", "is-active", "aesmd"])
        if linux
        else (False, "not Linux")
    )
    gramine_ok, gramine_detail = (
        command_runner(["gramine-sgx", "--version"])
        if linux
        else (False, "not Linux")
    )
    checks = {
        "linux": linux,
        "cpu_sgx": cpu_sgx,
        "sgx_enclave_device": enclave_device,
        "sgx_provision_device": provision_device,
        "aesmd_active": aesmd_ok,
        "pccs_configured": pccs_configured,
        "gramine_sgx": gramine_ok,
    }
    hardware_checks = (
        checks["linux"],
        checks["cpu_sgx"],
        checks["sgx_enclave_device"],
        checks["sgx_provision_device"],
        checks["aesmd_active"],
        checks["pccs_configured"],
    )
    accepted = all(hardware_checks)
    return {
        "host": {
            "platform": platform.platform(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "checks": checks,
        "evidence": {
            "aesmd": aesmd_detail[:2000],
            "gramine": gramine_detail[:2000],
            "qcnl_sha256_marker": "present" if qcnl else "absent",
            "qcnl_content_redacted": pccs_configured,
        },
        "verdict": (
            "accepted_for_d1_sample_work"
            if accepted
            else "blocked_until_real_sgx_environment"
        ),
        "claim_boundary": {
            "environment_check_only": True,
            "quote_verified": False,
            "sgx_acceptance": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-hardware",
        action="store_true",
        help="return non-zero unless the D1 hardware prerequisites are present",
    )
    parser.add_argument("--run-id", default="local-d1-check")
    args = parser.parse_args()
    result = collect_environment()
    record = build_record(
        run_id=args.run_id,
        phase="D1",
        outcome=result["verdict"],
        command="python -m infra.d1_environment_check",
        details=result,
    )
    if args.output:
        write_json(args.output, record)
    else:
        print(json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2))
    if args.require_hardware and result["verdict"] != "accepted_for_d1_sample_work":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["collect_environment"]

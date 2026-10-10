from __future__ import annotations

from pathlib import Path

from infra.d1_environment_check import collect_environment


def test_d1_environment_check_is_fail_closed_without_sgx(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    dev = tmp_path / "dev"
    proc.mkdir()
    dev.mkdir()
    (proc / "cpuinfo").write_text("flags: avx2\n", encoding="utf-8")
    result = collect_environment(
        proc_root=proc,
        dev_root=dev,
        qcnl_path=tmp_path / "missing.conf",
        system="Linux",
        command_runner=lambda command: (False, "inactive"),
    )
    assert result["verdict"] == "blocked_until_real_sgx_environment"
    assert result["claim_boundary"]["sgx_acceptance"] is False


def test_d1_environment_check_accepts_only_complete_prerequisites(
    tmp_path: Path,
) -> None:
    proc = tmp_path / "proc"
    dev = tmp_path / "dev"
    proc.mkdir()
    dev.mkdir()
    (proc / "cpuinfo").write_text("flags: sgx sgx_lc\n", encoding="utf-8")
    (dev / "sgx_enclave").touch()
    (dev / "sgx_provision").touch()
    qcnl = tmp_path / "qcnl.conf"
    qcnl.write_text('PCCS_URL="https://pccs.example/sgx/certification/v4/"\n')
    result = collect_environment(
        proc_root=proc,
        dev_root=dev,
        qcnl_path=qcnl,
        system="Linux",
        command_runner=lambda command: (True, "active"),
    )
    assert result["verdict"] == "accepted_for_d1_sample_work"
    assert all(result["checks"].values())

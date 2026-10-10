"""Unified local/server attack matrix with explicit pending evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from infra.evidence import build_record, write_json
from infra.security_negative import run_checks


SERVER_CHECKS: tuple[dict[str, str], ...] = (
    {
        "id": "D1-tampered-measurement",
        "phase": "D1",
        "attack": "修改受测量 enclave 文件或 release digest",
        "expected": "KAS 拒绝签发节点证书和 Lease",
    },
    {
        "id": "D1-debug-quote",
        "phase": "D1",
        "attack": "提交 sgx.debug=true 或旧 debug Quote",
        "expected": "DCAP/KAS 拒绝",
    },
    {
        "id": "D1-replayed-challenge",
        "phase": "D1",
        "attack": "重放已经消费的 challenge nonce",
        "expected": "attest 请求拒绝",
    },
    {
        "id": "D1-replaced-public-key",
        "phase": "D1",
        "attack": "替换 CSR 临时公钥但不更新 REPORTDATA",
        "expected": "REPORTDATA 绑定失败",
    },
    {
        "id": "D3-host-read-encrypted-fs",
        "phase": "D3",
        "attack": "在宿主直接读取、复制或篡改 encrypted FS",
        "expected": "无法获得可用明文且完整性校验失败",
    },
    {
        "id": "D3-missing-lease",
        "phase": "D3",
        "attack": "缺少或使用过期 Lease 启动 Worker",
        "expected": "Worker fail-closed",
    },
    {
        "id": "D4-plaintext-brpc",
        "phase": "D4",
        "attack": "连接明文 BRPC 端口或关闭 TLS",
        "expected": "Worker 不启动、无明文回退",
    },
    {
        "id": "D4-wrong-peer",
        "phase": "D4",
        "attack": "使用错误 CA、错误 SAN 或无客户端证书",
        "expected": "enclave TLS 握手拒绝",
    },
    {
        "id": "D6-result-tamper",
        "phase": "D6",
        "attack": "篡改 decode_step、ResultFrame 或混用模型",
        "expected": "客户端一致性验证拒绝",
    },
    {
        "id": "D6-ticket-replay",
        "phase": "D6",
        "attack": "重放输入、Ticket 或已消费材料",
        "expected": "进入 MPC 前拒绝",
    },
    {
        "id": "D9-host-material-scan",
        "phase": "D9",
        "attack": "扫描宿主机、日志、core dump、pcap 和临时目录",
        "expected": "不存在 Prompt share、KV、TLS 私钥或 K_disk_i",
    },
)


def build_matrix(*, run_id: str = "local-attack-matrix") -> dict[str, Any]:
    local = run_checks()
    local_checks = [
        {
            "id": f"LOCAL-{item['check']}",
            "phase": "local",
            "attack": item["check"],
            "expected": "rejected",
            "status": item["status"],
            "observed": item["reason"],
        }
        for item in local["results"]
    ]
    pending = [
        {
            **check,
            "status": "pending_server",
        }
        for check in SERVER_CHECKS
    ]
    all_local_rejected = local["all_rejected"]
    return build_record(
        run_id=run_id,
        phase="D1-D9",
        outcome=(
            "local_rejections_passed_server_checks_pending"
            if all_local_rejected
            else "local_rejection_failure"
        ),
        command="python -m infra.attack_matrix",
        details={
            "checks": [*local_checks, *pending],
            "local_check_count": len(local_checks),
            "server_pending_count": len(pending),
            "all_local_rejected": all_local_rejected,
            "claim_boundary": {
                "server_checks_executed": False,
                "sgx_acceptance": False,
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run-id", default="local-attack-matrix")
    args = parser.parse_args()
    record = build_matrix(run_id=args.run_id)
    if args.output:
        write_json(args.output, record)
    else:
        print(json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2))
    return 0 if record["details"]["all_local_rejected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SERVER_CHECKS", "build_matrix"]

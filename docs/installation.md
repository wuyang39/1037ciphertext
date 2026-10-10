# A1-22 本地开发与安装

## 依赖

- Python 3.11 或 3.12
- Windows PowerShell 7+ 或 Linux shell
- `git`
- 可选的 SGX v2、DCAP、Gramine 和 YACL/BRPC 环境，仅在服务器阶段使用

## 本地安装

从仓库根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

如果系统没有 PowerShell 激活权，可直接使用虚拟环境解释器：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## 本地验收命令

```powershell
.\deploy\run_local_checks.ps1
```

Ubuntu/WSL 使用：

```bash
./deploy/run_local_checks.sh
```

脚本会运行测试、真实 TLS 三节点联调、模型包、攻击矩阵、release 校验和证据
封存。完整能力边界见 [local-linux-development.md](local-linux-development.md)。

## 服务器阶段安装顺序

1. 按 [服务器资源准备.md](服务器资源准备.md) 选择 SGX v2/vSGX 实例，保留 DCAP 验证环境，验收后立即释放实例。
2. 构建 Gramine 镜像，确认 `sgx.debug=false`、DCAP Quote 和 encrypted FS 均可工作。
3. 部署 KAS/Audit，将其私钥放在独立控制面，不放入 P0/P1/P2 镜像。
4. 用真实 RA-TLS 替换 `mpc/spu_backend/mtls.py` 的 mock 通道，用 YACL/BRPC 启动三节点链路。
5. 运行 `tests/tee`、`tests/security`、`tests/e2e`，把 Quote、拒绝日志、pcap、trace 和宿主机扫描结果写入证据目录。

服务器阶段未通过 D1-D9 的真实硬件验收前，不得把 mock 结果写成 SGX 结论。

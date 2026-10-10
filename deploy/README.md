# A1-22 部署与本地联调

本目录提供不依赖真实 SGX 的本机 Linux/WSL 验证入口。服务器阶段脚本应在
D1 真实 Quote 通过后，基于这里的结果继续扩展，不能把本目录输出标记为 SGX
验收。

## 本机完整检查

Windows PowerShell：

```powershell
.\deploy\run_local_checks.ps1
```

Ubuntu/WSL：

```bash
chmod +x deploy/run_local_checks.sh deploy/run_local_nodes.sh
./deploy/run_local_checks.sh
```

脚本会执行：

1. 全部单元测试和 Python 编译检查。
2. 本地安全负例和 D1-D9 攻击矩阵。
3. D1 Linux/SGX 环境自检，并明确返回 `pending` 或 `accepted`。
4. 真实 localhost TCP/TLS 1.3 三节点 RSS 加法演示。
5. Tiny 模型导出、量化、三份额拆分和可选加密份额包。
6. release 构建、manifest 校验、源码脱敏扫描和证据目录封存。

输出默认写入 `artifacts/local-validation/`，不会提交到 Git。

## 三节点快速运行

```powershell
.\deploy\run_local_nodes.ps1
```

```bash
./deploy/run_local_nodes.sh
```

结果中的 `host_process_tls_termination=true` 表示 TLS 在普通 Linux 进程终止。
服务器阶段必须把证书和连接迁入 enclave，并由 YACL/BRPC 提供实际链路。

## 服务器阶段入口

服务器启动后先执行：

```bash
python -m infra.d1_environment_check --require-hardware \
  --output artifacts/server/d1-environment.json
```

该命令只有同时检测到 Linux、CPU SGX、`/dev/sgx_enclave`、
`/dev/sgx_provision`、`aesmd` 和 PCCS 配置时才会返回成功。环境检查成功仍
不代表 Quote 和 KAS 闭环完成。

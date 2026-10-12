# A1-22 本机 Linux/WSL 开发与验证

本文记录不依赖真实 SGX 的本机开发能力、运行方法和证据边界。

## 1. 适用范围

本机 Ubuntu/WSL2 可以完成：

- KAS、Ticket、Lease、审计和协议状态机。
- 真实 TCP/TLS 1.3 双向认证和三个 Linux 节点的 frame 通信。
- 3PC RSS 算术、固定点、Tiny Decoder 和端到端会话逻辑。
- 模型导出、量化、份额拆分、加密份额包和 manifest 校验。
- Gramine manifest 渲染、占位符检查和安全配置静态检查。
- 发布包、证据索引、SHA-256 封存和攻击负例矩阵。
- Docker、进程编排、端口、证书和网络参数的本机演练。

本机不能替代：

- 真实 Intel SGX/vSGX Quote。
- DCAP 远端验证、`MRENCLAVE` 和非 debug 证明。
- Gramine-SGX 的 enclave 隔离和 encrypted FS 保护。
- enclave 内终止的 YACL/BRPC mTLS。
- EPC、宿主攻击、真实启动延迟和最终性能数据。

## 2. 本机能力检查

当前开发机已具备 Ubuntu 22.04 WSL2、GCC 和 Python。WSL 中没有
`/dev/sgx_enclave`、`/dev/sgx_provision`，因此 D1 硬件门保持 pending。

建议安装本机 Linux 构建工具：

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build python3-venv python3-pip \
  tcpdump iproute2
```

Docker Desktop 可选。未启动 Docker 时，三节点以独立 Linux 线程和真实 socket
运行；启动 Docker 后可继续扩展为三个容器或三个独立进程。

## 3. 完整本地检查

Ubuntu/WSL：

```bash
chmod +x deploy/run_local_checks.sh deploy/run_local_nodes.sh
./deploy/run_local_checks.sh
```

Windows PowerShell：

```powershell
.\deploy\run_local_checks.ps1
```

输出默认写入 `artifacts/local-validation/`。该目录被 release 构建排除，不进入
Git。

## 4. 本机已实现的验证项

### 4.1 Native SM4-GCM

默认 `crypto.sm4_gcm.SM4GCM` 使用 OpenSSL native SM4 与 native GCM：

```text
provider_name = openssl-native-sm4-gcm
```

`PurePythonSM4GCM` 只保留为显式测试 oracle，不再被生产路径隐式选择。RFC 8998
和 GB/T 36624-2018 向量同时验证 native 与 Python oracle。

### 4.2 真实 localhost TLS 1.3

`mpc/spu_backend/transport.py` 使用真实 TCP、X.509、双向证书、TLS 1.3 和
length-prefixed frames。`infra/local_three_node.py` 建立 P0、P1、P2 三个监听
端点，并验证：

- P0 到 P1。
- P0 到 P2。
- P1 到 P2。
- 错误角色 SAN 和不被信任 CA 的拒绝。

这里的 TLS 在宿主 Linux 进程终止。服务器阶段必须迁入 enclave。

### 4.3 可替换 secure nonlinear provider

`mpc/secure_ops/provider.py` 提供：

- `SimulationRevealProvider`：显式本地模拟。
- `FailClosedSecureNonlinearProvider`：未配置安全算子时拒绝。
- `SecureNonlinearProvider`：YACL/SPU 后端替换接口。

生产路径必须注入已审计 provider，不得启用 simulation reveal。

### 4.4 模型包

Tiny 模型可以完整执行：

```bash
python -m infra.build_model_package \
  --output artifacts/local-validation/model-package \
  --encrypt-local

python -m infra.build_model_package \
  --output artifacts/local-validation/model-package \
  --verify
```

生成内容包括模型导出、量化 payload、precision plan、P0/P1/P2 份额、可选加密
份额和 package manifest。正式英文 GPT-2 权重在 D7 冻结后运行同一流程。

### 4.5 Gramine manifest

模板渲染和静态检查：

```bash
python -m infra.validate_gramine_manifest \
  --template tee/gramine/a122.manifest.template \
  --values deploy/gramine-values.example.json \
  --output artifacts/local-validation/a122.manifest
```

检查项包括 `sgx.debug=false`、DCAP、ECDSA Quote、encrypted mount 和禁用
insecure command-line argv。它不能证明真实 Gramine-SGX 可以启动。

### 4.6 发布与证据

本机可以构建 deterministic ZIP、校验 embedded/external manifest、扫描敏感
marker、生成 `evidence-index.json` 和 `evidence.sha256`。

```bash
python -m infra.build_release \
  --root . \
  --output artifacts/local-validation/a122-local.zip \
  --version local-linux-checkpoint

python -m infra.validate_release \
  artifacts/local-validation/a122-local.zip \
  --manifest artifacts/local-validation/a122-local.manifest.json

python -m infra.seal_evidence seal artifacts/local-validation
python -m infra.seal_evidence verify artifacts/local-validation
```

### 4.7 攻击矩阵

```bash
python -m infra.attack_matrix \
  --output artifacts/local-validation/attack-matrix.json
```

本地拒绝项会实际执行；D1、D3、D4、D6、D9 中依赖真实硬件的项明确标记为
`pending_server`。

## 5. WSL 使用建议

当前 WSL 约 7.5 GiB 内存适合 Tiny Decoder、三个轻量进程和模型工具。运行正式
正式 GPT-2（约 124M）前应关闭不必要进程，必要时在 `.wslconfig` 中适度增加内存。不要
为模型运行删除 TLS、证明或 Ticket 检查。

建议的开发顺序：

1. 运行 `deploy/run_local_checks.sh`。
2. 在本机修复协议、证书、模型包和部署脚本问题。
3. 选定正式模型和 tokenizer 后重新生成模型包。
4. 服务器 D1 通过后，再将 host TLS 替换为 enclave 内 YACL/BRPC。
5. 所有服务器结果写入独立的 `artifacts/server/<run-id>/`，不与本机结果混合。

## 6. 证据口径

本机结果统一标记：

```json
{
  "real_tcp_tls": true,
  "host_process_tls_termination": true,
  "enclave_internal_tls": false,
  "sgx_acceptance": false
}
```

答辩和论文不得把本机结果改写为 SGX 实测结果。

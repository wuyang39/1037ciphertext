# A1-22 密语三方

本仓库以 [`docs/A1-22_作品开发方案-TEE加固版.md`](docs/A1-22_作品开发方案-TEE加固版.md) 为核心开发文档。工程目标是在 `C + KAS/Audit + P0/P1/P2` 上交付一套可运行、可验证、可答辩的隐私推理系统：

- 客户端 `C` 在本地完成 tokenizer 与 RSS 输入拆分，并仅在本地校验和重构输出。
- 三个 SGX 节点通过 KAS 远程证明和密钥放行后，加载各自的模型份额。
- 三个 enclave 使用 3PC RSS 执行中文 GPT-2 级 Decoder 的完整自回归推理。
- 节点协议由 enclave 内终止的 mTLS 承载；明文 BRPC、debug enclave 和未证明节点均 fail-closed。
- 性能记录、攻击负例、审计记录和原始 trace 必须可由固定版本和脚本复现。

服务器租用、镜像复用、比赛日部署与资源释放方案见
[`docs/服务器资源准备.md`](docs/服务器资源准备.md)。

当前已经冻结的 canonical JSON、REPORTDATA 和 KAS 接口见
[`docs/protocol-baseline.md`](docs/protocol-baseline.md)。

跨团队对齐的 Linux/CPU、版本、三节点端口与配置格式、KAS 部署和模型份额接口见
[`docs/interface-freeze.md`](docs/interface-freeze.md)。

## 当前状态

仓库已完成基线初始化，实施阶段按文档中的 `D0` 至 `D10` 验收门推进。任何前置验收门未通过时，不进入依赖它的后续阶段。

优先并行启动：

1. `D0`：明文模型、固定点和 RSS 真值。
2. `D1`：单台真实 SGX 实例的 Quote 与 KAS 验证闭环。
3. `D2`：协议 schema、国密会话和 `JobTicket` 状态机。
4. `D4`：本地 3PC RSS 最小算子与 enclave 内 mTLS 前置验证。

当前本地代码已完成 `D0`、`D2`，以及 `D1` 的本地 KAS/DCAP 边界和拒绝路径，
并完成 `D3-D10` 中不依赖真实服务器的可测试实现：SM2 身份证书、
`ClientHello -> ServerHello -> Finished -> FinishedAck`、SM3/HKDF 方向密钥、
SM4-GCM 帧、严格 counter 反重放、`Close` 状态机、KAS 一次性 `JobTicket`
账本与脱敏审计 schema、受保护文件/Worker mock、3PC RSS 最小算子、mock
mTLS、安全 Transformer Block、ResultFrame、KV wipe、确定性模型导出、
dyadic 量化、静态图规划、脱敏 benchmark、本地负例与证据采集脚本。
D2 的 SM4-GCM 默认已切换为 OpenSSL native 实现，并用 RFC 8998 和
GB/T 36624-2018 向量验证；纯 Python 实现只保留为显式测试 oracle。

本机 Linux/WSL 还可以运行真实 localhost TCP/TLS 1.3 三节点链路、Gramine
manifest 静态检查、模型份额包、release 校验和证据封存：

```powershell
.\deploy\run_local_checks.ps1
```

详细能力边界和 Ubuntu/WSL 命令见
[`docs/local-linux-development.md`](docs/local-linux-development.md)。

本地 mock、encrypted FS、RSS、三节点 runtime 和 mTLS 均不是真实 SGX
验收。真实 Quote、Gramine encrypted FS、YACL/BRPC、三节点 enclave 和 EPC
指标待服务器阶段完成，清单见 [`docs/server-acceptance-checklist.md`](docs/server-acceptance-checklist.md)。

从账号采购、真实 D1 证明到 D10 证据冻结的完整执行顺序和成本控制见
[`docs/后续开发总计划.md`](docs/后续开发总计划.md)。

## 仓库结构

```text
.
├── client/                 # 本地 tokenizer、RSS 拆分、结果重构与 CLI
├── crypto/                 # SM2/SM3/SM4-GCM、AAD 与会话状态机
├── model/                  # 模型导出、校准和浮点/固定点参考
├── mpc/
│   ├── spu_backend/        # RSS I/O、编译、拓扑和 trace
│   ├── secure_ops/         # 安全算子
│   ├── stage_planner/      # 尺度、布局和静态图规划
│   └── material_ledger/    # 预处理材料一次性消费账本
├── tee/                    # enclave 入口、证明、Gramine 和安全清理
├── kas/                    # verifier、CA、策略、Lease、Ticket 与账本
├── third_party/yacl_tls/   # BRPC mTLS fail-closed 改造
├── infra/                  # Docker、Ansible/Terraform、安全组与拓扑
├── benchmark/              # trace、网络模拟、报表和图表脚本
├── deploy/                 # 本地联调、服务器阶段脚本入口和运行手册
├── tests/                  # unit、integration、tee、security 与 e2e
└── docs/                   # 核心设计、运行手册、模型卡、测试向量与 SBOM
```

## 安全基线

- 不提交生产 CA、KAS 私钥、`K_disk_i`、TLS 私钥、模型份额、RSS share、KV cache 或会话密钥。
- 不在生产路径使用明文 BRPC、客户端明文 embedding、硬编码密钥或 `sgx.debug=true`。
- 生产代码禁止 `reveal()`；仅测试白名单与明文参考实现可以使用。
- 协议对象、模型 manifest、精度计划和 AAD 字段冻结后，变更必须评审、更新测试向量并递增版本。

## 本地仓库

初始分支为 `main`。提交前至少检查：

```powershell
git status --short
rg -n "reveal\\(|sgx\\.debug\\s*=\\s*true|BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY" .
```

## 开发命令

```powershell
python -m pytest -q
python -m model.build_tiny_fixture --output tests/fixtures/tiny_float_reference.json
```

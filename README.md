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

## 当前状态

仓库已完成基线初始化，实施阶段按文档中的 `D0` 至 `D10` 验收门推进。任何前置验收门未通过时，不进入依赖它的后续阶段。

优先并行启动：

1. `D0`：明文模型、固定点和 RSS 真值。
2. `D1`：单台真实 SGX 实例的 Quote 与 KAS 验证闭环。
3. `D2`：协议 schema、国密会话和 `JobTicket` 状态机。
4. `D4`：本地 3PC RSS 最小算子与 enclave 内 mTLS 前置验证。

当前本地代码已完成 `D0`、`D1` 与 `D2` 的可测试实现：SM2 身份证书、
`ClientHello -> ServerHello -> Finished -> FinishedAck`、SM3/HKDF 方向密钥、
SM4-GCM 帧、严格 counter 反重放、`Close` 状态机、KAS 一次性 `JobTicket`
账本与脱敏审计 schema。D2 的 SM4-GCM 组合已用标准向量验证；正式 SGX 部署
仍需将纯 Python SM4 分组原语替换为常数时间 native 实现。

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

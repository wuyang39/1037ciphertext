# A1-22“密语三方”作品开发方案

> **内部执行文档。** 本文将 [A1-22_完整作品设计方案-TEE加固版.md](A1-22_完整作品设计方案-TEE加固版.md) 落成可运行、可验证、可答辩的软件。对外作品口径以设计书为准；本文保留阶段依赖、工程风险、测试门禁和失败处置，供团队开发使用。

## 1. 目标、范围与最终验收

### 1.1 最终要交付的系统

交付部署在 `C + KAS/Audit + P0/P1/P2` 上的软件：用户 `C` 在本地完成 tokenizer 与 RSS 输入拆分；三个 SGX enclave 节点在 KAS 远程证明和密钥放行后加载各自模型份额，以 3PC RSS 执行中文 Decoder 的完整自回归推理；节点间协议流量在 enclave 内终止的 mTLS 中传输；用户仅在本地校验并重构输出；系统提供完整的性能记录与安全负例证据。

最终演示模型固定为中文 GPT-2 级 Decoder（约 100M 参数），演示参数固定为 `batch=1`、输入长度桶 `8/16`、`max_new_tokens<=4`、固定上下文窗口 `16`。交付必须真实运行这套闭环；Tiny 模型和同机三进程仅用于缩小调试变量，不替代最终三节点 SGX 演示。

### 1.2 最终验收定义

在三台实际 SGX 实例和独立 KAS 上，从干净部署完成下列流程：

```text
登记 release 与模型 manifest
  → 三个节点生成并验证非 debug DCAP Quote
  → KAS 仅向通过测量策略的 enclave 放行存储密钥、节点证书与 Lease
  → 客户端验证节点身份并建立国密会话、获得 JobTicket
  → Prompt 本地 tokenize/RSS 拆分
  → 三个 enclave 在 mTLS 下运行 RSS Transformer
  → 客户端验证三份 ResultFrame 并在本地重构 token
  → 销毁会话态、作废 Ticket、输出脱敏审计与性能报告
```

必须同时拿到：端到端生成截图或录像、Quote/KAS 记录、篡改镜像拒绝记录、明文 BRPC 拒绝记录、网络抓包、Ticket 重放拒绝记录、宿主机材料采集安全演示、原始性能 trace 与一键复现实验脚本。

### 1.3 不变的工程原则

1. **先建立真值，再进入秘密域。** 每个模型/算子先有 PyTorch 浮点参考，再有环上固定点参考，最后有 RSS 重构比对；不以“密态程序没有报错”作为正确性证明。
2. **TEE 从第一天就是目标运行环境。** 模型和 RSS 算子可在本地开发，但任何跨节点能力均以“enclave 内持钥、证明后启动、mTLS fail-closed”为设计约束，避免最后阶段返工。
3. **一次只引入一个核心变量。** 不在同一提交中同时替换模型、量化 scale、Softmax 近似、SPU 版本和 TEE 镜像。
4. **不通过降级绕过安全接口。** 不使用客户端明文 embedding、明文 BRPC、硬编码/环境变量密钥、`sgx.debug=true` 或临时 `reveal()` 修补问题。
5. **所有结论都有可复现证据。** 固定模型 hash、release 测量值、随机种子、Prompt、网络参数、代码版本与原始 CSV/JSON trace；不从论文迁移性能数字。

## 2. 角色分工与接口冻结

建议四个工作流并行，使用同一份 `protocol_types.proto`、`model_manifest.json`、`release_manifest.json`、`precision_plan.json` 和 `JobTicket` schema。任意安全字段变更须同时更新协议、测试向量、版本号与文档。

| 工作流 | 负责目录 | 首个可验收产物 | 与其他工作流的契约 |
| --- | --- | --- | --- |
| A：模型与数值 | `model/`, `mpc/secure_ops/` | 浮点/固定点参考、Tiny Decoder、量化报告 | 输出 frozen 模型结构、shape、scale、误差阈值 |
| B：RSS 与图执行 | `mpc/spu_backend/`, `mpc/material_ledger/` | 3PC 小算子、私有 Block、trace | 输入输出均为 RSS ABI；禁止中间 reveal |
| C：TEE 与 KAS | `tee/`, `kas/`, `third_party/yacl_tls/` | Quote、KAS 放行、加密文件、enclave mTLS Echo | 输出 node identity、Lease、`tee_tls_config`、Ticket 校验接口 |
| D：会话、测试与交付 | `client/`, `crypto/`, `tests/`, `benchmark/`, `infra/` | 国密会话、攻击负例、性能采集、三机部署 | 固定帧格式、AAD、审计字段与一键复现命令 |

### 2.1 必须冻结的协议对象

| 对象 | 必填绑定字段 | 责任人 |
| --- | --- | --- |
| `release_manifest` | `release_id,MRENCLAVE,MRSIGNER,min_isvsvn,debug_allowed,spu_build_hash,expires_at` | C |
| `model_manifest` | `model_hash,tokenizer_hash,precision_plan_hash,model_version,operator_version` | A |
| `JobTicket` | `ticket_id,session_id,node_role,release_id,model_manifest_hash,share_epoch,length_bound,max_new_tokens,client_ephemeral_pub,expiry,counter,KAS_signature` | C/D |
| 业务帧 AAD | `protocol_version,session_id,epoch,counter,sender,receiver,model_manifest_hash,request_hash,message_type` | D |
| RSS Tensor ABI | `ring,shape,layout,scale_id,range_id,share_epoch` | A/B |
| `ResultFrame` | `session_id,ticket_id,epoch,decode_step,node_role,model_manifest_hash,request_hash,output_share,trace_digest,enclave_receipt_signature` | B/D |

接口冻结后，改变 `session_id`、scale、张量布局、角色名、hash 算法、材料 ID 或 Ticket 字段必须进行代码评审，重新生成 fixtures，并递增协议/配置版本。

## 3. 环境与资源准备

### 3.1 本地开发机与 SGX 云资源分工

当前 32 GB RAM 笔记本适合模型转换、固定点/RSS 仿真、KAS、客户端、单元测试和同机三进程集成；真实 Quote、Gramine-SGX、受保护文件与三节点 TEE 演示必须使用支持 vSGX 的 Linux 实例。GPU 不属于 RSS+SGX 主路径的刚性需求；可用于 PyTorch 明文校准和模型基线，但不替代 SGX 节点。

| 工作 | 本地电脑 | 单台 SGX 云机 | 三台 SGX 云机 |
| --- | ---: | ---: | ---: |
| 模型导出、量化、浮点/固定点参考 | 是 | 可选 | 否 |
| KAS API、客户端、协议 schema | 是 | 可选 | 否 |
| SPU 三方仿真/单测 | 是 | 可选 | 否 |
| DCAP Quote、Gramine enclave | 否 | 是 | 否 |
| 受保护文件与 KAS 放行 | 否 | 是 | 否 |
| enclave 内 BRPC mTLS / 3PC RSS | 否 | 可作 stub | 是 |
| 最终性能、安全演示、交付截图 | 否 | 否 | 是 |

主选环境为 Ubuntu 22.04、Intel SGX vSGX、Gramine-SGX、Intel DCAP、SecretFlow-SPU/YACL/BRPC。租用时先用一台按量实例验证 Quote 和 Gramine，再建立三节点短时联调；每次关闭或释放实例并设置预算告警。模型和 TEE PoC 的详细云资源选择见 [TEE加固设计与PoC实施方案.md](TEE加固设计与PoC实施方案.md)。

### 3.2 代码仓库骨架

```text
privacy-llm/
├── client/                      # 本地 tokenizer、RSS 拆分、结果重构、CLI
├── crypto/                      # SM2/SM3/SM4-GCM、AAD、会话状态机
├── model/                       # 模型导出、校准、浮点/固定点 reference
├── mpc/
│   ├── spu_backend/             # RSS I/O、编译、拓扑、trace
│   ├── secure_ops/              # embedding、MatMul、Softmax、Norm、GELU、Argmax
│   ├── stage_planner/           # 静态图尺度/布局规划
│   └── material_ledger/         # 预处理材料一次性消费
├── tee/
│   ├── tee_entry.py             # enclave 受控入口
│   ├── attestation/             # DCAP/RA-TLS/Lease 客户端
│   ├── gramine/                 # manifest、签名、受保护文件配置
│   └── secure_wipe.py           # 会话态清理
├── kas/                         # verifier、CA、策略、Lease、Ticket、账本
├── third_party/yacl_tls/        # BRPC mTLS fail-closed 改造
├── infra/                       # Docker、Ansible/Terraform、安全组、拓扑
├── benchmark/                   # trace、网络模拟、报表、图表脚本
├── tests/                       # unit、integration、tee、security、e2e
└── docs/                        # 运行手册、模型卡、测试向量、SBOM
```

### 3.3 版本锁定与密钥卫生

- 首日生成 `requirements.lock`、基础镜像 digest、SPU/YACL/BRPC commit、Gramine 版本、DCAP/PCCS endpoint 记录和 SBOM。
- 所有测试密钥通过 `tests/fixtures/` 临时生成；生产 CA、KAS 私钥、`K_disk_i`、TLS 私钥、RSS share 不提交 Git、不写 `.env`、不写 Docker image。
- 开发期允许 `gramine-direct` 仅验证应用依赖；每个需要安全结论的测试必须以签名后的 `gramine-sgx`、`sgx.debug=false` 运行。
- CI 执行密钥泄露扫描、`reveal()` 静态检索、依赖漏洞扫描和 manifest 政策检查。

## 4. 开发阶段与验收门

本计划分为 `D0–D10`。D0–D4 建立“模型/RSS/TEE 各自可验证”的底座；D5 起将它们合并。任何阶段未通过验收门，不推进依赖它的后续阶段。

### D0：环境、模型与固定点真值（第 1 周）

**目标：** 建立可追溯的明文模型与数值参考，避免把模型导出或量化错误误判为 MPC/TEE 问题。

实现事项：

- 选择许可清晰的中文 GPT-2 级模型及 tokenizer，记录来源、许可证、权重 hash、tokenizer hash、层数/隐藏维度/词表和测试 Prompt 集。
- 实现 `forward_reference()`、单 token decode、固定窗口 KV cache；冻结至少 20 条非敏感 Prompt 的 logits、argmax、逐 block 激活范围与输出 token fixture。
- 实现明文环上固定点模拟器：`Z_(2^64)` 运算、符号编码、dyadic scale、舍入、溢出检测与 secure truncate 语义。
- 写出 Tiny Decoder（2 层、词表 256）以隔离模型导出复杂性，并用同一 ABI 运行。
- 建立 `model_manifest` 和 `precision_plan` 的 JSON schema、hash 和 SM2 签名验证器。

**验收门 D0：** 固定容器、固定种子下浮点输出和 fixture 一致；固定点参考在所有冻结 Prompt 上输出逐层误差与溢出统计；模型、配置、依赖均可由 hash 精确定位。

### D1：单机 SGX 证明与 KAS 最小闭环（第 1 周，并行）

**目标：** 在写任何 TEE 业务代码前，证明实际租用实例能产生可由独立 KAS 验证的非 debug Quote。

实现事项：

- 创建一台 SGX 实例，确认 SGX 设备、DCAP/PCCS 服务、内核模块和时间同步正常；保存实例规格、地域、CPU/微码、驱动和 endpoint 信息。
- 用厂商 sample 与 Gramine hello 分别生成 Quote；KAS 实现 `/v1/challenge`、`/v1/attest`、精确 `MRENCLAVE`/`DEBUG=0`/nonce 校验与拒绝日志。
- enclave 内生成临时 P-256 TLS 密钥；将 `H(pubkey || role || release_id || nonce)` 绑定到 `REPORTDATA`；KAS 验证绑定后签发短期节点证书。
- 定义 `release_manifest.json`，发布脚本将每次签名后的 measurement 登记至 KAS 策略库。

**验收门 D1：** 正确 release 得到短期证书；改动一个受测量文件、使用 debug manifest、重放旧 challenge、替换临时公钥均被 KAS 拒绝。保存 Quote、验证报告、measurement 与 deny log。

### D2：国密会话、Ticket 与审计状态机（第 2 周）

**目标：** 在模型前先完成 `C ↔ P_i` 的身份、加密、反重放与授权边界。

实现事项：

- 用 GMSSL 或经验证国密实现生成/验证 SM2 证书、签名和 CRL；完成 `ClientHello → ServerHello → Finished → FinishedAck`。
- 以完整握手 transcript、`session_id`、节点角色、模型版本、epoch 为 KDF 上下文，经 SM3/HKDF 派生方向独立会话密钥；实现 SM4-GCM 帧、nonce、AAD、滑动窗口和 `Close` 状态机。
- 实现 KAS `/v1/issue-job-ticket` 与 `/v1/consume-ticket`；票据精确绑定模型 hash、`precision_plan_hash`、角色、长度、生成上限、客户端临时公钥、epoch、expiry 与 counter。
- 定义审计事件 schema，日志只写 `session_hash,ticket_id,release_id,measurement,result_code,bytes,elapsed_ms` 等脱敏字段。

**验收门 D2：** 正常三路会话建立；过期/伪造证书、改动 tag/AAD、重复/乱序 counter、跨 session、跨模型、已消费/过期 Ticket 均被拒绝，且拒绝发生在进入 MPC 前。

### D3：受保护文件与受控 Worker 启动（第 2 周，并行）

**目标：** 确保模型份额和预处理材料只有在正确 enclave 内、获得有效 Lease 后可使用。

实现事项：

- 建立 Gramine manifest：`sgx.debug=false`、DCAP、strict file policy、显式 trusted files、encrypted FS、`/run/tee` 与 `/run/session` tmpfs。
- KAS 加入 `/v1/release-storage-key`，只在证明通过的 RA-TLS 会话向 enclave 放行 `K_disk_i`；`tee_entry` 必须先拿到 Lease 和磁盘密钥，再挂载 `/secure` 并加载 Worker。
- 将 mock `model_share_i.bin`、mock preprocessing package 写入 encrypted FS；实现文件 hash 与 manifest 绑定、状态加载/失败清理。
- Worker 仅暴露固定的 `run_inference(ticket,input_share)` 接口；不提供 shell、任意 IR、任意 Python 和动态模型加载。

**验收门 D3：** 宿主直接读取、复制或篡改受保护文件均无法得到可用明文；错误 measurement 或缺失 Lease 时 Worker 不启动；敏感材料不出现在镜像、环境变量、host 日志或 core dump 采集结果中。

### D4：3PC RSS 最小算子与 enclave 内 mTLS 链路（第 3 周）

**目标：** 让三个已证明节点在 mTLS 下执行真实 RSS 小算子，验证“TEE、网络、SPU”接口没有断点。

实现事项：

- 配置 SPU 3PC RSS topology，实现 `share_input()`、`reconstruct_output()` 和固定点 adapter；为 `rss_add,mul,matmul,truncate,compare,reciprocal` 建立单测。
- fork YACL/BRPC Link 加入 `tee_tls_config`：TLS 1.3、KAS CA、双向证书、角色 SAN allowlist、关闭 BRPC builtin services、非 TLS 连接 fail-closed。
- 将 TLS 私钥、证书和解密端点保持在 enclave 内；以 Echo、secret-add、secret-mul、small MatMul 顺序接入。
- 实现最小 `MaterialLedger`：`material_id,model_version,share_epoch,op_type,count,expiry,status`，先保证原子领取、使用后置为已消费和审计落库。

**验收门 D4：** 三方 add/mul/matmul 对至少 1,000 组确定性边界/随机向量与固定点参考相符；抓包仅见 TLS records；明文、错误 CA、错误 SAN、无客户端证书连接均不能执行算子；关闭 TLS 配置时 Worker 启动失败而非降级。

### D5：Tiny Decoder 的私有 Transformer Block（第 4 周）

**目标：** 在完整安全链路中跑通真实 Decoder Block，而非仅做加密 MatMul 展示。

实现事项：

- 实现秘密 token 到 embedding 的 `secure_embedding/Idx2v`，禁止用客户端先算明文 embedding 绕过词表选择。
- 按顺序接入 QKV、causal `QK^T`、缩放、稳定 Softmax、`A*V`、输出投影、残差、LayerNorm、FFN、GELU 和安全 Argmax。
- 每个算子输出脱敏 `shape,ring,scale,range,rounds,bytes,elapsed_ms` trace；测试期仅在合成向量路径允许显式重构验证。
- 对齐“浮点 → 明文固定点 → RSS 重构”三级结果；将误差首次超标的算子、层、输入范围写入问题单。

**验收门 D5：** 2 层 Tiny Decoder 在三个 enclave 中完成一轮完整 Block；误差落在已登记阈值内、无未解释溢出、无生产路径 `reveal()`；每个非线性算子有独立数值和通信 profile。

### D6：端到端自回归与会话态治理（第 5 周）

**目标：** 产出第一个完整可演示闭环：本地 Prompt 到连续两个 token 的私有生成。

实现事项：

- 接入输入帧到 `/run/session`，在 Ticket、角色、模型哈希、epoch、counter、长度均校验后启动固定图。
- 实现 `K_share,V_share` 的 enclave tmpfs 会话缓存，完成第二 token 的增量 attention；禁止将 KV cache 持久化为跨会话数据。
- 生成 `ResultFrame`，以 enclave 回执签名、用户临时公钥加密 output share；客户端校验三份帧的一致性并本地重构 token。
- 实现 `Close`、超时、异常退出和 secure wipe；KAS Ticket 账本、`MaterialLedger`、Audit 记录与会话收尾一致。

**验收门 D6：** 连续生成至少 2 token；重复 ResultFrame、篡改 `decode_step`、混用模型 manifest、重放输入或 Ticket 均被拒绝；会话结束后对 `/run/session` 和进程临时目录扫描不发现 Prompt share、KV cache 或会话密钥。

### D7：中文 GPT-2 级模型迁移与模型份额导入（第 6 周）

**目标：** 将经 Tiny 验证的接口迁移到最终比赛模型，而不改动安全协议与 TEE 生命周期。

实现事项：

- 实现 HuggingFace 权重导出、确定性 graph conversion、模型/算子 hash、INT8/INT16 静态 dyadic 量化、层级 scale 与 `precision_plan` 签名。
- 模型导入端完成 RSS 拆分，每个份额仅在其对应 enclave 证明后通过业务通道交付，并落入 encrypted FS；加载回执绑定 `model_manifest_hash` 与 `share_epoch`。
- 逐 block 执行“浮点—固定点—RSS”对齐，记录 token 一致率、P99 logit 误差、激活范围和溢出计数；定位首个误差超标层后再继续。
- 固定 `8/16 token` 桶、`max_new_tokens<=4`、`context_window=16` 与公开评测 Prompt，避免性能数据随配置漂移。

**验收门 D7：** 中文 GPT-2 级模型在三节点 enclave 中完成至少 1 token 生成；模型份额、配置、tokenizer、epoch 与会话绑定无误；模型更换、旧 share、旧 Ticket、旧材料均不能被混用。

### D8：性能优化、消融与资源剖析（第 7 周）

**目标：** 在正确的最终模型上形成可解释、可复现的优化证据。

实现事项：

- 固化 `precision_plan`：低精度线性路径、高精度 Softmax/Norm 路径、clip/迭代/截断边界均版本化。
- 实现 `StagePlanner`，合并可直接复用 scale/layout 的 stage，减少不必要 truncate/repack 与小 RPC；输出优化前后的静态图 diff。
- 实现并固定 `softmax_piecewise`、`gelu_piecewise`、`rsqrt_goldschmidt` 的范围、系数与迭代次数。
- 分层采集：enclave 启动、Quote、KAS 放行、TLS 建连、模型加载、每算子、首 token、后续 token、会话关闭；同时采集 CPU/RAM/EPC、网络 bytes、材料消耗。

**验收门 D8：** 每项优化必须有开/关同条件对照，报告 token 一致率/误差、延迟、通信量、内存和安全回归结果；任一优化破坏正确性或安全接口即默认关闭，不进入最终配置。

### D9：三域部署、安全演示与复现冻结（第 8 周）

**目标：** 在与最终作品一致的部署中完成所有性能、安全与交付验证。

实现事项：

- `P0/P1/P2` 分别配置独立账号、管理员、密钥权限、安全组和审计域；KAS/Audit 位于独立控制面。测试 LAN 以及受控 `100 Mbps/40 ms`、`100 Mbps/80 ms` 网络环境。
- 运行真实安全负例：篡改 Worker/依赖、debug enclave、旧 Quote、错误 CSR 公钥、明文 BRPC、错误 SAN/CA、密钥释放请求重放、Ticket 重放、跨 session/model/epoch 帧、材料重复消费。
- 执行宿主机控制材料演示：收集 `P0/P1` 的磁盘、容器配置、host 日志、网络 pcap 与进程信息，扫描是否存在 Prompt、RSS share、KV、TLS 私钥、`K_disk_i` 明文；同时记录 KAS 拒绝篡改 release 的证据。
- 从新机器按安装手册部署，冻结镜像 digest、release measurement、配置、模型 hash、原始 trace、报表脚本、截图与视频。

**验收门 D9：** 安全负例均有明确拒绝点和审计记录；三节点端到端生成稳定；所有图表可由原始 trace 一键再生；答辩环境完成一次离线复现。

### D10：提交物收口（第 8 周末）

**目标：** 保证设计书、代码、实验、答辩材料和演示口径一致。

实现事项：

- 将实际实现对照 [A1-22_完整作品设计方案-TEE加固版.md](A1-22_完整作品设计方案-TEE加固版.md) 逐条勾验，删除未实现功能的对外描述。
- 输出模型卡、安装手册、部署拓扑、接口文档、SBOM、测试向量、性能报告、攻击演示脚本与故障恢复手册。
- 以干净账号和干净客户端走一次 15 分钟答辩演练：证明 → 会话 → 推理 → 攻击负例 → 指标报表。

**验收门 D10：** 交付包解压后无需手工补丁即可按文档运行；所有对外结论能对应到代码、配置、日志或实测图表。

## 5. 关键实现细则

### 5.1 KAS 与远程证明实现顺序

KAS 必须先实现“验证后放行”，再接入模型和业务逻辑。最小 REST/gRPC 接口如下：

```text
POST /v1/challenge
  {role, release_id} -> {challenge_id, nonce, expiry}

POST /v1/attest
  {challenge_id, quote_or_ra_tls_cert, csr, role, release_id}
  -> {node_cert, ca_bundle, lease_id, expires_at}

POST /v1/release-storage-key
  {lease_id, purpose="model-store", share_epoch}
  -> {K_disk_i over the attested channel}

POST /v1/issue-job-ticket
  {session_id, model_manifest_hash, precision_plan_hash, share_epoch, client_ephemeral_pub}
  -> {signed JobTicket}

POST /v1/consume-ticket
  {ticket_id, enclave_lease_id, session_id, counter}
  -> {accepted | already_consumed | expired | policy_denied}
```

实现检查点：`REPORTDATA` 必须绑定当前临时公钥与当前 KAS nonce；只允许精确 `MRENCLAVE` 和非 debug Quote；Ticket 消费状态保存在 KAS 在线账本，不能仅存本地密封文件；任何验证失败都返回拒绝，不允许“开发回退模式”进入推理。

### 5.2 Gramine 运行时最小策略

生产 manifest 至少包含：

```toml
sgx.debug = false
sgx.remote_attestation = "dcap"
sgx.file_check_policy = "strict"
fs.mounts = [
  { path = "/secure", type = "encrypted", uri = "file:/var/lib/privacy-llm/secure", key_name = "model_store" },
  { path = "/run/tee", type = "tmpfs" },
  { path = "/run/session", type = "tmpfs" }
]
```

`tee_entry` 的不可交换启动顺序为：生成临时密钥 → 获取 challenge/Quote → 证明/KAS 放行 → 注册受保护文件密钥 → 加载模型份额/材料 → 建立 mTLS → 启动受 Ticket 约束的 Worker。任何提前加载模型、先启动明文监听端口或将私钥写至 host 都视为实现缺陷。

### 5.3 SPU/YACL/BRPC 接口改造

改造保持 RSS 算法、Transformer 图和份额 ABI 不变，只将底层节点通道改为 enclave 内持钥的 mTLS：

```json
{
  "enabled": true,
  "min_tls_version": "TLS1.3",
  "ca_bundle": "/run/tee/attestation-ca.pem",
  "cert": "/run/tee/node.pem",
  "private_key": "/run/tee/node.key",
  "expected_peer_names": [
    "spiffe://a122/P0", "spiffe://a122/P1", "spiffe://a122/P2"
  ],
  "require_client_cert": true,
  "reject_plaintext_brpc": true,
  "disable_builtin_services": true
}
```

具体检查：服务端在首请求检查 TLS 状态；客户端与服务端均校验专用 CA 和目标 SAN；三节点连接矩阵仅允许 `P0↔P1↔P2` 协议所需连接；证书、私钥和 CA bundle 从 `/run/tee` 读取；任何配置缺失或 TLS 失败均停止 Worker。

### 5.4 数值实现与误差门槛

使用三级 golden path：

```text
PyTorch float reference
       ↓ 同一权重/Prompt/图
Z_(2^64) fixed-point reference
       ↓ 同一 scale、truncate、近似配置
RSS reconstruct-for-test result
```

每层/算子必须记录 `max_abs_error, mean_abs_error, relative_error, overflow_count, argmax_match`。阈值由 D0 的模型校准结果写入 `precision_plan`，不得只凭最终文本“看起来合理”放宽。Softmax、Norm 与 GELU 的近似修改必须先在合成边界向量、再在 block、最后在完整 Prompt 集验证。

### 5.5 调试与秘密清理规则

- 生产源码中禁止输出 Prompt、token id、embedding、RSS share、KV、logits、TLS 私钥、`K_disk_i`、明文 RPC payload。
- `reveal()` 只允许位于 `tests/plaintext_reference/` 或显式测试白名单；CI 通过 `rg` 与 AST/代码审查阻止其他位置调用。
- 每个会话结束、Ticket 拒绝、异常退出均调用 `secure_wipe`，清理 `/run/session` 对象、内存缓冲和会话密钥引用；审计只保留摘要。
- 故障调试使用合成 Prompt 与合成权重片段；需要检查真实结果时，仅在客户端侧输出授权 token。

## 6. 测试体系与持续集成

### 6.1 测试层级

| 层级 | 必测对象 | 通过标准 |
| --- | --- | --- |
| 单元 | SM2/SM3/SM4、AAD、nonce、RSS add/mul/truncate、量化、Ticket parser | 边界、负数、随机测试向量确定可复现 |
| 属性 | 份额重构、环运算关系、scale 转换、材料状态机 | 至少 1,000 组固定种子向量 |
| 模型 | Block、Argmax、KV 增量、近似函数 | 与 frozen fixed-point fixture 对齐 |
| TEE | Quote、REPORTDATA、测量策略、encrypted FS、Lease | 正确 release 放行，篡改/调试/重放拒绝 |
| 网络 | mTLS、SAN、明文拒绝、断线、重放 | 未认证流量不能进入 RSS Runtime |
| 集成 | C+KAS+P0/P1/P2，一次生成 | Prompt 仅本地，输出仅 C 重构 |
| 安全演示 | 宿主快照、抓包、日志、错误节点控制面 | 不出现敏感明文，KAS/Audit 记录完整 |
| 性能 | TTFT、token、内存、bytes、Quote/KAS | 原始 trace 可生成全部图表 |

### 6.2 CI 分层

每次提交运行本地 CPU CI：格式化、单元/属性、fixed-point、静态 `reveal()`/密钥扫描、schema 兼容与 Tiny RSS 测试。每日或合并前运行容器集成：三进程会话、Ticket、Tiny Decoder、mTLS mock。每个 release 候选运行 SGX CI：真实 Quote、KAS 放行、受保护文件、三节点小算子和安全负例。性能 CI 不以绝对机器数值阻塞合并，但必须保存同配置趋势并在超过预算时报警。

### 6.3 必须保留的测试证据

| 编号 | 证据 | 最终保存材料 |
| --- | --- | --- |
| E1 | 非 debug Quote 通过 | Quote、验证报告、时间戳、release hash |
| E2 | 受测量文件篡改 | 新旧 measurement、KAS deny log |
| E3 | host 磁盘读取 | 加密文件、读取失败/不可用结果、扫描摘要 |
| E4 | host 网络抓包 | pcap、协议解析截图、无明文扫描结果 |
| E5 | 明文/错误证书接入 | 客户端报错、服务端审计、连接拒绝记录 |
| E6 | Ticket/帧/材料重放 | `already_consumed` 或 `policy_denied` 账本记录 |
| E7 | RSS 小算子 | 固定点对照报告、通信 trace |
| E8 | 私有自回归 | 客户端输出摘要、三份认证 ResultFrame、会话收尾记录 |
| E9 | 宿主机材料合并 | 扫描脚本、摘要、KAS 与 Audit 对应事件 |
| E10 | 性能 | 原始 CSV/JSON、环境快照、图表生成命令 |

## 7. 性能测量与实验记录

### 7.1 记录字段

每次 benchmark 生成不可覆盖的 `run_id`，并保存：`git_commit`、镜像 digest、`release_id`、`MRENCLAVE`、模型/量化哈希、节点规格、SGX/Gramine/DCAP/SPU 版本、地域、带宽/RTT、Prompt 长度、生成长度、随机种子、开始/结束时间。

每条 trace 必须分解为：

- Quote 与 KAS 放行时间；
- 客户端认证、SM2/SM4 会话建立与节点 mTLS 建连时间；
- 模型份额加载时间与 encrypted FS I/O；
- 每层/每算子耗时、轮数与节点通信 bytes；
- TTFT、每个后续 token 时延、总时延、吞吐；
- CPU、RSS 内存、enclave 相关内存、磁盘 I/O；
- 预处理材料消耗、Lease/Ticket 拒绝和重连次数；
- 输出一致性、固定点误差、溢出与安全负例结果。

### 7.2 消融矩阵

| 对照 | 固定不变部分 | 观测指标 |
| --- | --- | --- |
| 浮点 vs 固定点 vs RSS | 模型、Prompt、长度、权重 | 误差、token 一致率、内存、延迟 |
| 全 64 位 vs `precision_plan` | 图、网络、模型 | bytes、时延、误差、溢出 |
| StagePlanner off/on | 模型、量化、网络 | truncate/repack 次数、RPC、bytes、时延 |
| 非线性配置变体 | scale、Prompt、模型 | Softmax/Norm/GELU 误差和轮数 |
| 本机/LAN/受控 WAN | release、模型、输入 | TTFT、每 token、总时延、网络占比 |
| TEE 生命周期阶段 | 同一安全图与输入 | 启动/证明/密钥放行/在线推理分项开销 |

测试时不把同机开发数据与三节点 SGX 数据混为一张主结论图；网络条件和硬件规格必须随图表显示。

## 8. 风险台账与处置顺序

| 风险 | 最早发现阶段 | 处置优先级与规则 |
| --- | --- | --- |
| 云实例无法产生有效 Quote | D1 | 立即换地域/实例族/云厂商，未通过 D1 不开始 TEE 集成 |
| Gramine 无法承载当前 Python/SPU 依赖 | D1/D3 | 先最小化入口和依赖、锁定 C++ Worker 边界；不在未证明环境装入模型份额 |
| BRPC TLS 接口与 SPU 调用链不匹配 | D4 | 先完成 Echo/add/mul，再定位 Link 层；不以 host 外 TLS 终止替代 enclave 内 TLS |
| SPU 不支持某 secret 算子 | D4/D5 | 基于已支持固定长度图重写；不回退到客户端明文回调 |
| 私有 embedding 过慢 | D5 | 独立 profile，优先批量 Idx2v 与固定长度；不降低 token 保护要求 |
| Softmax/Norm 溢出或 token 跳变 | D5/D7 | 回退范围/clip/scale/迭代，先修 fixed-point 再调 RSS |
| 100M 模型时间或内存超预算 | D7 | 根据 trace 定位算子后调整长度桶、生成数、量化与布局；不删除完整安全链路 |
| TCB 构建变更导致 measurement 漂移 | D1 起 | release pipeline 生成新 measurement、KAS 双版本审批、fixtures 同步；禁止手改 allowlist |
| 三人并行改坏协议 schema | 全程 | schema 变更必须评审；兼容性测试和版本递增为合并前条件 |
| 数据/日志泄密 | 全程 | 立即轮换测试密钥，删除泄漏制品，执行扫描并补充 CI 规则 |

## 9. 8 周推进日历

| 周次 | 主验收门 | 并行任务 | 周末产物 |
| --- | --- | --- | --- |
| 第 1 周 | D0 + D1 | 明文/固定点真值；真实 SGX Quote/KAS | fixtures、measurement、KAS deny 演示 |
| 第 2 周 | D2 + D3 | 国密会话/Ticket；encrypted FS/受控启动 | 会话负例、密钥放行和文件保护记录 |
| 第 3 周 | D4 | 3PC RSS 小算子；enclave mTLS BRPC | 小算子对照、pcap、明文拒绝 |
| 第 4 周 | D5 | Tiny Decoder Block、非线性、误差 trace | 私有 Block 演示与算子 profile |
| 第 5 周 | D6 | KV cache、ResultFrame、会话清理 | Prompt 到 2 token 的端到端演示 |
| 第 6 周 | D7 | 中文 GPT-2 导出、量化、份额模型导入 | 100M 模型 1 token 闭环 |
| 第 7 周 | D8 | StagePlanner、精度计划、性能消融 | 同条件优化表和原始 trace |
| 第 8 周 | D9 + D10 | 三域部署、攻击演示、文档/PPT | 冻结交付包和答辩演练录像 |

若时间压缩，绝不跳过 D1–D4 或 D9 的安全验收。优先缩小模型层数、长度桶和生成 token 数，保留真实 Quote、KAS、encrypted FS、enclave mTLS、完整 Transformer Block 与端到端一 token 生成。

## 10. 提交前检查清单

- [ ] 干净机器可按手册启动 `C,KAS,P0,P1,P2` 并生成结果。
- [ ] 三个节点均有真实、非 debug、与 release 对应的 Quote 和 KAS 放行记录。
- [ ] 任何受测量文件、证书、Ticket、模型/epoch、会话帧、材料 ID 被替换或重放均被拒绝。
- [ ] Prompt、token、embedding、RSS share、模型份额、KV cache、会话密钥和 `K_disk_i` 未出现在 host 可读文件、日志或抓包明文中。
- [ ] RSS 中间张量未调用生产 `reveal()`；输出仅在客户端重构。
- [ ] TLS 私钥和明文协议处理均在 enclave 内；明文 BRPC 被拒绝。
- [ ] `model_manifest`、`precision_plan`、release、Ticket、ResultFrame 与会话 AAD 完整绑定。
- [ ] 有明文、固定点、RSS、量化、StagePlanner 的同条件数据和可复现脚本。
- [ ] 有 Quote、篡改拒绝、pcap、受保护文件、重放拒绝、宿主控制材料演示和性能报告证据。
- [ ] 设计书、开发方案、运行手册、模型卡、代码和答辩 PPT 的功能清单严格一致。

## 11. 开工顺序

立即启动四件事：D0 的模型与固定点 reference、D1 的单台 SGX Quote/KAS、D2 的协议 schema/国密会话、D4 所需 SPU 三方本地小算子。第一个跨节点 Transformer Block 必须建立在“真实证明成功、KAS 能拒绝篡改 release、节点 mTLS 默认拒绝明文”之后。这样团队最早暴露的是硬件/证明/网络接口问题，而不是在大模型端到端失败后才发现基础安全链不成立。

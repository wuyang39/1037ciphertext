# A1-22 接口冻结清单

本文把三方对接前必须一致的接口集中写死，避免最终集成时返工。协议字段的权威
来源仍是 [`protocol-baseline.md`](protocol-baseline.md)；本文只记录"环境、版本、
端口、配置格式、模型份额"这类跨团队约定。

冻结含义：本文中的值一旦被下游引用，修改必须走第 6 节的变更流程。任何未在本文
确认的字段，默认以本文给出的值为准。

## 0. 状态总览

| # | 接口 | 状态 | 说明 |
| --- | --- | --- | --- |
| 1 | Linux 发行版与 CPU 架构 | 已冻结 | 值已定；实际内核/glibc/image digest 待 D1 记录 |
| 2 | Python / SPU-YACL-BRPC / Gramine 版本 | 部分冻结 | Python 全量 pin；外部组件已定目标版本，commit 待镜像构建时登记 |
| 3 | 三节点启动命令、端口、配置格式 | 已冻结 | 端口表、启动入口和 JSON 配置 schema 已落库并可校验 |
| 4 | KAS 部署位置、证明与密钥接口 | 已冻结 | 接口以 `protocol-baseline.md` 为准；传输通道待服务器阶段替换 |
| 5 | GPT-2 模型份额文件格式与加载 | 已冻结 | 正式模型定为英文 GPT-2（见 5.4/5.5）；权重 hash 待 D7 冻结 |

## 1. Linux 发行版与 CPU 架构

| 项目 | 冻结值 |
| --- | --- |
| 发行版 | Ubuntu 22.04 LTS（x86_64） |
| 镜像 | 阿里云"可信系统"Ubuntu 22.04 UEFI，或基于它制作的自定义镜像 |
| CPU 架构 | `x86_64` only，Intel Ice Lake（`g7t`/`c7t`/`r7t`），DCAP 证明路径 |
| 加密内存 | 单节点 ≥ 8 GiB（D1 最低），三节点 ≥ 16 GiB（`g7t.2xlarge`） |
| 禁止项 | ARM/ARM64 节点、未启用 vSGX 的实例、`sgx.debug=true` |

### 1.1 Python 运行时（重要）

Ubuntu 22.04 自带 `python3` 是 3.10，**不满足**项目 `requires-python = ">=3.11"`。
服务器节点统一按以下方式提供 CPython 3.12：

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
```

节点内的 venv、Gramine trusted files 和 `python_runtime_path` 必须指向同一个
3.12 解释器。禁止在服务器上用 3.10 直接运行本仓库代码。

### 1.2 需要登记的实际值

D1 通过后必须把以下值写入 `artifacts/server/<run-id>/` 和 SBOM：

- `uname -r`（内核版本）
- `ldd --version`（glibc 版本）
- `/etc/os-release` 的 `VERSION_ID`
- 自定义镜像 ID 与 OCI image digest

## 2. 版本冻结

### 2.1 Python 依赖

权威来源是 [`../requirements.lock`](../requirements.lock)，全部精确 pin，例如
`cryptography==48.0.0`、`torch==2.12.0+cpu`、`jsonschema==4.26.0`。解释器为
CPython 3.12.x（本机已在 3.12.10 验证）。`torch==2.12.0+cpu` 需要 PyTorch CPU
索引：`--extra-index-url https://download.pytorch.org/whl/cpu`。

### 2.2 外部运行时

| 组件 | 冻结目标 | 备注 |
| --- | --- | --- |
| Gramine | `v1.9` | 官方最新 release（2025-06-20）；manifest 只允许 `sgx.debug=false` |
| SecretFlow-SPU | `0.9.4` | 官方最新 release；三方拓扑固定 `P0/P1/P2`、2-of-3 |
| YACL | 按 SPU 0.9.4 子模块的 commit 固定 | 公开 tag 多为 `-nightly-` 预发布，不按 tag、按 commit |
| BRPC | `1.18.0` | `third_party/yacl_tls/` 的 Link 改造基于此版本 |
| Intel SGX SDK / DCAP QVL | 与目标地域 PCCS 匹配后记录 | D1 阶段确定并写入 SBOM |

### 2.3 版本变更规则

- SPU/YACL/BRPC 任一块变更，必须同步更新 `release_manifest.spu_build_hash`、
  SBOM 和 `RSSTopology.spu_build_hash`。
- Gramine 版本变更必须重新生成 `MRENCLAVE`，并走 KAS 双版本审批。
- 不允许在同一提交里同时替换模型、量化 scale、SPU 版本和 TEE 镜像。

## 3. 三节点启动命令、端口与配置格式

### 3.1 冻结端口表

| 用途 | P0 | P1 | P2 | 暴露范围 |
| --- | ---: | ---: | ---: | --- |
| SPU/BRPC 节点监听 | TCP 47100 | TCP 47101 | TCP 47102 | 仅同 VPC 私网 |
| Worker 健康/指标 | TCP 47110 | TCP 47111 | TCP 47112 | 仅本机 `127.0.0.1` |

| 用途 | 端口 | 暴露范围 |
| --- | ---: | --- |
| KAS HTTPS | TCP 8443 | 仅节点私网 |
| KAS/Audit 汇入 | TCP 8444 | 仅控制面私网 |
| SSH | TCP 22 | 仅管理 IP |

端口已由 `infra/validate_node_config.py` 强制校验，配置写错端口会被拒绝。

### 3.2 启动命令

本机演练（已实现）：

```bash
./deploy/run_local_nodes.sh
```

```powershell
.\deploy\run_local_nodes.ps1
```

KAS（已实现）：

```bash
python -m kas
```

服务器节点（接口已定，镜像构建产出二进制）：

```bash
/app/a122-worker --config /etc/a122/node.json
```

当前仓库只冻结了节点入口契约 `tee/worker.py` 的 `ProtectedWorker` 和本配置格式；
该 CLI 包装在 D3 实现，参数名 `--config` 不再改动。

### 3.3 节点配置格式

配置是 canonical JSON，示例见 [`../configs/node.example.json`](../configs/node.example.json)，
schema 见 [`../contracts/schemas/node_config.schema.json`](../contracts/schemas/node_config.schema.json)。

顶层字段固定为：

```text
config_version, node_role, release_id, share_epoch,
listen{address,port}, peers[{role,address,port,san}],
kas{base_url,ca_bundle_path},
paths{model_share,preprocessing_package},
tls{min_version,require_client_certificate,allow_brpc_builtin_services,role_san_allowlist},
sgx{debug,enclave_size}
```

必须满足的硬约束：

- `config_version` 固定为 `a122-node-config-v1`。
- `node_role ∈ {P0,P1,P2}`，`peers` 恰好是另外两个角色，不允许自环。
- 每个 peer 的 `port` 必须等于该角色的冻结端口，`san` 必须等于 `spiffe://a122/<role>`。
- `tls.role_san_allowlist` 恰好等于对端角色集合，绝不包含自身。
- `tls.min_version="TLS1.3"`、`require_client_certificate=true`、
  `allow_brpc_builtin_services=false`、`sgx.debug=false`，不得放宽。
- `kas.base_url` 必须是 `https://`，不允许明文 HTTP。

校验命令：

```bash
python -m infra.validate_node_config --config configs/node.example.json \
  --output artifacts/local-validation/node-config-validation.json
```

## 4. KAS 部署位置、证明与密钥接口

### 4.1 部署位置

- KAS 与 Audit 部署在**独立的非 SGX 控制面实例**（`ecs.g7.xlarge` 或 `ecs.c7.xlarge`），
  不进入 P0/P1/P2 自定义镜像。
- KAS 私钥、CA 私钥、Ticket 签名私钥只存在于控制面，绝不写入节点镜像、环境变量或普通配置。
- KAS 只接受节点私网访问；SSH 仅允许管理 IP。

### 4.2 证明接口

REPORTDATA 绑定公式、DCAP verifier 子进程契约（`--quote <file> --json` 及输出字段）
已在 [`protocol-baseline.md`](protocol-baseline.md) 冻结，本文不再重复。要点：

- 前 32 字节为规范编码摘要，后 32 字节为零。
- KAS 只在 nonce/role/release_id/CSR 公钥全部绑定且 Quote 非 debug 时签发短期证书。
- challenge 一次性；验证失败也消耗，不能重试同一 nonce。
- 缺失 CA/policy/DCAP verifier 时 KAS 启动失败，不存在"跳过验证"开关。

### 4.3 密钥与票据接口

| 方法 | 路径 | 返回 |
| --- | --- | --- |
| POST | `/v1/challenge` | `challenge_id, nonce, expires_at` |
| POST | `/v1/attest` | `node_certificate_pem, ca_bundle_pem, lease_id, expires_at` |
| POST | `/v1/issue-job-ticket` | 已签名 `JobTicket` |
| POST | `/v1/consume-ticket` | `status="accepted"` |
| GET | `/v1/ticket-public-key` | `public_key` |
| POST | `/v1/release-storage-key` | `key_id, key_hex, expires_at` |

错误码：未知 Ticket 404、已消费 409、过期 410、签名/绑定/Lease 非法 403。
`release-storage-key` 由 `KAS_STORAGE_KEY_MASTER_HEX`、角色、release、epoch、purpose
经 HKDF-SM3 确定性派生；同一 `(lease_id, share_epoch, purpose)` 重复放行返回 409。

### 4.4 环境变量

```text
KAS_CA_KEY_PATH        KAS_CA_CERT_PATH        KAS_RELEASE_POLICY_PATH
KAS_DCAP_VERIFY_BIN    KAS_TICKET_SIGNING_KEY_PATH
KAS_STORAGE_KEY_MASTER_HEX
KAS_HOST               KAS_PORT
KAS_CHALLENGE_TTL_SECONDS   KAS_NODE_LEASE_TTL_SECONDS
```

### 4.5 已知边界

当前 `release-storage-key` 以 mock HTTP 交付。服务器阶段必须把它和全部节点接口放到
已验证的 RA-TLS 通道上；本机 mock 不能作为 KAS 密钥接口的最终形态。

## 5. GPT-2 模型份额文件格式与加载方式

### 5.1 目录布局

模型包由 `python -m infra.build_model_package --output <dir> --encrypt-local` 生成，
布局固定为：

```text
<dir>/
├── package-manifest.json          # 全部文件 hash、model_hash、precision_plan_hash、share_epoch
├── quantized-tensors.bin          # dyadic 量化后的定长 payload
├── precision_plan.json            # 层级 scale、误差阈值、plan id
├── model/
│   ├── model.json                 # 张量表：name/shape/dtype/offset/length/sha256 + model_hash
│   └── tensors.bin                # 按张量名升序拼接的原始权重
├── shares/
│   ├── P0.bin  P1.bin  P2.bin     # 三路 XOR 加性份额
└── encrypted-shares/
    └── P0.enc  P1.enc  P2.enc     # 可选；enclave 证明通过后由 KAS 放行解封
```

### 5.2 份额格式

- 三份加性份额满足 `P0 ^ P1 ^ P2 == quantized-tensors.bin`，角色固定 `P0/P1/P2`。
- 每份份额绑定 `model_hash` 与 `share_epoch`，跨 epoch 或跨模型不得混用。
- 加密份额使用 MockEncryptedFileSystem 的 sealing 格式；生产密钥由 KAS 派生，
  镜像内不得保存 `K_disk_i`。

### 5.3 加载与校验

加载路径已实现：

- `model.export.load_model_bundle()`：逐张量校验 slice hash 和 model manifest hash。
- `model.share_import.import_model_share()`：绑定 `model_hash/epoch/role/证明 release`，
  任一不符即拒绝，份额才允许写入受保护存储。
- `model.share_import.reconstruct_model_payload()`：三份额重建，要求角色互异、
  hash/epoch/长度一致。
- `infra.build_model_package --verify`：文件集、hash、份额重建和 precision plan 一致性。

### 5.4 正式模型（已定）

| 项目 | 冻结值 |
| --- | --- |
| 模型 | 英文 GPT-2，`gpt2`（GPT-2 small），约 124M 参数 |
| 许可证 | OpenAI Modified MIT（`openai/gpt-2` LICENSE，1403 字节） |
| 权重来源 | OpenAI 官方 GPT-2 small 权重；D7 冻结下载来源与逐张量 hash |
| tokenizer | GPT-2 BPE，`vocab_size=50257`，`max_context=1024` |
| 演示参数 | `batch=1`、输入长度桶 `8/16`、`max_new_tokens<=4`、`context_window=16` |
| 绑定 | `model_manifest{model_hash,tokenizer_hash,precision_plan_hash,model_version,operator_version}` |

演示参数中 `context_window=16` 是 TEE 侧的固定窗口，与 GPT-2 原生 1024 上下文
无关；节点只处理窗口内的 token。

### 5.5 决策记录：模型语言

2026-10-12 三方确认正式模型为**英文 GPT-2**，取代开发方案文档原先的"中文 GPT-2
级"表述。理由：权重与 tokenizer 公开、许可证明确（Modified MIT）、可直接下载并
hash，无需额外的中文语料与许可证审查。

5.1-5.3 的文件格式与加载方式不因该决定改变。受影响的是 `model_hash`、
`tokenizer_hash` 和 `operator_version` 的取值，在 D7 冻结正式权重后填入本表。

### 5.6 tokenizer 加载

tokenizer 在客户端 `C` 本地运行，节点只接收已拆分的 RSS 输入份额。实现固定为
GPT-2 BPE：客户端先用 GPT-2 BPE 把提示编码为 token id，再按 `8/16` 长度桶补齐并
拆分份额；节点侧不接触原始文本。

`tokenizer_hash` 写入 `model_manifest` 并与会话绑定；tokenizer 替换后旧 share、
旧 Ticket、旧材料均不得复用。

## 6. 变更流程

以下任一项变化，必须评审、更新测试向量、递增对应版本号，并同步本文与
[`protocol-baseline.md`](protocol-baseline.md)：

- canonical JSON 编码、REPORTDATA 绑定、release policy；
- 会话字段、帧 AAD、KAS 配置字段；
- 端口表、节点配置 schema 版本；
- 模型、tokenizer、量化 scale、张量布局、角色名、hash 算法、材料 ID、Ticket 字段。

`node_config.schema.json` 的 `config_version`、`precision_plan` 版本和
`protocol_version` 是版本递增的锚点。

## 7. 待三方确认项

已确认：正式模型为英文 GPT-2（见 5.4/5.5）。以下仍需确认：

1. 目标地域与可用区（影响 PCCS endpoint 和 DCAP QVL 版本）。
2. 三节点最终规格是否维持 `g7t.2xlarge`，或根据 profile 调整。
3. KAS 独立控制面的实例规格与域名。
4. 端口表 47100-47112 与 8443/8444 是否与团队其他服务冲突。
5. SPU/YACL 的具体 commit 与 DCAP QVL 版本，在镜像构建时登记。

## 8. 证据

本机可生成的接口证据：

```bash
python -m infra.validate_node_config --config configs/node.example.json \
  --output artifacts/local-validation/node-config-validation.json
python -m infra.validate_gramine_manifest \
  --template tee/gramine/a122.manifest.template \
  --values deploy/gramine-values.example.json \
  --output artifacts/local-validation/a122.manifest
python -m infra.build_model_package --output artifacts/local-validation/model-package --verify
```

这些证据只证明接口一致和静态约束成立，不代表 SGX、真实 mTLS、encrypted FS 或
EPC 验收。

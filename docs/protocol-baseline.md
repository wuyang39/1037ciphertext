# A1-22 协议与接口基线

本文记录当前代码已经冻结的 D0/D1/D2 接口。修改 canonical JSON、REPORTDATA 绑定、release policy、会话字段、帧 AAD 或 KAS 配置字段时，必须同步更新 schema、测试向量、版本号和本文。

环境、版本、三节点端口与配置格式、KAS 部署位置和模型份额等跨团队约定见
[`interface-freeze.md`](interface-freeze.md)。

## Canonical JSON

manifest、policy 和后续签名对象统一使用以下编码计算哈希：

- UTF-8；
- 对象 key 升序；
- 不使用多余空白；
- 禁止 `NaN` 和 `Infinity`；
- 摘要算法为 SHA-256，十六进制小写。

实现位于 `contracts/canonical.py`，schema 位于
`contracts/schemas/`。

## REPORTDATA 绑定

TEE 节点在 enclave 内生成临时 P-256 密钥，KAS 对以下规范编码做 SHA-256：

```text
"A1-22:report-data:v1\0"
|| uint32_be(len(SubjectPublicKeyInfo_DER)) || SubjectPublicKeyInfo_DER
|| uint32_be(len(role)) || role_utf8
|| uint32_be(len(release_id)) || release_id_utf8
|| uint32_be(len(nonce)) || nonce_32_bytes
```

摘要占 REPORTDATA 前 32 字节，后 32 字节必须为零。KAS 只在当前 challenge nonce、
role、release_id、CSR 公钥全部绑定成功且 Quote 非 debug 时签发短期节点证书。

## 最小 KAS API

```text
POST /v1/challenge
  {role, release_id}
  -> {challenge_id, nonce, expires_at}

POST /v1/attest
  {challenge_id, role, release_id, dcap_quote_b64, csr_pem}
  -> {node_certificate_pem, ca_bundle_pem, lease_id, expires_at}

POST /v1/issue-job-ticket
  {session_id, node_role, release_id, model_manifest_hash,
   precision_plan_hash, share_epoch, length_bound, max_new_tokens,
   client_ephemeral_pub}
  -> {signed JobTicket}

POST /v1/consume-ticket
  {ticket_id, enclave_lease_id, session_id, counter}
  -> {status: "accepted"}

GET /v1/ticket-public-key
  -> {public_key}

POST /v1/release-storage-key
  {lease_id, role, release_id, share_epoch, purpose}
  -> {key_id, key_hex, expires_at}
```

`consume-ticket` 的失败不会返回 `accepted`：未知 Ticket 为 404，已消费为
409，过期为 410，签名/绑定/Lease 不合法为 403。

`release-storage-key` 只接受仍有效的节点 Lease。Key 由 KAS 的
`KAS_STORAGE_KEY_MASTER_HEX`、角色、release、epoch 和 purpose 经 HKDF-SM3
确定性派生；同一 `(lease_id, share_epoch, purpose)` 的重复放行返回 409。
该接口在当前本地代码中是 mock HTTP 交付，服务器阶段必须把它放到
已验证的 RA-TLS 通道上。

challenge 为一次性对象。即使 Quote 验证失败，challenge 也已消费，不能重试同一
nonce。正式 KAS 没有“跳过验证”配置；缺少 CA、policy 或 DCAP verifier 时启动失败。

## DCAP Verifier 边界

部署环境通过 `KAS_DCAP_VERIFY_BIN` 指定一个不接受网络输入的外部验证器。KAS 将该
程序作为子进程调用：

```text
<verifier> --quote <temporary-file> --json
```

成功时必须输出：

```json
{
  "mrenclave": "64 lowercase hex characters",
  "mrsigner": "64 lowercase hex characters",
  "isvsvn": 1,
  "debug": false,
  "report_data_b64": "base64 of exactly 64 bytes"
}
```

非零退出、超时、字段缺失、无效十六进制或错误 REPORTDATA 长度全部拒绝。

## D2 国密会话

协议版本为 `a122-gm-session-v1`。客户端与节点执行：

```text
ClientHello -> ServerHello -> Finished -> FinishedAck
```

双方的身份密钥由 KAS 签发的 canonical SM2 证书绑定。临时 SM2 密钥通过完整
handshake transcript 进行身份签名绑定，ECDH 共享点再经过 SM3/HKDF 派生
`C2P` 与 `P2C` 两个方向独立的 SM4 密钥和 8-byte nonce prefix。HKDF context
绑定 transcript hash、`session_id`、节点角色、release、模型版本、模型
manifest hash、precision plan hash 与 `share_epoch`。

业务帧使用 12-byte nonce：`nonce_prefix || uint32_be(counter)`。AAD 固定为：

```text
protocol_version, session_id, epoch, counter, sender, receiver,
model_manifest_hash, request_hash, message_type
```

默认接收端要求 counter 严格递增：重复、旧帧、跳号、跨 session、跨 epoch 或
跨模型均在 AEAD 解密和进入 MPC 前拒绝。`Close` 帧认证成功后双方进入关闭态，
后续帧不再接收。

`JobTicket` 由 KAS SM2 私钥签名，绑定 `ticket_id`、`session_id`、
`node_role`、`release_id`、模型与 precision hash、`share_epoch`、
`length_bound`、`max_new_tokens`、客户端临时公钥、`expiry` 与 `counter`。
Ticket 消费状态只保存在 KAS 在线一次性账本；消费请求还必须绑定未过期的
attestation Lease。

## SM4-GCM 实现边界

`crypto/sm4_gcm.py` 的默认 `SM4GCM` 使用 OpenSSL native SM4 和 native GCM，
provider 标记为 `openssl-native-sm4-gcm`。测试覆盖 GB/T 36624-2018、
RFC 8998、篡改拒绝和 native/Python oracle 一致性向量。

`PurePythonSM4GCM` 仅保留为显式测试 oracle，不会被默认协议路径隐式选择。
正式部署仍应使用组织批准的 OpenSSL/GmSSL/硬件密码构建，并确认 FIPS/合规配置；
替换 provider 后协议字段和测试向量保持不变。

## 环境变量

```text
KAS_CA_KEY_PATH
KAS_CA_CERT_PATH
KAS_RELEASE_POLICY_PATH
KAS_DCAP_VERIFY_BIN
KAS_TICKET_SIGNING_KEY_PATH
KAS_STORAGE_KEY_MASTER_HEX
KAS_HOST
KAS_PORT
KAS_CHALLENGE_TTL_SECONDS
KAS_NODE_LEASE_TTL_SECONDS
```

CA 私钥和 Ticket 签名私钥不得进入 Git、镜像环境变量或普通配置。示例 policy
只用于 schema 演示，必须替换为 release pipeline 登记的真实测量值。

## D3-D8 本地实现边界

- `tee/storage.py`：可验证的 encrypted-FS mock，支持 lease 绑定、错误 key、
  篡改、错 epoch 和失败清理；它不能证明宿主上的真实密文卷已经安全。
- `tee/worker.py`：固定入口 `run_inference(ticket, input_share)`，启动前要求
  active Lease、release 绑定的 storage key 和 Worker startup hash。
- `mpc/secure_ops/rss.py`：3PC RSS ring 算术和 Beaver 乘法 mock，覆盖
  add、mul、matmul、truncate、compare、reciprocal 与 1,000 组向量。
- `mpc/spu_backend/mtls.py`：TLS 1.3、KAS CA、双向证书、SAN allowlist 和
  builtin services 关闭的 fail-closed policy mock；不是实际 TLS 实现。
- `mpc/spu_backend/transport.py`：真实 localhost TCP/TLS 1.3 frame
  transport，用于本机三节点软件联调；TLS 在宿主进程终止，不是 enclave 内 mTLS。
- `mpc/secure_ops/transformer.py`：Tiny Decoder Block 的固定点/RSS 本地参考。
  Softmax、LayerNorm、GELU、Argmax 的运行路径显式标为 simulation reveal，
  正式路径必须替换为 secure operator。
- `mpc/secure_ops/provider.py`：可注入的 secure nonlinear provider 边界；
  默认本地实现是显式 simulation reveal，生产 provider 未配置时 fail-closed。
- `client/result.py`：三份 ResultFrame 的签名、加密、session/model/epoch/
  decode_step/request 绑定与一致性检查。
- `model/export.py`、`model/quantization.py`、`model/graph.py`：确定性权重
  导出、dyadic 量化、静态图 hash。
- `mpc/stage_planner/planner.py`：只合并 layout/scale 相同的相邻 stage，并
  保留优化前后 graph hash。

以上本地结果不得作为 SGX Quote、真实 encrypted FS、真实 mTLS、三节点
enclave 或性能数据的验收证据。

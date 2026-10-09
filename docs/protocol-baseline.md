# A1-22 协议与接口基线

本文记录当前代码已经冻结的 D0/D1/D2 接口。修改 canonical JSON、REPORTDATA 绑定、release policy、会话字段、帧 AAD 或 KAS 配置字段时，必须同步更新 schema、测试向量、版本号和本文。

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
```

`consume-ticket` 的失败不会返回 `accepted`：未知 Ticket 为 404，已消费为
409，过期为 410，签名/绑定/Lease 不合法为 403。

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

`crypto/sm4_gcm.py` 使用 GmSSL Python 的 SM4 分组原语，并按 NIST SP 800-38D
组合 GCM。测试覆盖 GB/T 36624-2018、RFC 8998 与篡改拒绝向量。

该 SM4 分组原语是纯 Python，不具备生产级常数时间保证。正式 SGX 部署必须替换
为经审计的 native GmSSL/硬件密码提供方；替换后协议字段和测试向量保持不变。

## 环境变量

```text
KAS_CA_KEY_PATH
KAS_CA_CERT_PATH
KAS_RELEASE_POLICY_PATH
KAS_DCAP_VERIFY_BIN
KAS_TICKET_SIGNING_KEY_PATH
KAS_HOST
KAS_PORT
KAS_CHALLENGE_TTL_SECONDS
KAS_NODE_LEASE_TTL_SECONDS
```

CA 私钥和 Ticket 签名私钥不得进入 Git、镜像环境变量或普通配置。示例 policy
只用于 schema 演示，必须替换为 release pipeline 登记的真实测量值。

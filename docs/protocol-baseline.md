# A1-22 协议与接口基线

本文记录当前代码已经冻结的 D0/D1 接口。修改 canonical JSON、REPORTDATA 绑定、release policy 或 KAS 配置字段时，必须同步更新 schema、测试向量、版本号和本文。

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
```

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

## 环境变量

```text
KAS_CA_KEY_PATH
KAS_CA_CERT_PATH
KAS_RELEASE_POLICY_PATH
KAS_DCAP_VERIFY_BIN
KAS_HOST
KAS_PORT
KAS_CHALLENGE_TTL_SECONDS
KAS_NODE_LEASE_TTL_SECONDS
```

CA 私钥不得进入 Git、镜像环境变量或普通配置。示例 policy 只用于 schema 演示，
必须替换为 release pipeline 登记的真实测量值。

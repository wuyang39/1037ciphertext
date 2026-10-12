# D1 单机真实 SGX 证明验收记录

> 运行编号：`d1-20261012T1810`（证明闭环）、`d1-20261012T1830`（Gramine）
>
> 结论：**D1 通过**。正确 release 放行，四项拒绝负例全部拒绝，最小
> Gramine-SGX 程序在 `sgx.debug=false` 下取得可用 DCAP Quote。

本记录覆盖 [后续开发总计划.md](后续开发总计划.md) 第 5 节的 D1 证明闭环和最小
Gramine-SGX 程序。D3 及之后阶段尚未执行。

## 1. 验收环境

| 项目 | 实测值 |
| --- | --- |
| 实例 | `iZuf6bjvfplpwleemaipwmZ`（`ecs.g7t.xlarge` 同族 vSGX） |
| 地域 | `cn-shanghai` |
| 系统 | Ubuntu 22.04.5 LTS，内核 `5.15.0-191-generic`，`x86_64` |
| CPU | Intel Xeon Platinum 8369B，CPUID `SGX`/`SGX_LC` 均为 true |
| 设备 | `/dev/sgx_enclave`、`/dev/sgx_provision` 均存在 |
| AESM | `aesmd` active |
| SGX SDK | `/opt/intel/sgxsdk` 2.30.101.1 |
| DCAP | `libsgx-dcap-ql` / `quote-verify` / `default-qpl` 1.27.101.1 |
| PCCS | `https://sgx-dcap-server-vpc.cn-shanghai.aliyuncs.com/sgx/certification/v4/` |
| Python | 3.12.15（uv 用户态安装，系统仅自带 3.10.12） |

环境自检命令：

```bash
python3 -m infra.d1_environment_check --require-hardware \
  --output artifacts/server/<run-id>/d1-environment.json
```

## 2. 使用的工具

- [tee/attestation/quote_probe](../tee/attestation/quote_probe)：最小 SGX enclave +
  宿主程序，用 AESM 出进程模式生成真实 ECDSA Quote，并把 KAS 绑定的
  `REPORTDATA` 写进 Quote。
- [tee/attestation/dcap_verifier](../tee/attestation/dcap_verifier)：
  `a122_dcap_verify`，即 `KAS_DCAP_VERIFY_BIN`，用 Intel DCAP QVL 校验 Quote
  签名链与 TCB，输出 KAS 需要的 JSON。
- [infra/d1_server_acceptance.py](../infra/d1_server_acceptance.py)：
  用 `KASSettings.from_env` / `build_service` 的生产装配路径驱动闭环。
- [deploy/run_d1_server.sh](../deploy/run_d1_server.sh)：一键构建三种探针并运行。

## 3. 结果

驱动脚本把正确路径与四项负例一起跑完：

| 步骤 | 结果 | 拒绝 / 放行原因 |
| --- | --- | --- |
| `accepted-release` | **accepted** | 真实 DCAP Quote 通过校验，签发节点证书与 Lease |
| `deny-tampered-measurement` | **rejected** | `PolicyRejected: MRENCLAVE does not match the release` |
| `deny-debug-quote` | **rejected** | `PolicyRejected: debug Quote is forbidden` |
| `deny-replayed-challenge` | **rejected** | `ChallengeNotFound: challenge is unknown or already consumed` |
| `deny-replaced-public-key` | **rejected** | `AttestationRejected: REPORTDATA does not bind the temporary node key` |

正确路径的关键值：

| 项目 | 值 |
| --- | --- |
| `MRENCLAVE` | `8c8170e210f65e196b8230212805bf29e0917af0a90c610ff869d2a207a5571f` |
| `MRSIGNER` | `fb8f5b31fd44ae0979e34b39dbedb124309e79597d43e90891ec0cc7c17e238d` |
| `ATTRIBUTES.DEBUG` | `false`（flags `0x0000000000000005`） |
| DCAP 校验状态 | `0x0000`（成功），结果 `0x0000a008`（非终结性：TCB 最新，需平台配置/软件加固） |
| Collateral 过期状态 | `0`（未过期） |
| Quote 大小 | `4734` 字节，签名数据 `4298` 字节，`cert_key_type=0x5` |

`0xa008` 是 `TEE_QV_MK_ERROR(0x0008)`，即
`SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED`。按 `sgx_qve_header.h`
的语义，它与 `OK`、`CONFIG_NEEDED`、`OUT_OF_DATE`、`SW_HARDENING_NEEDED`
等一样属于“校验通过但需要后续动作”；`INVALID_SIGNATURE`、`REVOKED`、
`UNSPECIFIED` 才是终结性失败，`a122_dcap_verify` 对后者返回非零使 KAS
fail-closed。附带的安全公告为 `INTEL-SA-00615 / 00657 / 00767`。

## 4. 证据

完整证据目录：[docs/evidence/d1-20261012T1810](evidence/d1-20261012T1810)。

离线校验：

```bash
python -c "from pathlib import Path; from infra.evidence import verify_directory; \
print(verify_directory(Path('docs/evidence/d1-20261012T1810'))['file_count'])"
```

目录内含 `quote.bin`、`quote-report.json`、`dcap-verify.json`、
`kas-policy.json`、`node-csr.pem`、`node-certificate.pem`、`lease.json`、
四项 `deny-*.json`，以及 `instance-check.txt`、`cpuinfo-and-devices.txt`、
`d1-environment.json`、`sample-enclave.txt` 和 `evidence.sha256`。

## 5. 最小 Gramine-SGX 程序

计划的第 5 节第 4 项要求先跑通一个最小 Gramine-SGX 程序。实例账号最初不在
`sudoers` 中，2026-10-12 取得提权后补充执行：

```bash
sudo bash deploy/install_gramine_server.sh   # packages.gramineproject.io，Gramine 1.9
bash deploy/run_d1_gramine.sh d1-20261012T1830
```

`deploy/run_d1_gramine.sh` 构建 [tee/gramine/hello](../tee/gramine/hello) 探针，
渲染并用一次性密钥签名 manifest，运行 `gramine-sgx ./hello` 取 enclave 内的
DCAP Quote，再交给 `a122_dcap_verify` 校验。

| 项目 | 值 |
| --- | --- |
| Gramine | 1.9（`gramine`、`gramine-ratls-dcap`） |
| `sgx.debug` | `false` |
| Quote | ECDSA/DCAP，4734 字节，`ATTRIBUTES.DEBUG=false`（flags `0x0000000000000005`） |
| DCAP 校验状态 | `0x0000`，结果 `0x0000a008` |
| `MRENCLAVE` | `0427d1eb51730429ff03239e6c5998a667cec38e1d938d2401a7309212b612b0` |
| `MRSIGNER` | `4a5a7e01f7d5c187345ad38d1a50a41e3a95a1c75f63c383ef16517cb0453292` |
| REPORTDATA 绑定 | 探针写入的 64 字节与 Quote 报告体一致 |

证据目录：[docs/evidence/d1-20261012T1830](evidence/d1-20261012T1830)。

## 6. 本轮未完成

1. `MRSIGNER` 由每次运行新生成的 enclave 签名密钥决定；两条 D1 记录中的
   Quote 都与当次 release policy 自洽。冻结发布时应改用固定的发布签名密钥。
2. 生产模板 `tee/gramine/a122.manifest.template` 与 Gramine 1.9 的 schema 不兼容，
   已实测定位到三处；这三处在 D3 中按 1.9 schema 修正并通过实机校验，见
   [d3-encfs-acceptance.md](d3-encfs-acceptance.md) 第 7 节。
3. D3–D10 的全部内容仍未开始。

## 7. 复现

```bash
git clone https://github.com/wuyang39/1037ciphertext.git
cd 1037ciphertext
uv python install 3.12
uv venv --python 3.12 ~/a122-venv
uv pip install --python ~/a122-venv/bin/python \
  'cryptography>=48,<49' 'gmssl>=3.2.2,<4' 'pydantic>=2.5,<3' 'jsonschema>=4.26,<5'
PYTHON=~/a122-venv/bin/python bash deploy/run_d1_server.sh
```

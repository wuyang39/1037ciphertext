# A1-22 结论映射表

D10 的验收门要求"所有对外结论能对应到代码、配置、日志或实测图表"。本文把每一条
对外结论钉到具体证据上，并明确标出**尚未完成**的部分，避免把本地结果当成
SGX 验收。

状态取值：

- **本地已验证**：代码、测试、封存证据齐全，但不构成 SGX/enclave 结论。
- **服务器已验证**：在真实 SGX 实例上运行并封存证据。
- **未完成**：尚无证据，必须如实标注。

## 1. 服务器硬件阶段

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| D1 证明闭环：Quote 生成、验证、KAS 放行 | 服务器已验证 | `d1-server-acceptance.md`；`docs/evidence/d1-20261012T1810` |
| 最小 Gramine-SGX 程序可运行并通过 DCAP 校验 | 服务器已验证 | `d1-server-acceptance.md`；`docs/evidence/d1-20261012T1830` |
| Gramine encrypted FS 挂载、明文删除、宿主侧拒绝 | 服务器已验证 | `d3-encfs-acceptance.md`；`docs/evidence/d3-20261012T1930` |
| KAS 放行 `K_disk_i` 与固定 Worker 入口启动条件 | 服务器已验证 | `d3-kas-release-acceptance.md`；`docs/evidence/d3-kas-20261012T115025Z` |
| 真实 attestation 门控的 KAS 放行（Quote → 验证 → 短期身份/Lease） | **未完成** | 缺口记录见 `d6-acceptance.md` §6 与 `local-completion-status.md`；当前回执签名链来自本地 PKI |

## 2. 三节点隐私推理

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| 3PC RSS 传输层、1,024 组向量、抓包、五类 fail-closed | 服务器已验证 | `d4-acceptance.md`；`docs/evidence/d4-20261012T143111Z`、`d4-3host-20261012T152216Z`、`d4-negs-3host-20261012T154315Z` |
| 三台独立实例的 `gramine-sgx` 内跑同一份受测树、单一 MRENCLAVE | 服务器已验证 | `d4-acceptance.md`；`docs/evidence/d4-enclave-shared-3host-20261013T1715Z` |
| enclave 内负例连跑三次全部拒绝、测量值逐字节复现 | 服务器已验证 | `docs/evidence/d4-enclave-negs-repeat-3host-20261013T0907Z` |
| enclave 内完整 Tiny Decoder Block（38 用例、溢出 0、无生产 reveal） | 服务器已验证 | `d5-acceptance.md`；`docs/evidence/d5-enclave-3host-20261013T1057Z` |
| enclave 内端到端私有自回归 3 token、安全 Argmax 与客户端一致 | 服务器已验证 | `d6-acceptance.md`；`docs/evidence/d6-enclave-3host-20261013T1324Z` |
| 会话关闭后 KV/份额被覆写删除、host 扫描干净 | 服务器已验证 | `d6-acceptance.md`；同上证据包 |

## 3. 正式模型（D7 本地部分）

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| GPT-2 small @ `607a30d7…` 冻结、逐文件 SHA-256 复核、Modified MIT 许可 | 本地已验证 | `docs/d7-model-freeze.md`；`docs/evidence/d7-local-model-20261013T1425Z/d7-freeze.json` |
| 程序自身浮点参考与发布版 logits 在候选列最大误差 5.82e-5 | 本地已验证 | 同上 `d7-fidelity.json` |
| 3 步贪心 token 与发布版一致（`,` ` and` ` the`） | 本地已验证 | 同上 `d7-generation.json`、`d7-summary.json` |
| 逐张量最差标定误差 1.9e-6、最窄位宽 18 | 本地已验证 | 同上 `d7-calibration.json`、`d7-precision-plan.json` |
| 纯 Python BPE 与 `GPT2TokenizerFast` 逐 id 一致 | 本地已验证 | `tests/unit/test_d7_gpt2_tools.py` |
| 三节点 enclave 内加载正式模型份额并生成 token | **未完成** | `d7-model-freeze.md` §6 方案；本轮验收实例已释放，无运行条件 |

## 4. D10 交付与其边界

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| release 包可由空目录解压并按安装手册运行（无需手工补丁） | 见 D10 证据包 | `docs/evidence/d10-release-20261013T144830Z/rehearsal.json` 与 `rehearsal.log` |
| CycloneDX SBOM 覆盖本地包、Python 依赖、服务器运行时与冻结模型 | 见 D10 证据包 | 同上 `sbom.json`；生成器 `infra/build_sbom.py` |
| 正式模型卡与许可清单 | 见 | `docs/model-card-gpt2.md`、`third_party/gpt2/LICENSE` |
| 仓库内无生产密钥/份额/会话材料 | 见 D10 证据包 | 同上 `secrets-sweep.json` |
| 三个验收实例地址已不再应答 | 见 D10 证据包 | 同上 `release-check.json`（探测）；计费中心确认另见 `resource-release.json` |

## 5. 答辩口径规则

1. 只报告由 trace、日志、hash 或测试输出直接支持的结论。
2. 任何仍依赖服务器阶段的指标标为 `pending_server`，不得用模拟值代替实测值。
3. 第 1、2 节标为"服务器已验证"的结论可以对外陈述；第 3 节的 D7 本地结论
   必须带"本地"限定；第 1、3 节的"未完成"条目不得在答辩中表述为已完成。

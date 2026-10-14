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

## 3. 正式模型（D7）与性能档位（D8）

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| GPT-2 small @ `607a30d7…` 冻结、逐文件 SHA-256 复核、Modified MIT 许可 | 本地已验证 | `docs/d7-model-freeze.md`；`docs/evidence/d7-local-model-20261013T1425Z/d7-freeze.json` |
| 程序自身浮点参考与发布版 logits 在候选列最大误差 5.82e-5 | 本地已验证 | 同上 `d7-fidelity.json` |
| 3 步贪心 token 与发布版一致（`,` ` and` ` the`） | 本地已验证 | 同上 `d7-generation.json`、`d7-summary.json` |
| 逐张量最差标定误差 1.9e-6、最窄位宽 18 | 本地已验证 | 同上 `d7-calibration.json`、`d7-precision-plan.json` |
| 纯 Python BPE 与 `GPT2TokenizerFast` 逐 id 一致 | 本地已验证 | `tests/unit/test_d7_gpt2_tools.py` |
| 三节点 enclave 各自加载正式权重份额并连续生成 3 个 token（提示 `the cipher key is secret` → ` secret secret secret`） | 服务器已验证 | `docs/d7-acceptance.md`；`docs/evidence/d7-enclave-3host-20261014T1018Z` |
| 逐步安全 Argmax 与客户端重建 logits 的 Argmax 一致；与 float64 参考最差 `max_abs_error` 0.0650 | 服务器已验证 | 同上 `d7-client-result.json` |
| 五类篡改/重放负例（重复结果帧、篡改 `decode_step`、混用模型 manifest、重放输入帧、重放 JobTicket）在进入 MPC 前全部被拒 | 服务器已验证 | 同上 `d7-summary.json`、`d7-three-p1-node-status.json` |
| close 后会话目录被覆写删除、KV 无残留、清洁度与 reveal 扫描干净、staged 份额跑完覆写删除 | 服务器已验证 | 同上 `d7-hygiene-p{0,1,2}.json`、`d7-reveal-scan.json` |
| 三份抓包判决 `tls13_only`、非 TLS 字节 0、空洞 0 | 服务器已验证 | 同上 `d7-three-P{0,1,2}-tls-summary.txt` |
| 层数与候选词表超出本次实测范围（1 层 + 1028 候选） | **未完成** | 本次是 1 层探针；更高层数与完整 `vocab = 50257` 没有实测 |

D8 把同一份 D7 工作负载放进三档声明网络条件下各跑一遍，逐档采宿主资源、逐台
分析自己那段抓包：

| 结论 | 状态 | 证据 |
| --- | --- | --- |
| 同一份 enclave 工作负载在 LAN / 每台出向 40 ms / 80 ms 三档下都完成，token 与 Argmax 与浮点参考一致 | 服务器已验证 | [d8-acceptance.md](d8-acceptance.md)；`docs/evidence/d8-enclave-profiles-20261014T1056Z` |
| 档位确实生效：标称 40 ms 量到 80.16 ms 往返、标称 80 ms 量到 160.15 ms，`tc` 在 `finally` 里拆除 | 服务器已验证 | 同上，各档 `d7-summary.json` 的 `network.rtt` 与 `network.cleared` |
| 客户端整段 16.534 s / 164.21 s / 274.871 s；线上流量三档相同（每台约 1.25 GB） | 服务器已验证 | 同上，`d8-report.md` |
| 宿主 CPU 均值、enclave RSS 峰值（约 16~17 MB）与 enclave CPU 秒逐档实测 | 服务器已验证 | 同上，`d8-resources-p{0,1,2}.jsonl` 与 `d8-report.md` |
| 报告可由固定脚本从 trace 重算，重算逐字节相同 | 服务器已验证 | 同上，`python -m infra.d8_three_hosts ... --rebuild`，摘要/报告/README 的 sha256 见 [d8-acceptance.md](d8-acceptance.md) 第 4 节 |
| 优化项的开/关消融（softmax/GELU/rsqrt 近似、量化、layout） | **未完成** | 冻结程序没有运行时开关，消融需要第二个冻结程序；缺口见 [d8-acceptance.md](d8-acceptance.md) 第 5 节 |
| 每进程 EPC 常驻量 | **未完成** | 本内核只暴露 EPC 段大小，`/proc` 里没有该计数 |

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
3. 第 1、2 节与第 3 节标为"服务器已验证"的结论可以对外陈述；第 3 节里仍标
   "本地已验证"的 D7 结论必须带"本地"限定；任何标为"未完成"的条目不得在答辩中
   表述为已完成。D7 的 enclave 结论必须同时带上 1 层 + 1028 候选的几何限定，
   不得说成"整个 GPT-2 跑在 enclave 里"。D8 的档位结论只能说成"三档声明网络
   条件下的实测"，不得说成"每项优化都有开/关对照"，也不得给出 EPC 占用量。

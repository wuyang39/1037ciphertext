# A1-22 本地阶段完成状态

本文只记录不依赖真实 SGX/多节点服务器的内容。`本地完成` 表示代码、mock、
拒绝路径和测试已经可运行；`服务器待办` 表示必须在真实 enclave 上重新验收。

> 服务器阶段进展：D1 已在真实 SGX 实例上通过（证明闭环运行
> `d1-20261012T1810`，最小 Gramine-SGX 程序运行 `d1-20261012T1830`），见
> [d1-server-acceptance.md](d1-server-acceptance.md)；D3 的 Gramine encrypted FS
> 也已在同一实例上通过（运行 `d3-20261012T1930`），见
> [d3-encfs-acceptance.md](d3-encfs-acceptance.md)；D3 的 KAS 放行
> `K_disk_i` 与固定 Worker 入口启动条件随后也在同一实例上通过（运行
> `d3-kas-20261012T115025Z`），见
> [d3-kas-release-acceptance.md](d3-kas-release-acceptance.md)。D4 的传输层、
> 1,024 组 RSS 向量、抓包判决和五类 fail-closed 场景在 SGX2 上以三进程形式
> 通过（运行 `d4-20261012T143111Z`），随后 P0/P1/P2 又分到三台独立实例上
> 复跑正向网格、抓包（运行 `d4-3host-20261012T152216Z`）和四类 fail-closed
> 负例（运行 `d4-negs-3host-20261012T154315Z`），两次都由
> `infra.d4_three_hosts` 一条命令驱动，见
> [d4-acceptance.md](d4-acceptance.md)。2026-10-13 又把三个节点放进
> `gramine-sgx`：单实例运行 `d4-enclave-20261013T0530Z` 三个进程共享一个
> MRENCLAVE，三实例运行 `d4-enclave-3host-20261013T052121Z` 与负例
> `d4-enclave-negs-3host-20261013T052407Z` 每台各自签名自己的 manifest，
> 正向与四个负例同样全过；enclave 内四类负例又连跑三次（运行
> `d4-enclave-negs-repeat-3host-20261013T0907Z`），三次全部拒绝、每台实例的
> 测量值跨运行逐字节复现。D5 的完整 Tiny Decoder Block 也已在三个 enclave 内
> 跑通（运行 `d5-enclave-3host-20261013T1057Z`：Softmax/LayerNorm/GELU/Argmax
> 与整个 Block 共 38 个用例全过、溢出 0、三棵树的 reveal 扫描干净、证书互校
> 6/6），见 [d5-acceptance.md](d5-acceptance.md)。D6 的端到端私有自回归随后也
> 在三个 enclave 内跑通（运行 `d6-enclave-3host-20261013T1324Z`：连续生成 3 个
> token、逐步安全 Argmax 与客户端重建 logits 的 Argmax 一致、五类篡改/重放负例
> 全部被拒、close 后会话目录被覆写删除且清洁度与 reveal 扫描干净），见
> [d6-acceptance.md](d6-acceptance.md)。D7 的正式模型随后也在同一套栈上跑通
> （运行 `d7-enclave-3host-20261014T1018Z`：三节点各自加载正式权重份额、连续
> 生成 3 个 token、逐步安全 Argmax 与客户端重建 logits 一致、五类负例全拒、
> close 后会话目录被覆写删除、三份抓包 `tls13_only` 且空洞 0），见
> [d7-acceptance.md](d7-acceptance.md)；受限几何是 **1 层 + 1028 候选**，不写
> "整个 GPT-2"。D8 的网络档位与资源实测随后也在同一套栈上跑完（运行
> `d8-enclave-profiles-20261014T1056Z`：LAN、每台出向 40 ms、80 ms 三档各跑
> 一遍完整流程，客户端整段 16.5 s / 164.2 s / 274.9 s，三档的 token 与误差
> 一致，九次节点运行的清洁度、close 覆写与抓包判决都干净），见
> [d8-acceptance.md](d8-acceptance.md)；**开/关消融没有做**（冻结程序没有
> 运行时开关），也没有每进程 EPC 计数。D9 及之后仍待执行；D4 还差
> 真实 attestation 放行，
> 以及把 staging 固化成一条命令（三台共享同一份受测树已经跑通，运行
> `d4-enclave-shared-3host-20261013T1715Z` 给出单一 MRENCLAVE）。

## 状态矩阵

| 阶段 | 本地完成内容 | 服务器待办 |
|---|---|---|
| D3 | encrypted-FS mock、错误 key/epoch/篡改拒绝、Worker 固定入口、Lease + storage key 状态机、失败清理 | 真实 Gramine encrypted FS、宿主读取证明、KAS 驱动的 `K_disk_i` 放行、Worker startup/epoch/Lease 校验均已在同一实例通过；剩余镜像与 core dump 扫描（D9） |
| D4 | 3PC RSS topology、add/mul/matmul/truncate/compare/reciprocal、固定点 adapter、1,000 组向量、MaterialLedger、mTLS policy mock | 真实 YACL/BRPC TLS 1.3、证书与 SAN/CA 校验、抓包、关闭 TLS 时 fail-closed 已在同一实例（三进程）通过；正向网格、抓包与四类 fail-closed 负例已在三台独立实例通过；三个节点也已在 `gramine-sgx` 内跑通单实例与三实例两种形态，enclave 内负例并连跑三次全部拒绝；三台在三实例 enclave 里跑同一份 staged 受测树、给出单一 MRENCLAVE；剩余真实 attestation 放行与 staging 的入口化 |
| D5 | secure embedding、QKV、causal attention、稳定 Softmax、A*V、残差、LayerNorm、FFN、GELU、Argmax、脱敏 trace | 三个 `gramine-sgx` enclave 内执行完整 Block、真实 secure nonlinear operator、enclave 内通信 profile 均已通过（运行 `d5-enclave-3host-20261013T1057Z`，38/38、溢出 0、无生产 reveal）；剩余正式模型权重（D7）与端到端自回归（D6） |
| D6 | Session runtime、ResultFrame、三帧一致性与篡改拒绝、KV cache、secure wipe | 三个 enclave 内的端到端自回归、五类篡改/重放负例、close 前后 tmpfs 扫描均已在三台实例通过（运行 `d6-enclave-3host-20261013T1324Z`，3 个 token、逐步 Argmax 一致、会话目录被覆写删除、扫描干净）；真实回执签名仍待 attestation 放行 |
| D7 | 正式英文 GPT-2（`gpt2` @ `607a30d7…`）冻结复核、safetensors 读取、候选词表规则、逐张量标定、静态图、纯 Python BPE、模型份额与加密份额包均已本地跑通；程序的浮点参考在候选列上与发布版最大差 5.8e-5、3 步贪心 token 完全一致，见 [d7-model-freeze.md](d7-model-freeze.md) 与 `docs/evidence/d7-local-model-20261013T1425Z` | 三个 `gramine-sgx` enclave 内加载正式权重份额并生成 3 个 token 已通过（运行 `d7-enclave-3host-20261014T1018Z`：逐步 Argmax 与客户端重建一致、与 float64 参考最差 `max_abs_error` 0.0650、五类负例全拒、close 后会话目录被覆写删除、清洁度与 reveal 扫描干净、三份抓包 `tls13_only` 空洞 0、staged 份额跑完覆写 92,542,258 字节后删除），见 [d7-acceptance.md](d7-acceptance.md)；仍待补的是更高层数与完整词表的几何（本次受 EPC/时延/份额规模限制为 1 层 + 1028 候选，已如实写进 manifest 与证据） |
| D8 | StagePlanner、softmax/GELU/rsqrt 近似边界、脱敏 benchmark collector、网络 profile、报告脚本 | 三档网络（LAN / 每台出向 40 ms / 80 ms）、宿主 CPU 与可用内存、enclave RSS 与 CPU 秒、线上流量、逐档安全回归已在三台 enclave 上实测，报告可由固定脚本从 trace 重算（运行 `d8-enclave-profiles-20261014T1056Z`，见 [d8-acceptance.md](d8-acceptance.md)）；剩余开/关消融（冻结程序无运行时开关，需第二个冻结程序）、每进程 EPC 计数（本内核不提供该文件）、长度桶与 batch |
| D9 | 本地负例脚本、证据采集脚本、拓扑模板、验收清单 | 三域部署、独立账号/安全组、pcap、宿主机材料演示、离线复现 |
| D10 | 安装手册、[正式模型卡](model-card-gpt2.md)、CycloneDX SBOM 生成器、[结论映射表](conclusion-map.md)、确定性 release 构建（`--tracked-only`）、空目录演练脚本、仓库密钥扫描与实例释放探测均已本地跑通，见 [d10-release-acceptance.md](d10-release-acceptance.md) 与 `docs/evidence/d10-release-20261013T144830Z` | 真实云账号的 15 分钟答辩演练、费用中心无持续计费确认（人工输入） |

## 本机 Linux/WSL 增量完成

除上表外，本机 Linux/WSL 阶段已经补充：

- 真实 localhost TCP/TLS 1.3 三节点传输和 P0/P1/P2 定向链路。
- 默认 OpenSSL native SM4-GCM，纯 Python 实现改为显式测试 oracle。
- secure nonlinear provider 注入边界和未配置时 fail-closed。
- Gramine manifest 模板渲染、占位符和静态安全策略校验。
- Tiny 模型量化、份额拆分、可选加密份额和 package manifest 校验。
- Tiny 参数初始化改为不依赖平台 libm 的可移植实现，使 `parameter_hash`、
  浮点参考夹具和模型包 `model_hash` 在 Windows 与 Linux 上完全一致。
- release archive、外部/embedded manifest 和敏感 marker 校验。
- 统一 evidence schema、索引封存和 SHA-256 校验。
- D1 环境自检、D1-D9 攻击矩阵和本机三节点部署演练。

这些结果不代表 SGX、enclave 内 TLS、encrypted FS 或 EPC 验收。详细说明见
[`local-linux-development.md`](local-linux-development.md)。

## 本地已执行

```powershell
python -m pytest -q
python -m compileall -q client contracts crypto kas model mpc tee tests infra
git diff --check
python infra/security_negative.py --output artifacts/evidence/negative-checks.json
python infra/collect_evidence.py --root . --output artifacts/evidence/local-checks.json
python infra/build_release.py --root . --output artifacts/a122-local.zip --version local-checkpoint
python infra/attack_matrix.py --output artifacts/evidence/attack-matrix.json
python infra.d1_environment_check.py --output artifacts/evidence/d1-environment.json
python infra.local_three_node.py --output artifacts/evidence/local-three-node.json
python infra.build_model_package.py --output artifacts/model-package --encrypt-local
python infra.build_model_package.py --output artifacts/model-package --verify
python -m model.export --source artifacts/gpt2-frozen --out artifacts/d7-export --layers 12 --sequence 8 --candidates 1024 --prompt "the cipher key is secret" --license third_party/gpt2/LICENSE
python -m infra.build_model_package --source artifacts/gpt2-frozen --output artifacts/d7-package --layers 12 --sequence 8 --candidates 1024 --prompt "the cipher key is secret" --license third_party/gpt2/LICENSE --encrypt-local
python -m infra.build_model_package --output artifacts/d7-package --verify
python -m infra.d7_local_evidence --source artifacts/gpt2-frozen --out docs/evidence/d7-local-model-<stamp> --license third_party/gpt2/LICENSE
python -m infra.build_release --root . --tracked-only --output artifacts/a122-release-<tag>.zip --version <tag>
python -m infra.validate_release artifacts/a122-release-<tag>.zip --manifest artifacts/a122-release-<tag>.manifest.json --scan-sensitive
python -m infra.d10_rehearsal --archive artifacts/a122-release-<tag>.zip --out artifacts/d10-rehearsal.json --log artifacts/d10-rehearsal.log
python -m infra.build_sbom --root . --version <tag> --output artifacts/d10-sbom.json
python -m infra.d10_release_check --targets artifacts/d10-targets.json --out artifacts/d10-release-check.json
python -m infra.d10_evidence --root . --out docs/evidence/d10-release-<run-id> --run-id <run-id> --archive artifacts/a122-release-<tag>.zip --release-manifest artifacts/a122-release-<tag>.manifest.json --release-check artifacts/d10-release-check.json --sbom artifacts/d10-sbom.json --rehearsal artifacts/d10-rehearsal.json --rehearsal-log artifacts/d10-rehearsal.log --model-card docs/model-card-gpt2.md --conclusion-map docs/conclusion-map.md
python infra.validate_gramine_manifest.py --values deploy/gramine-values.example.json
```

当前本地结果只能作为 mock 与接口证据，不能标记为 SGX 验收通过。

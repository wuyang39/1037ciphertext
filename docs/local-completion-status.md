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
> 测量值跨运行逐字节复现。D5 及之后仍待执行；D4 还差真实 attestation 放行，
> 以及让三台共享同一份受测代码树（现在三台之间的测量值仍不同）。

## 状态矩阵

| 阶段 | 本地完成内容 | 服务器待办 |
|---|---|---|
| D3 | encrypted-FS mock、错误 key/epoch/篡改拒绝、Worker 固定入口、Lease + storage key 状态机、失败清理 | 真实 Gramine encrypted FS、宿主读取证明、KAS 驱动的 `K_disk_i` 放行、Worker startup/epoch/Lease 校验均已在同一实例通过；剩余镜像与 core dump 扫描（D9） |
| D4 | 3PC RSS topology、add/mul/matmul/truncate/compare/reciprocal、固定点 adapter、1,000 组向量、MaterialLedger、mTLS policy mock | 真实 YACL/BRPC TLS 1.3、证书与 SAN/CA 校验、抓包、关闭 TLS 时 fail-closed 已在同一实例（三进程）通过；正向网格、抓包与四类 fail-closed 负例已在三台独立实例通过；三个节点也已在 `gramine-sgx` 内跑通单实例与三实例两种形态，enclave 内负例并连跑三次全部拒绝；剩余真实 attestation 放行与三方共享同一份受测代码树 |
| D5 | secure embedding、QKV、causal attention、稳定 Softmax、A*V、残差、LayerNorm、FFN、GELU、Argmax、脱敏 trace | 三个 enclave 内执行、secure nonlinear operator、真实通信 profile |
| D6 | Session runtime、ResultFrame、三帧一致性与篡改拒绝、KV cache、secure wipe | 真实两 token 自回归、enclave tmpfs 扫描、真实回执签名 |
| D7 | Torch/HuggingFace 风格权重导出、模型 hash、dyadic 量化、precision plan、静态图、份额拆分/导入 | 正式英文 GPT-2（`gpt2`）权重、真实三节点模型加载和 token 生成 |
| D8 | StagePlanner、softmax/GELU/rsqrt 近似边界、脱敏 benchmark collector、网络 profile、报告脚本 | EPC/CPU/RAM、真实延迟、通信量、开关对照和安全回归 |
| D9 | 本地负例脚本、证据采集脚本、拓扑模板、验收清单 | 三域部署、独立账号/安全组、pcap、宿主机材料演示、离线复现 |
| D10 | 安装手册、模型卡、SBOM、复现文档、攻击演示、确定性 release 构建 | 干净账号答辩演练、最终实测结论和证据冻结 |

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
python infra.validate_gramine_manifest.py --values deploy/gramine-values.example.json
```

当前本地结果只能作为 mock 与接口证据，不能标记为 SGX 验收通过。

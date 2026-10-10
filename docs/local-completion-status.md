# A1-22 本地阶段完成状态

本文只记录不依赖真实 SGX/多节点服务器的内容。`本地完成` 表示代码、mock、
拒绝路径和测试已经可运行；`服务器待办` 表示必须在真实 enclave 上重新验收。

## 状态矩阵

| 阶段 | 本地完成内容 | 服务器待办 |
|---|---|---|
| D3 | encrypted-FS mock、错误 key/epoch/篡改拒绝、Worker 固定入口、Lease + storage key 状态机、失败清理 | Gramine encrypted FS、宿主读取证明、镜像/环境变量/core dump 扫描 |
| D4 | 3PC RSS topology、add/mul/matmul/truncate/compare/reciprocal、固定点 adapter、1,000 组向量、MaterialLedger、mTLS policy mock | 真实 YACL/BRPC TLS 1.3、三节点证书、抓包、关闭 TLS 时 fail-closed |
| D5 | secure embedding、QKV、causal attention、稳定 Softmax、A*V、残差、LayerNorm、FFN、GELU、Argmax、脱敏 trace | 三个 enclave 内执行、secure nonlinear operator、真实通信 profile |
| D6 | Session runtime、ResultFrame、三帧一致性与篡改拒绝、KV cache、secure wipe | 真实两 token 自回归、enclave tmpfs 扫描、真实回执签名 |
| D7 | Torch/HuggingFace 风格权重导出、模型 hash、dyadic 量化、precision plan、静态图、份额拆分/导入 | 正式中文 GPT-2 级模型、真实三节点模型加载和 token 生成 |
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

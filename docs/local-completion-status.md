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

## 本地已执行

```powershell
python -m pytest -q
python -m compileall -q client contracts crypto kas model mpc tee tests infra
git diff --check
python infra/security_negative.py --output artifacts/evidence/negative-checks.json
python infra/collect_evidence.py --root . --output artifacts/evidence/local-checks.json
python infra/build_release.py --root . --output artifacts/a122-local.zip --version local-checkpoint
```

当前本地结果只能作为 mock 与接口证据，不能标记为 SGX 验收通过。

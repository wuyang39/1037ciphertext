# A1-22 本地复现记录

## 已固定的参考

- 协议：`docs/protocol-baseline.md`
- Tiny 模型：`tests/fixtures/tiny_float_reference.json`
- D2 协议 schema：`contracts/schemas/`
- 本地安全负例：`infra/security_negative.py`
- 证据采集：`infra/collect_evidence.py`

## 本地复现步骤

```powershell
python -m pytest -q
python -m model.build_tiny_fixture --output tests/fixtures/tiny_float_reference.json
python infra/security_negative.py --output artifacts/evidence/negative-checks.json
python infra.attack_matrix.py --output artifacts/evidence/attack-matrix.json
python infra.d1_environment_check.py --output artifacts/evidence/d1-environment.json
python infra.local_three_node.py --output artifacts/evidence/local-three-node.json
python infra.build_model_package.py --output artifacts/model-package --encrypt-local
python infra.build_model_package.py --output artifacts/model-package --verify
python infra.validate_gramine_manifest.py --values deploy/gramine-values.example.json --output artifacts/a122.manifest
python infra/collect_evidence.py --root . --output artifacts/evidence/local-checks.json
python infra/build_release.py --root . --output artifacts/a122-local.zip --version local-checkpoint
python infra.validate_release.py artifacts/a122-local.zip --manifest artifacts/a122-local.manifest.json
python infra.seal_evidence.py seal artifacts/evidence
python infra.seal_evidence.py verify artifacts/evidence
```

## 可重复性边界

本地 RSS、encrypted FS、mTLS 和 Session runtime 都是确定性 mock。它们可以验证接口、拒绝路径、数值范围和状态机，但不能替代：

- 真实 SGX Quote 与 DCAP 策略验证
- Gramine encrypted FS 的宿主读取测试
- 三个真实 enclave 的 mTLS/BRPC 链路
- EPC、SGX 启动延迟、网络 pcap 和三节点 token 生成

## 论文/答辩口径

只报告由 trace、日志、hash 或测试输出直接支持的结论。任何仍依赖服务器阶段的指标必须标为 `pending_server`，不能使用模拟值代替实测值。

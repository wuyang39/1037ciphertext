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

## D10 交付复现

```powershell
# 1. 只打包 Git 跟踪的文件，避免未跟踪的临时材料混入交付包
python -m infra.build_release --root . --tracked-only `
  --output artifacts/a122-release-<tag>.zip --version <tag>
python -m infra.validate_release artifacts/a122-release-<tag>.zip `
  --manifest artifacts/a122-release-<tag>.manifest.json --scan-sensitive

# 2. 空目录演练：解压、编译、跑测试，无需任何手工补丁
python -m infra.d10_rehearsal --archive artifacts/a122-release-<tag>.zip `
  --out artifacts/d10-rehearsal.json --log artifacts/d10-rehearsal.log

# 3. SBOM 与资源释放探测
python -m infra.build_sbom --root . --version <tag> --output artifacts/d10-sbom.json
python -m infra.d10_release_check --targets artifacts/d10-targets.json `
  --out artifacts/d10-release-check.json

# 4. 汇总成封存的 D10 证据包
python -m infra.d10_evidence --root . --out docs/evidence/d10-release-<run-id> `
  --run-id <run-id> --archive artifacts/a122-release-<tag>.zip `
  --release-manifest artifacts/a122-release-<tag>.manifest.json `
  --release-check artifacts/d10-release-check.json --sbom artifacts/d10-sbom.json `
  --rehearsal artifacts/d10-rehearsal.json --rehearsal-log artifacts/d10-rehearsal.log `
  --model-card docs/model-card-gpt2.md --conclusion-map docs/conclusion-map.md
```

`d10_release_check` 只能观测实例地址是否仍应答；费用中心无持续计费项属于人工
确认，作为 operator 输入写入 `resource-release.json`，未确认前计费门不签署。

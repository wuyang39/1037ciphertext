# D10 验收记录：提交物收口与资源释放

运行号：`d10-release-20261013T144830Z`
证据包：[docs/evidence/d10-release-20261013T144830Z](evidence/d10-release-20261013T144830Z)

本文是 D10 的验收记录。它只记录已经发生的测量；凡是没有证据的条目一律标为
未完成或待人工确认。

## 1. 最终 release

| 项 | 值 |
| --- | --- |
| 文件 | `artifacts/a122-release-20261013T144830Z.zip` |
| 版本 | `a122-d10-20261013T144830Z` |
| SHA-256 | `5968dbff16e645658ba53cd7093c639c7582337b04c7bacc7700d0824437077c` |
| 包内文件数 | 605 |
| 解压后字节 | 26,763,638 |
| 打包方式 | `--tracked-only`（只打包 Git 跟踪的文件，未跟踪材料不会混入） |
| manifest 校验 | 通过，`--scan-sensitive` 无未复核敏感标记 |

release 由提交 `ee02b9ece193f27b2a05db466c5a51ecde398d96` 切出：在该提交上运行
第 7 节命令即可复现同一个包。本验收记录和证据包在这之后生成，因此不在包内，
而是与之并列的交付物，用 SHA-256 指向包。

冻结的 GPT-2 权重（548 MB）按设计不进包；包内记录其六个文件的 SHA-256。

## 2. 空目录演练（验收门第 2 项）

`python -m infra.d10_rehearsal` 把上面的包解压到一个空目录，再从解压副本里
编译并运行测试集，import path 上只有解压副本，没有开发机仓库：

| 项 | 结果 |
| --- | --- |
| 安装手册所需文件 | 6/6 齐全 |
| `compileall` | 退出码 0 |
| 从解压副本运行测试 | `288 passed, 3 skipped, 3 warnings in 69.45s` |
| 判定 | `runs-without-patching` |

与开发机基线的差异是 D7 的 2 个模型测试：它们需要冻结权重，而权重不进包，因此
按设计 skip。skip 被记录，不计入通过。

## 3. 模型卡、SBOM 与许可（验收门第 3 项）

| 项 | 结果 |
| --- | --- |
| 模型卡 | [model-card-gpt2.md](model-card-gpt2.md)（SHA-256 `f848d2be…`） |
| 许可 | Modified MIT（OpenAI, 2019），文本 `third_party/gpt2/LICENSE` |
| SBOM | CycloneDX 1.5，25 个组件：9 个本地包、10 个 Python 依赖、5 个服务器运行时、1 个冻结模型 |
| 结论映射 | [conclusion-map.md](conclusion-map.md)，逐条结论钉到证据 |

## 4. 敏感材料清理（验收门第 4 项）

`infra/d10_evidence.sweep_repository` 扫描 594 个 Git 跟踪文件：

| 项 | 结果 |
| --- | --- |
| 禁止路径（`secrets/`、`*.key`、`model_share*.bin`、`*.share` 等） | 0 |
| 数据文件中的敏感标记 | 0 |
| 判定 | `clean` |

三处源码命中列在 `reviewed_source_markers` 并逐条给出理由：一处是密钥包编码器
里的字典字段名，两处是证据扫描器的自测假 PEM。豁免按"路径 + 标记"精确匹配，
同一文件里出现别的标记（例如真 PEM）仍会失败。

扫描边界：它只能为仓库跟踪的内容作证，看不到实例上的生产密钥、模型份额或
会话态；那部分由实例清理记录覆盖。

## 5. 云资源释放（验收门第 6、7、8 项）

`python -m infra.d10_release_check` 探测四个历史地址的 22 端口：

| 地址 | 结果 |
| --- | --- |
| `47.117.34.67` | `no_listener`（连接超时） |
| `106.15.54.240` | `no_listener`（连接超时） |
| `47.116.200.143` | `no_listener`（连接超时） |
| `106.14.207.224` | `no_listener`（连接超时） |

综合判定 `released`：没有任何地址仍用我们的密钥应答。工具在收到 SSH banner 时
会用指定密钥尝试登录，只有"登录成功"才算实例仍在运行，因此不会把仍在计费的
实例误判为已释放；无法验证的情况记为 `unverified` 而不是 `released`。

**未完成，需人工确认**：本仓库没有阿里云 AccessKey，也刻意不保留，因此云盘、
EIP、快照、镜像和公网带宽的持续计费状态，以及费用中心"无持续计费资源"的
确认，都无法由代码读取。`resource-release.json` 把该确认记为
`billing_status = awaiting-operator`。**在该确认写入之前，D10 的资源门不签署。**

## 6. 未完成清单

1. 费用中心无持续计费资源的确认（operator 输入）。
2. 真实云账号上的 15 分钟答辩演练（证明 → 会话 → 推理 → 攻击负例 → 指标报表）。
3. D4 的真实 attestation 门控 KAS 放行。
4. D8 的性能/消融与 D9 的三域部署、攻击演示。
5. D7 的几何扩展：本轮 enclave 解码是 1 层 + 1028 候选（运行
   `d7-enclave-3host-20261014T1018Z`，见 [d7-acceptance.md](d7-acceptance.md)），
   更高层数与完整 `vocab = 50257` 没有实测。

## 7. 复现

```powershell
$stamp = "<UTC 时间戳>"
python -m infra.build_release --root . --tracked-only `
  --output "artifacts/a122-release-$stamp.zip" --version "a122-d10-$stamp"
python -m infra.validate_release "artifacts/a122-release-$stamp.zip" `
  --manifest "artifacts/a122-release-$stamp.manifest.json" --scan-sensitive
python -m infra.d10_rehearsal --archive "artifacts/a122-release-$stamp.zip" `
  --out artifacts/d10-rehearsal.json --log artifacts/d10-rehearsal.log
python -m infra.build_sbom --root . --version "a122-d10-$stamp" --output artifacts/d10-sbom.json
python -m infra.d10_release_check --targets artifacts/d10-targets.json `
  --out artifacts/d10-release-check.json
python -m infra.d10_evidence --root . --out "docs/evidence/d10-release-$stamp" `
  --run-id "d10-release-$stamp" --archive "artifacts/a122-release-$stamp.zip" `
  --release-manifest "artifacts/a122-release-$stamp.manifest.json" `
  --release-check artifacts/d10-release-check.json --sbom artifacts/d10-sbom.json `
  --rehearsal artifacts/d10-rehearsal.json --rehearsal-log artifacts/d10-rehearsal.log `
  --model-card docs/model-card-gpt2.md --conclusion-map docs/conclusion-map.md
python -m infra.seal_evidence verify "docs/evidence/d10-release-$stamp"
```

## 8. 验收门判定

| 门 | 判定 |
| --- | --- |
| 所有对外结论可追溯 | 通过（[conclusion-map.md](conclusion-map.md)，未完成项已标注） |
| 交付包解压后无需手工补丁即可运行 | 通过（本机空目录演练） |
| 云资源已释放且无持续计费项 | **部分**：探测部分通过；费用中心确认待人工 |

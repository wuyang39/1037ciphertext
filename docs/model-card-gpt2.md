# A1-22 正式模型卡：英文 GPT-2（small）

本文是提交物里的正式模型卡。仓库里另有一张
[TinyDecoder 模型卡](model-card.md)，它只描述接口与数值验证用的内置小模型；
对外结论一律以本卡为准。

## 1. 基本信息

| 项 | 值 |
| --- | --- |
| 模型 | 英文 GPT-2（GPT-2 small，自回归 Transformer 解码器） |
| 权重仓库 | `gpt2` |
| 冻结版本 | `607a30d783dfa663caf39e06633721c8d4cfcd7e` |
| 上游 | `https://github.com/openai/gpt-2` |
| 许可 | Modified MIT License（OpenAI, 2019）；文本见 [../third_party/gpt2/LICENSE](../third_party/gpt2/LICENSE) |
| 冻结方式 | `HF_ENDPOINT=https://hf-mirror.com` + `HF_HUB_DISABLE_XET=1`，逐文件 SHA-256 复核 |
| 用途 | 隐私保护的三方（3PC）自回归解码演示与验收 |

冻结文件与摘要（`model/gpt2.py` 的 `SOURCE_FILES` 即此表，
`require_gpt2_source` 会逐文件复核，任一不符即拒绝加载）：

| 文件 | 字节 | sha256 |
| --- | --- | --- |
| `config.json` | 665 | `0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4` |
| `merges.txt` | 456318 | `1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5` |
| `model.safetensors` | 548105171 | `248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707` |
| `README.md` | 8092 | `0fcd631078093c2aa1d93438b898320b8a1167784e2a1ab37b8016e9de8b3c2e` |
| `tokenizer.json` | 1355256 | `8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6` |
| `vocab.json` | 1042301 | `196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783` |

权重本身不入 Git（`.gitignore` 忽略 `artifacts/`）。冻结版本号加逐文件摘要
保证"下载到的就是同一份权重"可以离线复核。

CycloneDX SBOM 把该模型记为 `machine-learning-model` 组件并附全部六个文件
摘要，见 [../docs/sbom.md](sbom.md) 与 D10 证据包内的 `sbom.json`。

## 2. 几何与精度

来自冻结的 `config.json`：

- `n_layer = 12`，`n_embd = 768`，`n_head = 12`
- `n_ctx = 1024`，`vocab_size = 50257`
- `layer_norm_epsilon = 1e-5`，`activation_function = gelu_new`
- 张量元素共 137,022,720 个；去掉 12 份 `1x1x1024x1024` 常量因果掩码后为
  124,439,808 个参数

定点标定（`model/calibration.py`）：逐张量选最窄可行 dyadic 位宽，本冻结下
**最差误差 1.9e-6，最窄可用位宽 18**（零偏置张量触到下限 8）。完整逐张量
计划见 [evidence/d7-local-model-20261013T1425Z/d7-precision-plan.json](evidence/d7-local-model-20261013T1425Z/d7-precision-plan.json)。

## 3. 运行方式与边界（如实记录）

**已在本地证明**（`docs/evidence/d7-local-model-20261013T1425Z`）：

- 程序自身的浮点参考算术与发布版 GPT-2 在候选列上最大绝对误差 **5.82e-5**
  （发布版以 float32 计算）。
- 提示 `the cipher key is secret`（token `[1169, 38012, 1994, 318, 3200]`）
  下，3 步贪心 token 与发布版完全一致：`,`、` and`、` the`。
- 纯 Python GPT-2 字节级 BPE 与 `GPT2TokenizerFast` 在 16 条固定语料上逐 id
  相同，客户端无需在目标机装 `transformers`。

**已在三节点 enclave 内运行**（运行 `d7-enclave-3host-20261014T1018Z`，见
[d7-acceptance.md](d7-acceptance.md)）：三个 `gramine-sgx` enclave 各自加载自己
那一份正式权重份额，用提示 `the cipher key is secret` 连续生成 3 个 token
` secret secret secret`；逐步安全 Argmax 与客户端重建 logits 的 Argmax 一致，
与 dealer 侧 float64 参考的最差 `max_abs_error` 为 **0.0650**；五类篡改/重放负例
全部被拒；close 之后会话目录被覆写删除、清洁度与 reveal 扫描干净；三份抓包判决
`tls13_only`、空洞 0。**这一次跑的是 1 层 Block 加 1028 个候选 token 的受限解码，
不是整个 GPT-2**——层数与候选宽度都写进 model manifest 并由两端各自校验。

程序内有**两个与发布版不同的输入**，两者都写进 model manifest：

1. **候选词表**：`lm_head` 只对候选 token 取 Argmax，而不是全部 50257。
   规则公开且与提示无关——取 GPT-2 最小的 `K` 个 token id，再并上本次提示
   编码出的 id；候选表升序排列，其摘要进入 manifest，双方分歧会被直接拒绝。
2. **位置表**：只取 `wpe` 的前 `sequence` 行。提示左对齐放在窗口开头，解码
   读第 `len(history)-1` 行；因果掩码保证填充行不可达，与"窗口等于当前上下文
   长度"在数学上等价。

## 4. 已知限制

- 候选词表受限意味着"生成质量"只在候选集内成立。证据给出的可复核判据是
  "发布版 top-1 落在候选集内"，以及 enclave 内逐步 Argmax 与参考一致，
  而不是完整词表下的等价。
- enclave 内实际跑的是 **1 层**、窗口 8、候选 1028：一层就要三方各自 4.5 s～5.0 s
  的墙钟、每台 65 KB 的会话状态和每份 70 MB 的份额包，所以本轮停在 1 层探针，
  证据里只写实际层数，不写"整个 GPT-2"。
- 每方明文份额规模约 693 MB（86,642,180 个 float64），因此正式权重不进镜像、
  不进 Git，只以受测树内的一次性 tar 分发并在跑完覆写删除。
- D4 的真实 attestation 放行仍未实现，回执签名链目前来自本地 PKI。
- 本轮发布的模型 hash（`c0394f50…`）、tokenizer 摘要（`8414cab9…`）、候选表
  摘要（`53767094…`）与精度计划哈希已冻结进 D10 release，并作为
  `ModelManifest` 绑定到 enclave 会话（`3afdeb07…` / `db1950d9…`）；两端各自
  校验，任一不匹配在任何 MPC 入口之前被拒。
- 三节点 enclave 内实际验证的是 **1 层**：更高层数没有实测，不得按已验证陈述。

## 5. 不适用范围

- 不用于任何安全、事实准确性或生产生成能力的对外声明。
- 不用于中文或非 GPT-2 词表覆盖的语言。
- 不把本卡第 3 节的 enclave 结论外推到 1 层以外的几何或完整词表；也不把其中
  仍属本地的部分（程序 float 参考与发布版的一致性、纯 Python BPE 的逐 id 相同）
  当成 enclave 结论。
- 超出本次实测范围的任何说法，都必须以新的现场证据包为准。

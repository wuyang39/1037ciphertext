# D7 正式英文 GPT-2：冻结、本地复现与 enclave 执行方案

本文记录 D7 已经做完的部分：把正式英文 GPT-2 冻结成可验证的字节、把它切成
enclave 程序真正消费的张量、给出逐张量量化标定，并用**程序自己的算术**复现
发布版 GPT-2 的输出。三节点 enclave 内的 D7 解码尚未运行，本文最后一节写清
它要跑什么、按什么几何跑，以及为什么几何要受限。

状态：本地部分完成并封存证据；enclave 解码待执行。

## 1. 冻结来源

| 项 | 值 |
| --- | --- |
| 仓库 | `gpt2`（HuggingFace 镜像的官方改名前权重仓库） |
| 版本 | `607a30d783dfa663caf39e06633721c8d4cfcd7e` |
| 许可 | Modified MIT License（OpenAI, 2019），文本存于 [../third_party/gpt2/LICENSE](../third_party/gpt2/LICENSE) |
| 上游 | `https://github.com/openai/gpt-2` |
| 参数 | 137,022,720 个张量元素；去掉 12 份 1×1×1024×1024 常量因果掩码后为 124,439,808 个参数 |

冻结文件与摘要（`model/gpt2.py` 中 `SOURCE_FILES` 就是这份表，
`require_gpt2_source` 会逐文件复核）：

| 文件 | 字节 | sha256 |
| --- | --- | --- |
| `config.json` | 665 | `0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4` |
| `merges.txt` | 456318 | `1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5` |
| `model.safetensors` | 548105171 | `248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707` |
| `README.md` | 8092 | `0fcd631078093c2aa1d93438b898320b8a1167784e2a1ab37b8016e9de8b3c2e` |
| `tokenizer.json` | 1355256 | `8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6` |
| `vocab.json` | 1042301 | `196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783` |

权重文件不入 Git（`.gitignore` 忽略 `artifacts/`），`model.safetensors` 的
lfs 摘要与上面一致，因此"下载到的是不是同一份权重"可以离线复核。

几何（`config.json`）：`n_layer = 12`、`n_embd = 768`、`n_head = 12`、
`n_ctx = 1024`、`vocab_size = 50257`、`layer_norm_epsilon = 1e-5`、
`activation_function = gelu_new`。

## 2. 代码

| 组件 | 作用 |
| --- | --- |
| `model/safetensors.py` | 无依赖读取 safetensors 容器：8 字节小端头长、JSON 头、连续数据段；张量长度必须与形状一致，载荷不得重叠 |
| `model/gpt2.py` | 冻结表、`Gpt2Config`、候选词表规则、把 c_attn 拆成 q/k/v、按候选行切 embedding、按层切 12 个 block |
| `model/calibration.py` | 逐张量选最窄可行 dyadic 位宽（含 int64 余量约束）并给出实际误差；逐层误差报告 |
| `model/graph.py` | `convert_decoder_graph` 由几何生成静态图，`convert_gpt2_graph` 是正式模型入口；Tiny 图与其共用同一套算子序列 |
| `model/export.py` | `export_gpt2_run`：冻结复核 → 切张量 → 确定性 bundle → 静态图 → 标定精度计划 → 绑定 model/tokenizer/precision 三份摘要的 model manifest；`python -m model.export` 即入口 |
| `mpc/spu_backend/d7_program.py` | GPT-2 的 MHLO 程序：私有 embedding 查表 + 位置相加 + 12 个 pre-LN block + 末层 LayerNorm + 候选 lm_head + secure Argmax |
| `infra/d7_vectors.py` | 运行几何、扁平权重集、逐算子对齐的 float 参考、候选索引与 GPT-2 token id 的映射 |
| `infra/d7_fidelity.py` | 只在操作机上跑的发布版对比（torch/transformers，惰性导入，节点永不加载） |
| `infra/build_model_package.py` | `build_gpt2_model_package`：在标定位宽上量化、拆三份额、可选加密份额、package manifest 与 claim boundary |
| `client/gpt2_bpe.py` | 正式 GPT-2 字节级 BPE 的纯 Python 实现（客户端唯一需要 tokenizer 的地方） |
| `infra/d7_local_evidence.py` | 生成本文第 4 节的证据包 |

## 3. 两个与发布版不同的输入（如实记录）

程序里的算术就是 GPT-2 的算术，但有两个输入被约束，两者都写进 model manifest：

1. **候选词表**：lm_head 只对候选 token 排 Argmax，而不是全部 50257。规则是
   公开且与提示无关的——取 GPT-2 最小的 `K` 个 token id（GPT-2 按 merge 频次
   编号，最小的 id 就是最常出现的字节对），再并上本次提示编码出的 id（提示
   token 若不在集合里就无法 embedding）。候选表升序排列，其摘要进入 manifest，
   双方若对候选表有分歧会被直接拒绝而不是各算各的。
2. **位置表**：只取 `wpe` 的前 `sequence` 行，也就是长度为 `sequence` 的因果
   上下文本来就用到的那些行。

提示左对齐放在窗口开头，解码时读第 `len(history) - 1` 行。因果掩码保证这一行
看不到它后面的填充行，所以填充行无法影响结果——这与"把 `sequence` 当作当前
上下文长度"在数学上等价，但让一个固定形状的程序可以服务一整段会话的每一步。

## 4. 本地证据（已封存）

运行 `python -m infra.d7_local_evidence`（12 层、窗口 8、候选 1028、提示
`the cipher key is secret`），证据目录
[docs/evidence/d7-local-model-20261013T1425Z](evidence/d7-local-model-20261013T1425Z)：

| 项 | 结果 |
| --- | --- |
| 冻结复核 | 6 个文件全部 `verified: true` |
| 提示 token | `[1169, 38012, 1994, 318, 3200]` = `the` ` cipher` ` key` ` is` ` secret` |
| 候选宽度 | 1028（1024 个最小 id + 4 个提示 id） |
| 程序参考 vs 发布版 logits（候选列） | 最大绝对误差 5.8e-5（发布版在 float32 下计算） |
| 发布版 top-1 是否落在候选集内 | 3 步全部 `true` |
| 3 步贪心：程序 token vs 发布版 token | `,` ` and` ` the` 三步全部一致 |
| 逐张量标定 | 最差 1.9e-6，最窄位宽 18（0 偏置张量取到下限 8） |
| 每个参与方的份额规模 | 693 MB（86,642,180 个 float64） |

这一节要证明的事：**在进入 enclave 之前，程序的算术已经等价于发布版 GPT-2**。
enclave 运行之后只剩定长协议误差这一项差异（D6 实测为 4e-4~8e-4）。

同样的 16 条语料上，`client/gpt2_bpe.py` 与 `transformers` 的
`GPT2TokenizerFast` 逐 id 相同（见 `tests/unit/test_d7_gpt2_tools.py`），
所以客户端不需要在目标机上装 transformers。

## 5. 为什么 enclave 内不能按 50257 全词表跑

D6 在同一套 SPU/YACL 栈上实测：`hidden = 16`、`vocab = 152`、窗口 8 的
一步是 2.1 s，一步约 5.7e4 次乘加。正式模型按窗口 8、12 层算是
约 6.9e8 次乘加，比 D6 大四个数量级；同时每方份额 693 MB，
`vocab = 50257` 的 lm_head 与 embedding 各自再加 309 MB。

因此 D7 的 enclave 运行必须在这两点上受限，本文把它写成 claim boundary 而不是
当成没发生：受限的是**候选词表**（第 3 节）和**待实测的层数/窗口**，
不是算术、不是权重来源、不是 tokenizer。

## 6. enclave 运行方案（待执行）

1. `--layers` 从 1 起步做一次探针运行，量出每层墙钟时间，再决定 12 层是否
   在预算内；无论最终跑几层，证据里写实际层数，不写"整个 GPT-2"。
2. 每个解码步用一个 `decode_row` 固化的程序（`build_gpt2_program(..., decode_row=k)`），
   程序按需编译、按 `step-<row>` 命名；窗口固定为 `sequence`。
3. 份额由 dealer 离线拆分，明文份额只存在于受测树内并通过 tar 分发，跑完覆写
   删除；不进镜像、不进 Git。
4. 会话绑定 share epoch 与 KAS JobTicket；模型哈希、tokenizer 摘要、候选词表
   摘要、精度计划哈希全部进入 `ModelManifest`，任一不匹配在任何 MPC 入口之前被拒。
5. 负例至少包含：旧 share、旧 epoch、旧 Ticket、模型替换、tokenizer/候选表替换。
6. 客户端把 enclave 返回的 token 与第 4 节的 float 参考对齐，报出逐步
   `max_abs_error` 与 token 一致性。

## 7. 尚未覆盖

1. 三节点 enclave 内的正式模型解码尚未运行，本节之前的所有结果都不构成
   enclave 验收。
2. 候选词表受限意味着"生成质量"只在候选集内成立；证据里给出的是
   "发布版 top-1 落在候选集内"这一可复核判据。
3. D4 的真实 attestation 放行仍未实现，回执签名链仍来自本次运行的本地 PKI。
4. 性能、EPC/CPU/RAM 与网络档位对照属于 D8。

## 8. 复现

```powershell
# 取权重（需要镜像端点；xet 端点在国内直连会 404）
$env:HF_ENDPOINT="https://hf-mirror.com"; $env:HF_HUB_DISABLE_XET="1"
huggingface-cli download gpt2 --revision 607a30d783dfa663caf39e06633721c8d4cfcd7e `
  --local-dir artifacts/gpt2-frozen

python -m model.export --source artifacts/gpt2-frozen --out artifacts/d7-export `
  --layers 12 --sequence 8 --candidates 1024 --prompt "the cipher key is secret" `
  --license third_party/gpt2/LICENSE
python -m infra.build_model_package --source artifacts/gpt2-frozen `
  --output artifacts/d7-package --layers 12 --sequence 8 --candidates 1024 `
  --prompt "the cipher key is secret" --license third_party/gpt2/LICENSE --encrypt-local
python -m infra.build_model_package --output artifacts/d7-package --verify
python -m infra.d7_local_evidence --source artifacts/gpt2-frozen `
  --out docs/evidence/d7-local-model-<stamp> --license third_party/gpt2/LICENSE
```

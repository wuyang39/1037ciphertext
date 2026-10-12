# A1-22 模型卡

## 当前模型

仓库内置模型是用于接口、数值和缓存验证的 `TinyDecoder`，默认参数：

- `vocab_size=256`
- `hidden_size=32`
- `num_layers=2`
- `num_heads=4`
- `intermediate_size=64`
- `max_seq_len=32`
- `layernorm_eps=1e-5`

`tests/fixtures/tiny_float_reference.json` 固定了初始化种子、参数 hash、输入序列和浮点 logits，用于检查导出、固定点 adapter、RSS 算子及增量 KV cache 的数值一致性。

## 使用范围

- 本地协议闭环、固定点误差排查、trace schema 验证。
- D5 的单个 Decoder Block 对齐。
- D6 的两 token 会话态和结果帧测试。
- D7 的导出、量化、静态图转换和模型份额拆分接口。

不用于质量、事实准确性、生产安全或真实生成能力的对外结论。

## 最终模型迁移要求

正式模型已定为英文 GPT-2（`gpt2` / GPT-2 small，约 124M 参数，OpenAI
Modified MIT）。D7 必须另行冻结：

- 权重下载来源、许可证文本和 GPT-2 BPE tokenizer 版本（`vocab_size=50257`）
- 导出后的 `model_hash` 和每个张量 hash
- `precision_plan`、层级 dyadic scale 和签名
- `share_epoch`、目标角色和三份模型份额
- 8/16 token 桶、`max_new_tokens<=4`、`context_window=16`
- 浮点、固定点、RSS 三种路径的 token 一致率、P99 logit 误差、激活范围和溢出计数

模型替换、旧 share、旧 Ticket、旧材料均不得跨 epoch 混用。

# D5 私有 Tiny Decoder Transformer Block 验收记录

本文记录 D5 的实测结果：完整 Tiny Decoder Block 在三个 SGX enclave 内运行，
Softmax、LayerNorm、GELU、Argmax 和整个 Block 的误差都在登记阈值内，没有未解释
溢出，生产的节点路径也不存在明文 reveal。

## 1. 验收基线

| 角色 | 实例 ID | 私网 | 公网 |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

- 运行 ID `d5-enclave-3host-20261013T1057Z`，提交
  `4f17822bbf8ef9a57a0e56ae5d56a1f364f3a3ae`。
- 运行时：SecretFlow-SPU 0.9.5（`SEMI2K`，`FM64`，`fxp_fraction_bits = 18`），
  Gramine 1.9 + `gramine-sgx`，`sgx.remote_attestation = "dcap"`，
  `sgx.enclave_size = 4G`、`max_threads = 64`、栈 2M。
- Block 几何：`sequence = 8`、`hidden_size = 8`、`num_heads = 2`、
  `intermediate_size = 16`、`vocab_size = 32`，用例种子 `20261013`。
- 三个节点各自在自己实例的 enclave 里执行；SPU/YACL/BRPC 的 TLS 1.3 流量走 VPC
  私网，每台实例用本机 `tcpdump` 抓自己那一段。

## 2. 使用的工具

| 组件 | 作用 |
| --- | --- |
| `mpc/spu_backend/d5_program.py` | Softmax、LayerNorm、GELU、Argmax 与整个 Block 的 MHLO 程序；causal mask 用公开的 0/1 常量乘进指数，不把大负指数喂给 enclave 内的 `exponential` |
| `mpc/spu_backend/program_runtime.py` | 承载程序集、按名字执行并从共享输入里取参数 |
| `tee/enclave/d5_node.py` | 三个角色共用的 D5 节点：建链、逐用例执行、写误差表、状态与脱敏 trace |
| `tee/enclave/node_common.py` | D4/D5 共用的失败类型、文档编解码、share 通道与日志 |
| `infra/d5_vectors.py` | 确定性用例集（种子 `20261013`）、浮点参考与容差表 |
| `infra/d5_workspace.py` | 复用 D4 PKI 生成三份角色配置 |
| `infra/d5_three_hosts.py` | 一条命令的三实例驱动、证据收集与封存 |
| `infra/reveal_scan.py` | 生产路径 reveal 扫描，逐文件白名单 |

## 3. 运行

```bash
# 操作机上（三实例，每个节点放进 gramine-sgx，跑完自动收集、封存、校验）
python -m infra.d5_three_hosts \
  --cluster <cluster.json> \
  --run-id d5-enclave-3host-<stamp> \
  --out-dir docs/evidence/<run-id> \
  --mode enclave --seal \
  --ssh-user jiahao --ssh-key <key> --ssh-key-password <pass> \
  --expect-commit 4f17822bbf8ef9a57a0e56ae5d56a1f364f3a3ae

# 单机三进程的本地回路（同一套程序与用例，不跨主机）
python -m infra.d5_acceptance --root /tmp/d5loop --run-id <stamp> \
  --repo . --python <venv>/bin/python
```

驱动在 P0 生成工作区，经 tar 分发到 P1/P2；三台各自渲染并签名自己将要加载的
manifest，再依次启动抓包与节点。P0 收齐 38 个用例后写状态文件，驱动回读误差表、
逐用例结果、通信 trace 和三份节点日志，然后在操作机上跑 reveal 扫描、写 README、
封存索引并校验。

## 4. 结果

### 4.1 每算子误差

38 个用例全部通过（`verdicts: passed`，网格摘要
`0dca84b60da01202269696d1de25bdfa1617155c28e3df881b93a61d6c8eea8d`）。

| 程序 | 用例 | 通过 | `max_abs_error` | 容差 | `overflow_count` |
| --- | --- | --- | --- | --- | --- |
| `softmax` | 8 | 8 | 2.56e-3 | 5e-3 | 0 |
| `layernorm` | 7 | 7 | 1.09e-3 | 5e-3 | 0 |
| `gelu` | 6 | 6 | 5.36e-2（见 4.3） | 1e-2 + 尾部预算 | 0 |
| `argmax` | 8 | 8 | 0（索引全等） | 精确 | 0 |
| `block` | 9 | 9 | 7.04e-4 | 2e-2 | 0 |

逐用例记录（`d5-case-results.json`）里每一项都带 `max_abs_error`、
`mean_abs_error`、`relative_error`、`max_scaled_error`、`overflow_count`、
`shape_mismatch`、`tolerance` 和判决；`argmax` 与 `block` 另有 `argmax_match`，
Block 还分别给出 `hidden`、`logits` 和 `token` 三段。9 个 Block 用例的
`token.actual` 与 `token.expected` 全部相等，最坏 `max_scaled_error` 为 0.27
（判决上限 1.0）。

### 4.2 enclave 内通信 profile

| 项目 | 值 |
| --- | --- |
| 建链耗时 | 5.313 s |
| 全网格 share 字节 | 272494 |
| 逐用例耗时 | 122 ms（最小）/ 487 ms（中位）/ 1972 ms（最大） |
| 对端 RTT | 121 ms ~ 1970 ms |
| 握手版本 | 全部 `TLSv1.3` |

`d5-communication-trace.json` 逐用例给出 `elapsed_ms`、`share_bytes` 和两个对端的
RTT，只记录字节数、角色、指纹与时序，不含 share、密钥或明文输入。

### 4.3 GELU 尾部误差的解释

`gelu` 的 `max_abs_error` 是 5.36e-2，出现在 `tanh` 形式的饱和尾部：enclave 内的
`tanh` 在 |x| 很大时停在 ±(1 − 2.7e-3)，输出因此是 `|x| · d`，绝对值误差随
`|x|` 线性增长。这一项没有被藏起来，也没有放进容差里凑合：

- `tail_error_per_input` 把两侧尾巴上的误差除以该输入的 `|x|`，本次为 2.4e-3；
- `approximation_error` 是近似 GELU 与精确 GELU 之间的误差，本次为 4.7e-4；
- 判决用的是锚在输入上的双边预算 `max_scaled_error ≤ 1`，而不是松掉的绝对值上限。

换句话说，尾部"大误差"来自算子本身的饱和行为，被测的是每单位输入的误差，而不是
让它躲在一个宽绝对值阈值后面。

### 4.4 enclave 证据

| 角色 | MRENCLAVE | `d5_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `83d40e4435dba334f9075b9cc0baa65e504062c1bf266e86140489853ff050eb` | `b5a3d0d2f0990cff0942ca9485b272cfdf932d7c1b80f4950d5485835a258085` |
| P1 | `c784b44dacf4977af3cf0e00f89275b0496c3a95f1baab08457922126e0e260a` | `9f965688c696aae3aff7826d742c860d3922353958465c7d585183f5fe93d3b9` |
| P2 | `3b7014bbe088501d90a0e159faf243a24f3dc57538c33f2aabf3f51984bf34d0` | `38c28aee25da210dbd035d0a35106c48aed9e679ab469054331d9a4fee66745e` |

- `inside_enclave: true`、`attestation_available: true`（`/dev/attestation/quote`
  在 enclave 内存在）。
- `distinct_measurements: 3`：三台各自签名自己真正加载的树，所以三份测量值不同。
  这一点如实记录，没有把三次运行写成一个 enclave。要让三台收敛成同一个
  MRENCLAVE，用的是 [d4-acceptance.md](d4-acceptance.md) 4.10 节的 staged 树流程
  （运行 `d4-enclave-shared-3host-20261013T1715Z`）；D5 默认驱动不替人做 staging。
- 三份节点日志都以 `Gramine is starting.` 开头，说明节点确实运行在
  `gramine-sgx` 里，而不是宿主进程。

### 4.5 证书互校

`peer_certificates_match: true`，`certificate_mismatches: []`。每个节点都在状态
文件里写下自己出示的证书摘要和其它角色接受的摘要，三者两两对应：

| 角色 | `identity_sha256` |
| --- | --- |
| P0 | `2c2d1783830b5ba7af11ee65609954b2b9a3e55381669ad7e6ed3103c80cdfd3` |
| P1 | `1dc411c56af0085d0e7b771ef3564ec40ac74648f21ca9529545cc50a254e2e4` |
| P2 | `379e71786aaaeb784ccd6addba30f37bbe16a8ce4d29dbd223c501e5ec4333af` |

三个角色的 `teardown_finished` 都是 `true`。

### 4.6 抓包

三份抓包各自只由产生它的实例分析，判决都是 `tls13_only`，不能归属到 TLS 的
载荷字节为 0：

| 角色 | 期望端口报文 | TLS 1.3 流 | TLS 1.2 及以下 | 应用数据记录 | 非 TLS 字节 | 判决 |
| --- | --- | --- | --- | --- | --- | --- |
| P0 | 152673 | 86 | 0 | 260402 | 0 | `tls13_only` |
| P1 | 153816 | 45 | 0 | 259856 | 0 | `tls13_only` |
| P2 | 153905 | 45 | 0 | 259814 | 0 | `tls13_only` |

原始 pcap 各约 51 MB，留在产生它的实例上；`<bundle>.exclusions.json` 记下三份的
字节数与 sha256，放进目录就会让校验更严而不是绕过。

### 4.7 生产路径 reveal 扫描

`d5-reveal-scan.json` 在三台的树各扫一遍 `mpc/`、`tee/`、`kas/`、`client/`、
`crypto/`、`contracts/`、`deploy/`、`infra/` 下的 Python 源，三个角色都是
`findings: 0`、`verdict: clean`；命中的 34 处全部落在白名单里（本地固定点参考、
显式 opt-in 的仿真 provider、扫描器自己的模式表，以及断言 `reveal_allowed=False`
必须拒绝的负例测试）。任一实例扫出未解释命中，驱动会直接失败，而不会把它封存成
脚注。

## 5. 证据位置

[docs/evidence/d5-enclave-3host-20261013T1057Z](evidence/d5-enclave-3host-20261013T1057Z)
共 22 个索引文件：

| 文件 | 内容 |
| --- | --- |
| `d5-summary.json` | 角色、几何、每程序误差、enclosure 块、证书互校与抓包摘要 |
| `d5-operator-errors.json` | 从 P0 回读的每程序/整体误差表 |
| `d5-case-results.json` | 38 个用例逐条记录 |
| `d5-communication-trace.json` | 逐用例时序、share 字节、链路设置与 enclave 事实 |
| `d5-reveal-scan.json` | 三棵树的 reveal 扫描结果 |
| `d5-enclave-p{0,1,2}-sign.txt`、`d5-enclave.manifest` | 三台的签名输出与被签 manifest |
| `d5-three-<role>-tls-summary.txt` | 各自抓包的分析结论 |
| `d5-three-p{0,1,2}-node.log`、`d5-three-p{0,1,2}-node-status.json` | 节点日志与状态 |
| `README.md` | 由封存摘要生成的运行说明 |
| `evidence-index.json`、`evidence.sha256` | 目录索引与封存 |

复验：`python a122_verify_all.py` 报 `bundles=13 failed=0`，
`python a122_index_check.py` 报 `mismatches: 0`。

## 6. 尚未覆盖

以下内容未被本次运行证明，不得按已通过计：

1. 真实 attestation 放行：enclave 内确实产生了 DCAP Quote
   （`attestation_available: true`），但三个角色的证书仍来自本次运行的本地 PKI，
   不是 Quote → 验证 → 签发短期身份/Lease 的 KAS 产物。这一条与 D4 第 7 节第 1 项
   是同一条缺口。
2. 不是正式模型：权重是按 Kaiming-uniform 生成的合成权重，词表只有 32，目的是把
   算子、掩码和 Argmax 打通，不构成语言模型质量结论。正式英文 GPT-2 属于 D7。
3. 不是端到端自回归：本次是单步 Block（含 LM head 与 secure Argmax），没有多
   token 连续生成、KV cache 与会话清理，那属于 D6。
4. 没有性能结论：只有 enclave 内的耗时与字节数记录，没有 EPC/CPU/RAM、网络档位
   对照和开/关消融，那属于 D8。
5. 三份测量值不同：默认驱动让每台签名自己的树，因此是三个 enclave、三份测量值；
   单一 MRENCLAVE 需要 D4 4.10 的 staged 流程。

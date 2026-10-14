# D8 开/关消融验收记录

本文记录运行 `d8-ablations-20261014T1148Z`。D8 的第一阶段
（[d8-acceptance.md](d8-acceptance.md)）把同一份冻结程序放在三档声明网络条件下
各跑一遍，但验收门里"每项优化都有同条件对照"这一条**没有达成**，那份记录的
第 5 节第 1 条把它如实留成缺口。本次运行补的就是这一条：程序、权重份额、
几何、提示词与网络条件全部不动，只动一个运行时开关。

## 1. 缺口是什么，以及为什么不需要第二个冻结程序

缺口的原文是"没有开/关消融……冻结程序没有运行时开关"。这句话在**程序文本**
这一层是对的：`mpc/spu_backend/d7_program.py` 生成的 MHLO 里，
`mhlo.exponential`、`mhlo.tanh`、`mhlo.rsqrt` 都是写死的算子，没有开关。

但非线性算子到底"多准"，并不由程序文本决定，而是由 SPU 运行时决定。
`libspu.RuntimeConfig` 暴露了这些开关（本机 `a122-venv311` 的
`spu/libspu.pyi` 与运行时实测，SEMI2K / FM64 / fxp 18 下的默认值）：

| 运行时字段 | 默认值 | 它决定什么 |
| --- | --- | --- |
| `fxp_exp_iters` | 8 | softmax 的指数函数迭代次数 |
| `fxp_exp_mode` | `EXP_DEFAULT` | 指数函数的算法族（Pade / Taylor / Prime） |
| `fxp_div_goldschmidt_iters` | 2 | softmax 归一化那个除法的 Goldschmidt 迭代次数 |
| `enable_lower_accuracy_rsqrt` | `false` | LayerNorm 里 `mhlo.rsqrt` 是否走低精度路径 |
| `fxp_log_iters` / `fxp_log_orders` | 3 / 8 | 对数函数 |
| `sigmoid_mode` | `SIGMOID_DEFAULT` | sigmoid 近似档位 |
| `fxp_fraction_bits` | 18 | 定点小数位宽，也就是这一路上的量化精度 |

这些都是**出厂就有的运行时开关**，所以消融不需要第二个冻结程序，也不需要
第二组权重：同一个程序、同一组份额，换一个 `RuntimeConfig` 就是另一臂。

本次仍然没有做的，是"把发出去的 MHLO 算子换成另一套多项式"——那确实需要第二
个程序文本、第二份测量值，见第 8 节。

## 2. 四个实验臂

| 臂 | 动的是什么 | 写进配置的写法 |
| --- | --- | --- |
| `baseline` | 什么都不动（对照组） | 位宽取自导出的标定，运行时选项为空 |
| `baseline-repeat` | 与 `baseline` 完全相同，再跑一遍 | 同上 |
| `approx-low` | 只调低非线性近似：指数 8→2 次迭代、除法 2→1 次、rsqrt 走低精度 | `{fxp_exp_iters: 2, fxp_div_goldschmidt_iters: 1, enable_lower_accuracy_rsqrt: true}` |
| `fxp-12` | 只压窄定点位宽：18 → 12 | `--fractional-bits 12` |

`baseline-repeat` 的作用是给出一份噪声底：它和 `baseline` 的差别只可能是
运行本身的浮动，任何比这个浮动还小的"差异"都不能当作开关的效果。

## 3. 固定条件

- **提交**：三台实例都在 `b1f87bae5b9822d704e1b17ca924c7fbebc45bec`，
  驱动用 `--expect-commit` 逐台核对过。
- **程序与几何**：D7 冻结的 1 层 GPT-2 探针，窗口 8、候选词表 1028 个 id、
  提示词 `the cipher key is secret`、每臂 3 个 token。
- **权重**：同一份 `~/a122-d7/export`，四臂都由同一个 dealer 路径切分；
  每个臂重新安置一次（transport 证书、SM2 标识重新生成），所以每台的测量值
  与其它臂都不同——这与 D7 记录的是同一件事，不是缺陷。
- **网络**：四臂都不注入任何 `tc` 规则（LAN），互相之间没有网络差异。
- **每臂都是一整轮**：安置 → 三台 `gramine-sgx` 内启动 → 客户端连跑 3 步 →
  五类篡改/重放负例 → close → 会话目录扫描 → 份额覆写删除 → 抓包自析。
- **硬件**：三台均为 Intel Xeon Platinum 8369B、4 vCPU、7.7 GB 内存、
  EPC 段 `0x240000000-0x42fffffff`、`/dev/sgx_enclave`、Gramine 1.9、
  内核 5.15.0-191-generic。

## 4. 结果

整段（客户端进程起止）与保真度：

| 臂 | 定点位宽 | 客户端整段 (s) | 相对对照 | 最差 `max_abs_error` | 相对对照 | 生成 token | 与浮点参考一致 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `baseline` | 18 | 16.247 | 1.000 | 0.065481 | 1.000 | 3200, 3200, 3200 | 是（token 与 Argmax 都一致） |
| `baseline-repeat` | 18 | 16.185 | 0.996 | 0.066080 | 1.009 | 3200, 3200, 3200 | 是 |
| `approx-low` | 18 | 16.395 | 1.009 | 7.272384 | **111.06** | 3200, 3200, 3200 | 是 |
| `fxp-12` | 12 | 16.680 | 1.027 | 0.906605 | **13.85** | 3200, 3200, 3200 | 是 |

逐 step 的客户端墙钟（毫秒）与最差误差：

| 臂 | 第 1 步 | 第 2 步 | 第 3 步 | 逐步 `max_abs_error` |
| --- | --- | --- | --- | --- |
| `baseline` | 5236.413 | 5187.998 | 5179.502 | 0.065481 / 0.060913 / 0.065245 |
| `baseline-repeat` | 5409.951 | 4944.214 | 4966.994 | 0.064299 / 0.063682 / 0.066080 |
| `approx-low` | 5770.876 | 4997.168 | 4975.660 | 7.164022 / 7.187500 / 7.272384 |
| `fxp-12` | 5910.269 | 5045.615 | 5079.953 | 0.906605 / 0.764661 / 0.840165 |

三臂的第一步都略慢（链路与密钥协商的冷启动），第 2、3 步进入稳态。

宿主与 enclave 资源（每台 0.5 s 采一次，取全程）：

| 臂 | 角色 | 宿主 CPU 均值 % | 宿主 CPU 峰值 % | enclave RSS 峰值 MB | enclave CPU 秒 | 可用内存最低 MB |
| --- | --- | --- | --- | --- | --- | --- |
| `baseline` | P0 / P1 / P2 | 31.04 / 29.22 / 32.47 | 65.53 / 59.90 / 64.11 | 16.4 / 16.7 / 16.5 | 48.24 / 49.19 / 49.27 | 6269 / 6467 / 6510 |
| `baseline-repeat` | P0 / P1 / P2 | 30.19 / 31.65 / 29.58 | 73.24 / 62.27 / 54.63 | 16.4 / 16.6 / 16.4 | 47.55 / 51.90 / 47.97 | 6251 / 6466 / 6496 |
| `approx-low` | P0 / P1 / P2 | 32.22 / 31.83 / 30.14 | 72.07 / 69.38 / 53.40 | 16.3 / 16.7 / 16.3 | 50.30 / 52.12 / 46.93 | 6299 / 6464 / 6489 |
| `fxp-12` | P0 / P1 / P2 | 31.65 / 31.29 / 32.02 | 70.48 / 67.82 / 61.06 | 16.5 / 16.7 / 16.5 | 49.79 / 52.62 / 47.99 | 6267 / 6493 / 6536 |

线上流量与抓包判决（每台自己分析自己那份 pcap）：

| 臂 | 每台线上流量 MB | 每台 TCP 重传 | 空洞 | 判决 |
| --- | --- | --- | --- | --- |
| `baseline` | 1254.1 / 1253.0 / 1252.9 | 217 / 226 / 245 | 0 / 0 / 0 | `tls13_only` |
| `baseline-repeat` | 1254.2 / 1253.1 / 1252.9 | 185 / 239 / 224 | 0 / 0 / 0 | `tls13_only` |
| `approx-low` | 1252.7 / 1251.7 / 1251.5 | 225 / 234 / 211 | 0 / 0 / 0 | `tls13_only` |
| `fxp-12` | 1254.1 / 1253.0 / 1252.8 | 254 / 281 / 273 | 0 / 0 / 0 | `tls13_only` |

四臂的收尾判决一致，没有一条因为换了开关而放松：

| 检查 | `baseline` | `baseline-repeat` | `approx-low` | `fxp-12` |
| --- | --- | --- | --- | --- |
| 五类负例全部拒绝 | 是 | 是 | 是 | 是 |
| close 后清洁度扫描 | clean | clean | clean | clean |
| 安置份额覆写删除 | clean | clean | clean | clean |
| 三节点正常释放 | 是 | 是 | 是 | 是 |
| close 后三台会话目录 | 0 文件 / 0 字节（目录不存在） | 同左 | 同左 | 同左 |

## 5. 每一臂确实生效

消融最容易出的错，是"以为改了、其实没接到进程里"。三处独立记录互相校对：

1. **安置文档**（驱动写、随包提交的 `d7-stage.json`）里 `runtime` 段：
   `fxp-12` 是 `{"export_fractional_bits": 18, "fractional_bits": 12, "options": {}}`
   ——导出的标定宽度留在 18，只有这一轮的会话位宽被钉到 12；
   `approx-low` 是 `{"fractional_bits": 18, "options": {"enable_lower_accuracy_rsqrt": true, "fxp_div_goldschmidt_iters": 1, "fxp_exp_iters": 2}}`。
2. **每个节点自己的 ready 行**回显它真正打开时的运行时。例如
   `approx-low` 的 P0：

   ```json
   {"role": "P0", "runtime": {"fraction_bits": 18, "options":
     {"enable_lower_accuracy_rsqrt": true, "fxp_div_goldschmidt_iters": 1,
      "fxp_exp_iters": 2}}}
   ```
3. **客户端自己的结果文档**（`d7-client-result.json` 的 `runtime` 段）记录它
   用来切分与重建份额的那份配置。

驱动的 `arm_checks()` 把三者与"这一臂要求的值"逐项比对，任何一项对不上就把
该臂标成 `arm_landed: false` 并在报告里列出问题，而不是照常进表。本次四臂的
`arm_landed` 全为 `true`，且 `arm_problems` 全空。

## 6. 怎么读这张表

- **噪声底**：`baseline` 与 `baseline-repeat` 是同一配置的两次运行，整段差
  **0.4%**（16.247 s 对 16.185 s），最差误差差 **0.9%**（0.065481 对 0.066080）。
  也就是说 ±1% 的墙钟差异、±1% 的误差差异不构成结论。
- **非线性近似的准确度买到了什么**：`approx-low` 把指数迭代从 8 降到 2、除法
  从 2 降到 1、rsqrt 换低精度，墙钟变化 **+0.9%（落在噪声内）**，而最差误差从
  0.065 涨到 7.27，**放大 111 倍**。也就是说在本工作负载与本几何下，这些开关
  的准确度几乎不花时间，但一旦调低就丢掉两个数量级的保真度。
- **定点位宽的代价**：从 18 压到 12，墙钟 +2.7%（刚出噪声带），最差误差放大
  **13.85 倍**（0.0655 → 0.9066）。位宽在这里同样是"精度换不到速度"的旋钮。
- **贪心 token 没有变**：四臂都生成 `3200, 3200, 3200`（` secret secret
  secret`），与客户端自己重建 logits 的 Argmax 以及 float64 参考一致。这说明
  这一层的 logits 误差（≤7.27）还没有跨过候选列之间的间隔；它**不能**被读成
  "近似随便调都不会影响输出"——换提示词、换几何或换更长的自回归就未必。
- **流量与内存不受影响**：四臂都是每台约 1.25 GB、enclave RSS 峰值 16.3~16.7 MB、
  enclave CPU 秒 46.9~52.6。重传数 185~281 在等流量下波动，属链路噪声。

一句话：本工作负载上，出厂的高精度近似配置**不是**性能瓶颈，把近似调低既换不来
时间、又要付出保真度；把定点位宽压窄同样换不来时间。这是同条件对照才能得出的
结论，也解释了为什么发布配置保持在这些默认值上。

## 7. 证据与复算

证据包：`docs/evidence/d8-ablations-20261014T1148Z`（107 个文件、约 15 MB），
`evidence-index.json` + 分离的 `evidence.sha256` 封存，`sha256` 为
`6879293aa05c95f8642a8be6de97f5dfe9209ecaf438470da0d99c11a9109e08`。
本地复验：

```bash
python -m infra.seal_evidence verify docs/evidence/d8-ablations-20261014T1148Z
python -m pytest tests/unit -q
```

包内每臂包含：`d7-summary.json`、`d7-client-result.json`、`d7-client.log`、
`d7-three-p{0,1,2}-node-status.json`、`d7-three-p{0,1,2}-node.log`（ready 行里
就有该臂的运行时回显）、`d7-three-P{0,1,2}-tls-summary.txt`、`d7-hygiene-p{0,1,2}.json`、
`d7-stage.json`、三份 `d7-enclave-p{0,1,2}-sign.txt`、`d7-enclave.manifest`、
`d8-platform-p{0,1,2}.json`、`d8-resources-p{0,1,2}.jsonl`。十二份原始 pcap
（每臂每台一份，各约 1.26 GB）不在包里，它们的字节数与 sha256 记在各臂
`d7-summary.json` 的 `captures` 里。

摘要、报告与 README 都不是手写的：它们是同一遍从四个臂目录读回来的产物，可以
原地重算而不需要再上服务器——

```bash
python -m infra.d8_ablation \
  --out-dir docs/evidence/d8-ablations-20261014T1148Z \
  --run-id d8-ablations-20261014T1148Z \
  --expect-commit b1f87bae5b9822d704e1b17ca924c7fbebc45bec --rebuild --seal
```

`--rebuild` 的时间戳取自 trace 本身（本包是最后一臂的完成时刻
`2026-10-14T11:56:48Z`），所以连跑两次得到逐字节相同的三个文件，重算后封存
`sha256` 不变。本包按上面的命令重算过，三个文件的 `sha256`：

| 文件 | sha256 |
| --- | --- |
| `d8-ablations-20261014T1148Z-summary.json` | `2c5cfa1438c2ff0fe22b4b887547c3470b41206627ae2b651ed2c0e106e0d288` |
| `d8-ablation-report.md` | `63bfeb917203415144ccb3f4293962a5610038afe845cbf34de6f44b66f2ee7f` |
| `README.md` | `2abff204ee283bc1109da697808444d3f72dd4828f42283a06556c04d9f10b93` |

重建时若某臂 trace 记的提交与 `--expect-commit` 不一致，`--rebuild` 会直接报错，
而不是盖上被要求的那个提交号。

重跑同一条命令（操作步骤）：

```bash
python -m infra.d8_ablation \
  --cluster ~/a122_cluster_enclave2.json \
  --out-dir artifacts/server/d8-ablations-<stamp> \
  --run-id d8-ablations-<stamp> \
  --expect-commit <sha> --sudo-password <pw> --seal
```

`--arms '<json>'` 可以只跑指定的一臂，`--skip-existing` 会复用已完成的臂，所以
中途失败时不必从头再来。

## 8. 尚未覆盖

以下内容仍然**没有**被本次运行证明，不得按已通过计：

1. **换掉 MHLO 算子本身的近似**。本次动的是运行时开关；把
   `mhlo.exponential` / `mhlo.tanh` / `mhlo.rsqrt` 换成另一套多项式（例如用
   `mpc/secure_ops/approximations.py` 里登记的 `softmax_piecewise_v1`、
   `gelu_piecewise_v1`、`rsqrt_goldschmidt_v1`）会是第二个程序文本、第二组
   测量值，本次没有做。那三个登记规格因此仍只有本地测试支持，不是 enclave 结论。
2. **每臂只跑了一次**（对照组重复一次）。单臂的取值波动只由 `baseline` 对
   `baseline-repeat` 给出，没有做多次重复去分离抖动来源。
3. **没有每进程 EPC 常驻量**。本内核不提供该计数，负结果与探测脚本见
   `docs/evidence/d8-epc-probe-20261014T1205Z`（封存 `sha256`
   `7216a19a1f9bced81b0a61cf8064e9a7c079bd3e7dfc184b7e614eaac1a62856`）。
4. **长度桶与 batch 仍未覆盖**。本次几何固定窗口 8、单条请求，长度分桶、
   批处理与更长提示词都没有跑。
5. **臂是独立会话，不是同一会话中途改配置**。每个臂重新安置、重新生成
   transport 与 SM2 材料，所以三台的测量值每臂都不同；可比性来自同一份程序
   文本（臂只作为 staging/runtime 选项随行，落在 plan、运行时块与记录里，见
   `tests/unit/test_d7_stage.py::test_an_ablation_arm_reaches_the_staged_configs_and_the_record`
   与 `tests/unit/test_d8_ablation.py::test_an_arm_moves_named_switches_and_resolves_symbolic_enum_names`）、
   同一几何、同一提示词与同一网络条件。
6. **档位不是链路仿真**：本次四臂都在 LAN 下跑，没有注入延迟；延迟档位的结果
   见 [d8-acceptance.md](d8-acceptance.md)。

## 9. 运行后清理

- 运行自带的 scrub：三台各自的安置份额先被 `dd` 覆写再删除
  （本次每台覆写 92,542,258 字节后删除），`/tmp/{role}.tgz` 与 dealer 的
  `~/a122-d7/dist` 一并删除，四臂的 `staging_scrub` 判决都是 `clean`。
- 收尾清理：删除十二份 pcap（每台约 5.0 GB，共约 19.6 GB）、四臂四个
  `/dev/shm/a122-d7/<run>-<arm>` 会话根、`/tmp` 下的 `-hygiene.json` /
  `-probes.json`、以及 `~/a122-d7/three`、`~/a122-d7/dist`、`~/a122-d7/client`
  这三个每次安置都会重建的目录。保留 `~/a122-d7/export` 与
  `~/a122-d7/tokenizer`（dealer 的冻结输入）。
- 清理后三台 `tc qdisc show dev eth0` 只剩 `mq` 根（本次没有注入过规则）、
  `/dev/shm/a122-d7` 为空、无 `d7_node` / `gramine` / `tcpdump` 残留进程、
  负载 0.02~0.05、根盘回到 8%。实例本身的停机与释放属 D10 流程。

# D7 正式英文 GPT-2 三节点 enclave 验收记录

本文记录 D7 的实测结果：正式英文 GPT-2 的权重份额经 dealer 离线切分后，由三条
mTLS 会话分别交给三台实例，每个节点在各自的 `gramine-sgx` enclave 内加载**自己
那一份**份额，一个客户端提示驱动三节点协议连续生成 3 个 token；五类篡改/重放
负例全部在进入 MPC 之前被拒；会话关闭后三台的会话目录被覆写删除，清洁度与
reveal 扫描干净；三份抓包都判为 `tls13_only` 且无空洞。

**这仍然不是"整个 GPT-2 跑在 enclave 里"。** 本次实际运行的是 1 层 Block 加
1028 个候选 token 的受限解码，两个受限都是写在 manifest 里、双方各自校验的
声明，不是省略。第 6 节把它们逐条列出。

## 1. 验收基线

| 角色 | 实例 ID | 私网 | 公网 |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.15.28.144` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `139.224.54.254` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `8.133.240.216` |

- 运行 ID `d7-enclave-3host-20261014T1018Z`，提交
  `a1f45db677c4d202b1561e51cb28d65c6e468a8b`。
- 运行时：SecretFlow-SPU 0.9.5（`SEMI2K`、`FM64`、`fxp_fraction_bits = 18`），
  Gramine + `gramine-sgx`、`sgx.enclave_size = 4G`、`max_threads = 64`、栈 2M。
- 模型几何：`layers = 1`、`sequence = 8`、`hidden_size = 768`、`num_heads = 12`、
  `intermediate_size = 3072`、`vocab_size = 1028`（候选词表）、`fractional_bits = 18`。
- 每台节点在自己实例的 enclave 内执行；SPU/YACL/BRPC 的 TLS 1.3 流量走 VPC
  私网，每台用本机 `tcpdump` 抓自己那一段；逐步骤状态溢写到
  `/dev/shm/a122-d7/<run-id>/<role>`（tmpfs，宿主可观察）。
- 份额由 dealer 在操作机上离线切成三份，每台只拿到自己那一个
  `shares/<role>.json`；明文份额不进镜像、不进 Git。

## 2. 使用的工具

| 组件 | 作用 |
| --- | --- |
| `contracts/d7_session.py` | 冻结的会话契约：`ModelManifest`、`SessionPlan`、step/result 载荷与解析器、精度计划（SEMI2K/FM64/fxp18/无 reveal） |
| `mpc/spu_backend/d7_program.py` | 正式 GPT-2 的静态图：embedding 查表 + 1 层 Block + 候选 `lm_head`，输入 29 个权重张量 + `history`(8x1028)，输出 `hidden`/`logits`/`token` |
| `mpc/spu_backend/d5_program.py` | D5 的 Block 程序，D6/D7 以关键字参数扩展 prelude/额外输入，D5 行为不变 |
| `mpc/spu_backend/sharing.py` | `split_secret`、`share_probe`（份额的 32 字符前缀）、`make_splitter`/`make_joiner` |
| `mpc/secure_ops/kv_cache.py` | `KVBuffer` 就地清零、`wipe_record`、`assert_scrubbed` |
| `client/gpt2_bpe.py` | 纯 Python GPT-2 字节级 BPE（与 `GPT2TokenizerFast` 逐 id 相同，见 `tests/unit/test_d7_gpt2_tools.py`） |
| `crypto/frame.py` | `SecureSession.wipe()`：清空双向密钥与转录哈希，并记录被清零的字节数 |
| `tee/enclave/d7_node.py` | D7 节点：D6 状态机的子类，换自己的 ready/done 标记与模型 manifest 解析 |
| `tee/enclave/d6_node.py` | 共享状态机：hello→ticket→握手→会话运行时；逐步溢写、票据注册表拒绝重放、close 覆写并删除会话目录 |
| `client/d7_session.py` / `client/d7_runner.py` | 私有自回归循环、结果帧重建、安全 Argmax 与重建 logits 的比对、五类负例、浮点参考比对、并发 release |
| `infra/d7_workspace.py` / `infra/d7_stage.py` | 复用 D4 PKI 生成三角色配置与份额，逐节点打包并在跑完覆写删除 |
| `infra/d7_three_hosts.py` | 一条命令的三实例驱动、抓包、证据收集与封存 |
| `infra/hygiene_scan.py` / `infra/reveal_scan.py` | close 后的探针搜索；生产路径 reveal 扫描 |

## 3. 运行

```bash
# 操作机上（三实例，每个节点放进 gramine-sgx，跑完自动收集、封存、校验）
python -m infra.d7_three_hosts \
  --cluster <cluster.json> \
  --run-id d7-enclave-3host-<stamp> \
  --out-dir docs/evidence/<run-id> \
  --mode enclave --seal \
  --prompt "the cipher key is secret" --max-new-tokens 3 \
  --ssh-user jiahao --ssh-key <key> --ssh-key-password <pass> \
  --expect-commit a1f45db677c4d202b1561e51cb28d65c6e468a8b
```

驱动在 operation 机上切份额、逐节点打 tar、在 P0 起一个绑在 **VPC 私网地址**上的
临时 HTTP 服务（端口 47890）供 P1/P2 取自己的包，取完立刻停掉；随后三台各自
渲染并签名自己将要加载的 manifest，依次启动抓包与节点。P0 上另起客户端进程，
向三个 share 端口建三路 mTLS 会话并驱动自回归循环；驱动在客户端运行期间每
0.5 s 采一次会话目录快照，客户端结束后回读结果、状态、日志与逐台 TLS 摘要，
跑 reveal 扫描，再对三台做清洁度扫描，覆写删除三份 staged 份额，最后封存索引
并校验。

抓包用 `tcpdump -i eth0 -s 0 -B 262144`：D7 一次解码在三台之间各走约 1.2 GB，
内核默认的接收环（本镜像 `net.core.rmem_max` 原为 212992 字节）会在一毫秒内溢出，
丢包之后分析器再也无法重组那条流。第一次封存运行
（`d7-enclave-3host-20261014T094737Z`）的三份抓包就因此判成
`tls_or_plaintext_violation`（`non_tls_payload_bytes` 为 0，但 `capture gaps`
各约 6.5 万～7.7 万包）。驱动现在在起抓包之前先读 `net.core.rmem_max`，够大才
继续，并明确要求 256 MiB 的环；三台实例的 `net.core.rmem_max` 已提到
268435456，本文是修复后重跑的结果。那一束有空洞的证据没有提交，它的原始文件留在
`artifacts/`（gitignore）。

第一束修复后抓包的运行（`d7-enclave-3host-20261014T1015Z`）虽然解出了 token、
抓包也干净，但它封存的"份额已擦除"判决是假的：擦除脚本把每一处 `~/…` 都交给了
`shlex.quote`，波浪号被冻结成一个字面目录名，`[ -f "$share" ]` 恒为假，驱动
三台都记下 `bytes_overwritten: 0`、`share_present: no`，而每台上 92,542,258
字节的 `shares/<role>.json` 与 70 MB 的 dist 包还原封不动躺在磁盘上。该束证据已
作废并从 `docs/evidence/` 删除，三份泄漏的份额在实例上手工覆写删除。修复见
`infra/d7_three_hosts.py` 的 `scrub_script`（每处家目录路径都经 `remote_path`
渲染成 `"$HOME/…"`，探针改为搜 1 MiB 以上的 JSON），本文这一束是两处修复都落地
之后重跑的结果，§4.10 的擦除字节数现在是真实的 92,542,258。

## 4. 结果

### 4.1 生成的 token

| 项 | 值 |
| --- | --- |
| Prompt | `the cipher key is secret` |
| Prompt token | `[1169, 38012, 1994, 318, 3200]` |
| 候选表内下标 | `[1024, 1027, 1025, 318, 1026]` |
| 生成 token | `[3200, 3200, 3200]` |
| 生成词 | `[' secret', ' secret', ' secret']` |
| 生成文本 | ` secret secret secret` |
| 会话 ID | `a713073d9ca6db610dcc8900715957a404266eae66faf8366d8c57b6c79caa57` |

| 步 | token | 候选下标 | `decode_row` | 历史长度 | 重建 logits 的 Argmax | 安全 Argmax | 客户端 wall ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3200 | 1026 | 4 | 5 | 1026 | `True` | 5242.258 |
| 2 | 3200 | 1026 | 5 | 6 | 1026 | `True` | 5067.478 |
| 3 | 3200 | 1026 | 6 | 7 | 1026 | `True` | 5759.579 |

最后两列的相等是这条回路要证明的事：三方各自用 enclave 内的安全比较得出 token，
而手上没有任何模型份额的客户端把三份回执重建成 logits，自己再取一次 Argmax，
两者一致。客户端整段 wall time 为 16.717 s，三个节点各自的单步耗时在 4.58 s～
5.33 s 之间（P0 4693.1/4578.8/5296.8 ms，P1 4863.8/4619.4/5210.7 ms，
P2 4725.2/4683.0/5329.1 ms）。

### 4.2 与浮点参考的偏差

| 步 | `max_abs_error` | `mean_abs_error` | 参考 token | token 一致 | Argmax 一致 |
| --- | --- | --- | --- | --- | --- |
| 1 | 6.34e-2 | 1.43e-2 | 1026 | `True` | `True` |
| 2 | 6.09e-2 | 1.36e-2 | 1026 | `True` | `True` |
| 3 | 6.50e-2 | 1.35e-2 | 1026 | `True` | `True` |

最差 `max_abs_error` 为 0.06500。参考由 dealer 侧用同一份冻结权重以 float64
计算，客户端不持有模型。

这里要如实说明两件事。第一，这个数字比 D6 的 4e-4～8e-4 大两个数量级。原因
不是 enclave 出错，而是几何与量程：D6 是 `hidden = 16`、`vocab = 152` 的玩具
Block，logits 在个位数附近；D7 是 `hidden = 768`、`intermediate = 3072`、候选
宽 1028 的正式层，本次 logits 的取值范围是 −39.7 到 +8.3。同样 18 位小数位
（分辨率 2⁻¹⁹ ≈ 1.9e-6）在更宽的归约里累积，而误差是绝对量，所以它随 logits
量程一起放大。第二，这一次比较的是 **enclave 输出 vs dealer 侧 float64 参考**
（6.5e-2），与 [d7-model-freeze.md](d7-model-freeze.md) §4 里
**程序 float 参考 vs 发布版 GPT-2**（5.8e-5）不是同一个量，不能拿来互相抵消。
本次能证明的是：3 步的 token 与 Argmax 都与参考一致，即这个量级的定点误差没有
改变解码结果。

### 4.3 五类负例

| 场景 | 结果 | 驱动给出的原因 |
| --- | --- | --- |
| `duplicate_result_frame` | 拒绝 | `result frames do not cover P0, P1, and P2` |
| `tampered_decode_step` | 拒绝 | `result-frame decode-step mismatch` |
| `mixed_model_manifest` | 拒绝 | `result-frame model mismatch` |
| `replayed_request_frame` | 拒绝 | `ReplayRejected: counter is duplicated or out of order` |
| `replayed_job_ticket` | 拒绝 | `D6NodeError: the JobTicket has already been accepted by this node` |

前三条在结果帧重建阶段被客户端拦下，后两条在帧重放与票据注册表阶段被节点拦下，
都在进入 MPC 之前。P1 的状态里如实记着 2 条对应的拒绝记录（重放帧与重放票据
都被发给了它），P0/P2 没有收到这两条。

### 4.4 会话状态清理

| 角色 | 溢写文件 | 覆写字节 | 会话目录被删除 | 密钥清零字节 | 残留 KV 条目 |
| --- | --- | --- | --- | --- | --- |
| P0 | 3 | 196839 | `True` | 80 | 0 |
| P1 | 3 | 196839 | `True` | 80 | 0 |
| P2 | 3 | 196839 | `True` | 80 | 0 |

| 项 | close 之前 | close 之后 |
| --- | --- | --- |
| 会话根下的文件数 | 1 | 0 |
| 会话根下的字节数 | 65613 | 0 |

close 之前驱动采到的快照是三台各一份 `kv/step-0001.share`（每台 65613 字节）；
close 之后 `session_dir_removed: true`、三个目录都
不存在、`kv.all_zero: true`、`buffers: 3`、`entries: 0`、`unscrubbed: []`。
这三份快照由驱动采样，不是节点自己的声明。D7 的单步状态比 D6 大一个数量级
（65613 对 1441 字节），因为 `hidden = 768` 的那一层就是这么大。

### 4.5 清洁度扫描

三个角色的 `hygiene … verdict` 都是 `clean`、`findings: 0`、`not_empty: []`、
`file_hits`/`process_hits`/`journal_hits` 全空。扫描用本次运行发布过的 18 个
share 前缀作为探针，搜索 `/dev/shm` 会话根、`/tmp`、workspace 的 `out/`、
`/var/log`、systemd journal，以及每个进程的 command line 与环境变量。扫描同时
断言三个会话目录已不存在、会话根为空。

### 4.6 enclave 证据

| 角色 | MRENCLAVE | `d7_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `9c3fb97916d4e967eb7a6e08176053948d287058b6f88c8fd29c1c290b39d781` | `5382eee046312effed93e8854ab821ffed3f459080e26d18fa5ce3619d4fcda0` |
| P1 | `033bb39c2cac324828035613b68e10e4e5fd658f5fe84a7268094f035cdbea3f` | `d8710ad89ac42dbe92a7e8864a3705a18d2680abe41defa3fc5ae89441c93f99` |
| P2 | `1532891dde086f807e25813af6a49641b40a054e2f86599dc1cd2ba7f26862cc` | `11b3a190e309e335fb4b184d2150b89d0cb271c1403768ae778970c12eea791b` |

- 三个节点的 `inside_enclave: true`，`transport` 记录为
  `SPU/YACL/BRPC over TLS 1.3 inside a Gramine-SGX enclave`。
- 三份节点日志都以 `Gramine is starting. Parsing TOML manifest file…` 开头，
  说明节点确实运行在 `gramine-sgx` 里，而不是宿主进程。
- `distinct_measurements: 3`。这次**是设计使然而不是缺陷**：三台各自签名自己
  真正加载的那棵树，而三棵树里放的是不同的份额，所以测量值本就不同。单一
  MRENCLAVE 的形态用的是
  [d4-acceptance.md](d4-acceptance.md) 4.10 节的 staged 树流程，D7 默认驱动
  不替人做 staging。
- 节点没有读取 `/dev/attestation/quote`，本文不据此声明任何 attestation 结论。

### 4.7 证书互校与自释放

三个角色的身份摘要两两对应：P0 `a06e5a0d…`、P1 `56d93f84…`、P2 `31e5f737…`，
每个角色记录的另两个对端摘要与对方自报的一致（例如 P1 记录的 P0/P2 摘要与
P0/P2 各自的自报值逐字节相同）；三方建链耗时 4.609 s / 7.553 s /
6.626 s，`teardown_finished` 三者皆为 `True`，`shutdown` 三步都回
`{"released": true, "reply": "bye"}`。

### 4.8 抓包

三份抓包各自只由产生它的实例分析，判决都是 `tls13_only`，没有空洞，不能归属到
TLS 的载荷字节为 0：

| 角色 | 抓包字节 | 期望端口报文 | TLS 1.3 流 | TLS 1.2 及以下 | 应用数据记录 | 非 TLS 字节 | 空洞 | 判决 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P0 | 1265072028 | 134109 | 11 | 0 | 228852 | 0 | 0 | `tls13_only` |
| P1 | 1263911253 | 132970 | 8 | 0 | 228808 | 0 | 0 | `tls13_only` |
| P2 | 1263687263 | 132582 | 7 | 0 | 228800 | 0 | 0 | `tls13_only` |

期望端口是驱动程序声明的全部七个：六个 SPU/share 端口加暂存用的 47890。抓包
过滤器与后处理分析用的是同一份列表。重传为 231/254/233 包（去重后 92 KB～103 KB），
属于跨公网/VPC 的正常重传。原始 pcap 各约 1.26 GB，留在产生它的实例的 `/tmp/` 下；
`<bundle>.exclusions.json` 记下三份的字节数与 sha256，放进目录会让校验更严而不是
绕过。本次没有做"故意明文探测"，因此 probe 列表为空，D4 的明文探针覆盖那一条。

### 4.9 生产路径 reveal 扫描

`d7-reveal-scan.json` 在三台的树各扫一遍 `mpc/`、`tee/`、`kas/`、`client/`、
`crypto/`、`contracts/`、`deploy/`、`infra/` 下的 Python 源，三个角色都是
`findings: 0`、`verdict: clean`；命中的 34 处全部落在白名单里（本地固定点参考、
显式 opt-in 的仿真 provider、扫描器自己的模式表，以及断言必须拒绝的负例测试）。

### 4.10 份额分发与清理

| 角色 | tar 字节 | tar sha256 | 包内份额文件 | 跑完覆写 | 目录删除 |
| --- | --- | --- | --- | --- | --- |
| P0 | 70110076 | `104a2a8d…` | `shares/P0.json` | `clean` | `True` |
| P1 | 70111043 | `4615a9f4…` | `shares/P1.json` | `clean` | `True` |
| P2 | 70110961 | `6c86e0a5…` | `shares/P2.json` | `clean` | `True` |

每台只拿到自己那一个份额文件（`shared_with_this_node` 逐节点都只有一个），P1/P2
是从 P0 的 VPC 私网地址取的（`FETCH-OK`，tar 校验通过），没有任何一份份额走过
公网。跑完驱动回读三棵树，每台的 `shares/<role>.json` 都被第一遍用 `dd` 覆写
92,542,258 字节、第二遍 `rm -f`，`share_present=no`；随后
`find … -name '*.json' -size +1048576c` 在 staged 树与 dist 根上都没再找到任何
份额大小的 JSON（`large_json_left: []`），`staging_scrub … verdict` 为 `clean`。
会话绑定的 `plan_manifest` 为 `model_manifest_hash = 3afdeb07…`、
`precision_plan_hash = db1950d9…`、`release_id = a122-d7`、`share_epoch = 1`。

## 5. 证据位置

[docs/evidence/d7-enclave-3host-20261014T1018Z](evidence/d7-enclave-3host-20261014T1018Z)
共 25 个索引条目（22 个随包文件 + 3 个只留摘要的抓包）：

| 文件 | 内容 |
| --- | --- |
| `d7-summary.json` | 角色、prompt、token、逐步延迟、负例、close 证据、enclosure、before/after 会话快照、份额分发与清理、抓包摘要 |
| `d7-client-result.json` | 客户端看到与检查的全部内容：请求哈希、重建 token、自己的 Argmax 比对、每条被拒的负例与浮点参考比对 |
| `d7-client.log` | 客户端进程自己的 stdout，含一行判决 |
| `d7-three-p{0,1,2}-node-status.json` | 每个节点的逐步摘要、拒绝记录、KV 清零记录与 close 证据 |
| `d7-three-p{0,1,2}-node.log` | 每个节点的日志（Gramine 启动行，含自身摘要与对端摘要的 ready 行，末尾 done 行） |
| `d7-three-P{0,1,2}-tls-summary.txt` | 每台实例对自己那段抓包的 TLS 1.3 分析 |
| `d7-hygiene-p{0,1,2}.json` | 每台实例 close 后对 tmpfs、临时树、日志与进程表的搜索结果 |
| `d7-reveal-scan.json` | 三棵树共用的 reveal 扫描 |
| `d7-stage.json` | dealer 侧的份额切分、逐节点打包与分发记录 |
| `d7-enclave-p{0,1,2}-sign.txt`、`d7-enclave.manifest` | 三台 `gramine-sgx-sign` 的输出与被签 manifest |
| `README.md` | 由封存摘要生成的运行说明 |
| `evidence-index.json`、`evidence.sha256` | 目录索引与封存 |

本地复验：`python -m pytest tests/unit/test_evidence_bundles.py -q` 报 7 passed，
其中包含对这个新封存目录的校验（索引、seal、exclusions、LF 行尾、无 PEM）。

## 6. 尚未覆盖

以下内容未被本次运行证明，不得按已通过计：

1. **不是整个 GPT-2。** 实际跑的是 1 层 Block、窗口 8、候选词表 1028。层数与
   候选宽度都写进 `ModelManifest` 并由两端各自校验，任一不匹配会在进入 MPC
   之前被拒；但"生成质量"只在候选集内成立，可复核的判据是"发布版 top-1 落在
   候选集内、且 3 步 Argmax 与参考一致"。
2. **不是真实 attestation 放行。** 证书仍来自本次运行的本地 PKI，不是
   Quote → 验证 → 签发短期身份/Lease 的 KAS 产物。与 D4 第 7 节第 1 项同一条
   缺口。节点没有读 `/dev/attestation/quote`。
3. **enclave 配置仍是开发档。** 节点日志照实打印了 Gramine 的三条
   `insecure configurations`：`loader.log_level`、`loader.insecure__use_cmdline_argv`
   （把宿主的命令行原样转给应用）和 `sgx.allowed_files`（有一部分文件不经校验
   直通）。这三条在 D5/D6 的同一份模板上就存在，属于当前开发配置，不是本次
   新引入的；生产化要单独处理。
4. **抓包只证明"没有看到明文"，不证明"抓全了每一字节"。** 环已经放大到能装下
   本次流量（空洞 0），但这是本次规模下的结论。
5. **没有性能结论。** 只有 enclave 内逐步 wall time，没有 EPC/CPU/RAM、网络
   档位对照和开/关消融，那属于 D8。
6. **三份测量值不同是按设计如此**，不是缺陷；单一 MRENCLAVE 的形态在 D4。

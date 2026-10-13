# D6 端到端私有自回归验收记录

本文记录 D6 的实测结果：一个客户端提示经过三台 SGX enclave 内的 P0/P1/P2，
连续生成 3 个 token；每一步的 enclave 内安全 Argmax 与客户端从三份回执重建
logits 后自己取的 Argmax 逐个相等；五类篡改/重放负例全部被拒；会话结束后三台
的会话目录被覆写并删除，随后的清洁度扫描在每台实例上都干净。

## 1. 验收基线

| 角色 | 实例 ID | 私网 | 公网 |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.14.207.224` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `47.117.34.67` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `47.116.200.143` |

- 运行 ID `d6-enclave-3host-20261013T1324Z`，提交
  `3e82e1b890bdcfc004688f5f65238fb09156863b`。
- 运行时：SecretFlow-SPU 0.9.5（`SEMI2K`、`FM64`、`fxp_fraction_bits = 18`），
  Gramine 1.9 + `gramine-sgx`、`sgx.remote_attestation = "dcap"`、
  `sgx.enclave_size = 4G`、`max_threads = 64`、栈 2M。
- 几何：`sequence = 8`、`hidden_size = 16`、`num_heads = 2`、
  `intermediate_size = 32`、`vocab_size = 152`，用例种子 `20261013`。
- 每台节点在自己实例的 enclave 内执行，SPU/YACL/BRPC 的 TLS 1.3 流量走 VPC
  私网，每台用本机 `tcpdump` 抓自己那一段；逐步骤状态溢写到
  `/dev/shm/a122-d6/<run-id>/<role>`（tmpfs，宿主可观察）。

## 2. 使用的工具

| 组件 | 作用 |
| --- | --- |
| `contracts/d6_session.py` | 冻结的会话契约：`ModelManifest`、`SessionPlan`、step/result 载荷与解析器、精度计划（SEMI2K/FM64/fxp18/无 reveal） |
| `mpc/spu_backend/d6_program.py` | 把 embedding 查表并入 D5 Block，输入 21 个权重张量 + `history`(8x152)，输出 `hidden`/`logits`/`token` |
| `mpc/spu_backend/d5_program.py` | D5 的 Block 程序，D6 以关键字参数扩展 prelude/额外输入，D5 行为不变 |
| `mpc/spu_backend/sharing.py` | `split_secret`、`share_probe`（份额的 32 字符前缀）、`make_splitter`/`make_joiner` |
| `mpc/secure_ops/kv_cache.py` | `KVBuffer` 就地清零、`wipe_record`、`assert_scrubbed` |
| `client/tokenizer.py` | 152 词 `WordTokenizer`；`"the cipher key is secret"` → `[3,70,71,11,80]` |
| `crypto/frame.py` | `SecureSession.wipe()`：清空双向密钥与转录哈希，并记录被清零的字节数 |
| `tee/enclave/d6_node.py` | D6 节点：hello→ticket→握手→会话运行时；逐步溢写、票据注册表拒绝重放、close 覆写并删除会话目录 |
| `client/d6_session.py` | 私有自回归循环、结果帧重建、安全 Argmax 与重建 logits 的比对、五类负例、并发 close |
| `client/d6_runner.py` | 客户端进程：`TLSExchange`、构建客户端、浮点参考比对、并发 release |
| `infra/d6_workspace.py` | 复用 D4 PKI 生成三角色配置与份额（含 `shares/` 在受测树内） |
| `infra/d6_three_hosts.py` | 一条命令的三实例驱动、证据收集与封存 |
| `infra/hygiene_scan.py` | 会话根、`/tmp`、`out/`、日志、`journalctl`、`/proc/*/cmdline|environ` 的探针搜索 |
| `infra/reveal_scan.py` | 生产路径 reveal 扫描，逐文件白名单 |

## 3. 运行

```bash
# 操作机上（三实例，每个节点放进 gramine-sgx，跑完自动收集、封存、校验）
python -m infra.d6_three_hosts \
  --cluster <cluster.json> \
  --run-id d6-enclave-3host-<stamp> \
  --out-dir docs/evidence/<run-id> \
  --mode enclave --seal \
  --ssh-user jiahao --ssh-key <key> --ssh-key-password <pass> \
  --expect-commit 3e82e1b890bdcfc004688f5f65238fb09156863b

# 同一条驱动不换代码、只换启动方式，先在宿主进程上跑一遍
python -m infra.d6_three_hosts ... --mode host --run-id d6-host-3host-<stamp>
```

驱动在 P0 用真实 libspu 生成工作区，经 tar 分发到 P1/P2；三台各自渲染并签名自己
将要加载的 manifest，再依次启动抓包与节点。P0 上另起客户端进程，向三个 share
端口建三路 mTLS 会话并驱动自回归循环；驱动在客户端运行期间每 0.5 s 采一次会话
目录快照（记录 close 之前的份额落盘状态），客户端结束后回读结果、状态、日志与
逐台 TLS 摘要，跑 reveal 扫描，再对三台做清洁度扫描，最后封存索引并校验。

本次先跑 `--mode host` 预演（运行 `d6-host-3host-20261013T1323Z`）确认整套接线，
再跑 enclave 版本。两者生成同样的 token 序列。

## 4. 结果

### 4.1 生成的 token

| 项 | 值 |
| --- | --- |
| Prompt | `the cipher key is secret` |
| Prompt token | `[3, 70, 71, 11, 80]` |
| 生成词 | `['yes', 'his', 'small']` |
| 生成文本 | `yes his small` |
| 会话 ID | `ef8e01b0e5feb8725132ece9b2d177974813df4d2c17bf9b187ad2cccc9adf52` |

| 步 | token | 词 | 重建 logits 的 Argmax | 安全 Argmax | wall ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 30 | `yes` | 30 | `True` | 2102.595 |
| 2 | 45 | `his` | 45 | `True` | 2229.916 |
| 3 | 60 | `small` | 60 | `True` | 2230.384 |

最后两列的相等是这条回路要证明的事：三方各自用 enclave 内的安全比较得出 token，
而手上没有任何模型份额的客户端把三份回执重建成 logits，自己再取一次 Argmax，
两者一致。客户端整段 wall time 为 7.383 s。

### 4.2 与浮点参考的偏差

| 步 | `max_abs_error` | `mean_abs_error` | 参考 token | token 一致 | Argmax 一致 |
| --- | --- | --- | --- | --- | --- |
| 1 | 8.02e-4 | 2.26e-4 | 30 | `True` | `True` |
| 2 | 4.92e-4 | 1.20e-4 | 45 | `True` | `True` |
| 3 | 4.21e-4 | 1.38e-4 | 60 | `True` | `True` |

参考由 dealer 侧用同一份合成权重以 float64 计算，客户端不持有模型。

### 4.3 五类负例

| 场景 | 结果 | 驱动给出的原因 |
| --- | --- | --- |
| `duplicate_result_frame` | 拒绝 | `result frames do not cover P0, P1, and P2` |
| `tampered_decode_step` | 拒绝 | `result-frame decode-step mismatch` |
| `mixed_model_manifest` | 拒绝 | `result-frame model mismatch` |
| `replayed_request_frame` | 拒绝 | `ReplayRejected: counter is duplicated or out of order` |
| `replayed_job_ticket` | 拒绝 | `D6NodeError: the JobTicket has already been accepted by this node` |

`negative_verdicts.passed` 为 `true`，且每一条都由客户端在真正进入 MPC 之前拦下
（前三条在结果帧重建阶段，后两条在帧重放与票据注册表阶段）。

### 4.4 会话状态清理

| 角色 | 溢写文件 | 覆写字节 | 会话目录被删除 | 密钥清零字节 | 残留 KV 条目 |
| --- | --- | --- | --- | --- | --- |
| P0 | 3 | 4323 | `True` | 80 | 0 |
| P1 | 3 | 4323 | `True` | 80 | 0 |
| P2 | 3 | 4323 | `True` | 80 | 0 |

| 项 | close 之前 | close 之后 |
| --- | --- | --- |
| 会话根下的文件数 | 3 | 0 |
| 会话根下的字节数 | 4323 | 0 |

close 之前每个角色各有一份 `kv/step-0001.share`（1441 字节）；close 之后
`session_dir_removed: true`、`/dev/shm` 下三个目录都不存在、`kv.all_zero: true`、
`unscrubbed: []`。这三份快照由驱动在客户端运行期间采样，不是节点自己的声明。

### 4.5 清洁度扫描

三个角色的 `hygiene … verdict` 都是 `clean`、`findings: 0`、`not_empty: []`。
扫描用本次运行发布过的 18 个 share 前缀作为探针，搜索 `/dev/shm` 会话根、
`/tmp`、workspace 的 `out/`、`/var/log`、systemd journal，以及每个进程的
command line 与环境变量。扫描同时断言三个会话目录已不存在、会话根为空——一个
"删了目录但留了别的东西"的 close 会在这里失败，而不是被记成脚注。

### 4.6 enclave 证据

| 角色 | MRENCLAVE | `d6_node.manifest` sha256 |
| --- | --- | --- |
| P0 | `60660738c586699f960d9fadb3a3771b96c730c851480ce901ad745655875609` | `9883706a9839e82b6948d6e5c08b7e5b489912632b20fadcb4fd87acd971407a` |
| P1 | `6694f72dc7a17414e32797ae548389a3099cc6d7a5010fc730265231132768d7` | `fee8a481b758a4151cc725b10611b19c42e14da671c8acb6a4c7677d6a58d7f4` |
| P2 | `afe0b3070c1a5f73b33990b05f38163f8f32aeb3b71a3c9c02cb1a5121c12549` | `a715fb12f9373406ba459fae64d7b635fdffae24510237ad177f81e44d25cbae` |

- 三个节点的 `inside_enclave: true`，`transport` 记录为
  `SPU/YACL/BRPC over TLS 1.3 inside a Gramine-SGX enclave`。
- 三份节点日志都以 `Gramine is starting. Parsing TOML manifest file…` 开头，
  说明节点确实运行在 `gramine-sgx` 里，而不是宿主进程。
- `distinct_measurements: 3`：每台各自签名自己真正加载的树，所以测量值不同。
  这一点如实记录，没有把三次运行写成一个 enclave。单一 MRENCLAVE 用的是
  [d4-acceptance.md](d4-acceptance.md) 4.10 节的 staged 树流程；D6 默认驱动
  不替人做 staging。
- D6 节点没有读取 `/dev/attestation/quote`（状态里 `attestation_available` 为空），
  本文不据此声明任何 attestation 结论；真实放行仍是 D4 的缺口。

### 4.7 证书互校与自清理

三个角色的证书摘要两两对应：P0 `33a7b2c2…`、P1 `bb0320c3…`、P2 `2f413f87…`，
每个角色记录的另两个对端摘要与对方自报的一致；`teardown_finished` 三者皆为
`True`。P1 的状态里记有 2 条拒绝，来自负例阶段向它重放的帧与票据。

### 4.8 抓包

三份抓包各自只由产生它的实例分析，判决都是 `tls13_only`，不能归属到 TLS 的
载荷字节为 0：

| 角色 | 期望端口报文 | TLS 1.3 流 | TLS 1.2 及以下 | 应用数据记录 | 非 TLS 字节 | 判决 |
| --- | --- | --- | --- | --- | --- | --- |
| P0 | 38260 | 11 | 0 | 64805 | 0 | `tls13_only` |
| P1 | 38283 | 8 | 0 | 64765 | 0 | `tls13_only` |
| P2 | 38355 | 7 | 0 | 64756 | 0 | `tls13_only` |

原始 pcap 各约 17 MB，留在产生它的实例的 `/tmp/` 下；`<bundle>.exclusions.json`
记下三份的字节数与 sha256，放进目录会让校验更严而不是绕过。本次运行没有做
"故意明文探测"，因此 probe 列表为空——D4 的明文探针覆盖那一条。

### 4.9 生产路径 reveal 扫描

`d6-reveal-scan.json` 在三台的树各扫一遍 `mpc/`、`tee/`、`kas/`、`client/`、
`crypto/`、`contracts/`、`deploy/`、`infra/` 下的 Python 源，三个角色都是
`findings: 0`、`verdict: clean`；命中的 34 处全部落在白名单里（本地固定点参考、
显式 opt-in 的仿真 provider、扫描器自己的模式表，以及断言必须拒绝的负例测试）。

## 5. 证据位置

[docs/evidence/d6-enclave-3host-20261013T1324Z](evidence/d6-enclave-3host-20261013T1324Z)
共 24 个索引条目：

| 文件 | 内容 |
| --- | --- |
| `d6-summary.json` | 角色、prompt、token、逐步延迟、负例、close 证据、enclosure、before/after 会话快照与抓包摘要 |
| `d6-client-result.json` | 客户端看到与检查的全部内容：请求哈希、重建 token、自己的 Argmax 比对、每条被拒的负例与浮点参考比对 |
| `d6-client.log` | 客户端进程自己的 stdout，含一行判决 |
| `d6-three-p{0,1,2}-node-status.json` | 每个节点的逐步摘要、拒绝记录、KV 清零记录与 close 证据 |
| `d6-three-p{0,1,2}-node.log` | 每个节点的日志（ready 行含自身摘要与对端摘要，末尾 done 行） |
| `d6-three-P{0,1,2}-tls-summary.txt` | 每台实例对自己那段抓包的 TLS 1.3 分析 |
| `d6-hygiene-p{0,1,2}.json` | 每台实例 close 后对 tmpfs、临时树、日志与进程表的搜索结果 |
| `d6-reveal-scan.json` | 三棵树共用的 reveal 扫描 |
| `d6-enclave-p{0,1,2}-sign.txt`、`d6-enclave.manifest` | 三台 `gramine-sgx-sign` 的输出与被签 manifest |
| `README.md` | 由封存摘要生成的运行说明 |
| `evidence-index.json`、`evidence.sha256` | 目录索引与封存 |

本地复验：`python -m pytest tests -q` 报 **234 passed, 1 skipped**（含
`tests/unit/test_evidence_bundles.py` 对这个新封存目录的校验），
`python -m pyflakes client contracts crypto kas model mpc tee infra tests`
在 `client/`、`tee/`、`infra/` 上没有未定义名。

## 6. 尚未覆盖

以下内容未被本次运行证明，不得按已通过计：

1. 不是正式模型：权重是按 Kaiming-uniform 生成的合成权重，词表 152，目的是把
   端到端回路、KV 与会话清理打通，不构成语言模型质量结论。正式英文 GPT-2 属 D7。
2. 不是真实 attestation 放行：证书仍来自本次运行的本地 PKI，不是
   Quote → 验证 → 签发短期身份/Lease 的 KAS 产物。与 D4 第 7 节第 1 项同一条缺口。
3. 没有性能结论：只有 enclave 内逐步 wall time，没有 EPC/CPU/RAM、网络档位对照
   和开/关消融，那属于 D8。
4. 三份测量值不同：默认驱动让每台签名自己的树，因此是三个 enclave、三份测量值。
5. 明文探针为空：本次没有向端口发故意明文连接；D4 的三实例运行覆盖了那一条。

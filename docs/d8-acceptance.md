# D8 网络档位与资源实测验收记录

D8 量的是同一份 D7 工作负载在三档**声明**网络条件下的表现：三台实例各在
`gramine-sgx` 内加载自己那份正式权重份额，一个客户端提示驱动 3 步解码，每档
完整跑一遍；运行期间每 0.5 s 采一次宿主资源，跑完由每台实例分析自己那段抓包。
档位不是叙述，而是 `tc` 真的挂在网卡上：驱动在节点就绪之后、客户端启动之前，
给每台的**出向**流量（目标是对端子网 `172.27.172.0/24`）挂 `delay + rate`，
跑完在 `finally` 里拆掉；挂完先验 `FILTER-OK`，再用本机 `ping` 量一次往返，
量不到声明的延迟就让整档失败。**没有真正生效的档位不会出现在报告里。**

**本次不是"每项优化的开/关对照"。** D7 冻结的那个程序没有近似的运行时开关，
消融要另做第二个冻结程序，本次没有做；本内核不提供每进程 EPC 常驻计数，报告
不会替它编一个数；长度桶与 batch 没有被 1 层探针几何覆盖。第 5 节逐条列出。
几何仍然是 D7 的 **1 层 Block + 1028 候选词表**，不是整个 GPT-2。

## 1. 验收基线

| 角色 | 实例 ID | 私网 | 公网 |
| --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ` | `172.27.172.201` | `106.15.28.144` |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z` | `172.27.172.202` | `139.224.54.254` |
| P2 | `iZuf6bd6qnhgtveg5khygdZ` | `172.27.172.203` | `8.133.240.216` |

- 运行 ID `d8-enclave-profiles-20261014T1056Z`，提交
  `df01452ef187a5bcf223dd082afce511508a7579`。
- 三档依次为 `lan`（不注入）、`wan-40ms`（每台出向 40 ms、限速 100 Mbit/s）、
  `wan-80ms`（每台出向 80 ms、限速 100 Mbit/s）；三档完成时刻分别是
  2026-10-14T10:59:38Z、11:05:02Z、11:12:14Z。
- 模型几何与 D7 相同：`gpt2-1l-cand1028-v1`（model hash
  `c0394f5002ee79e2a9119d85e44d756dcd8b3aa930934919e2cf7f871df85ad9`）、
  `layers = 1`、`hidden_size = 768`、`intermediate_size = 3072`、
  `vocab_size = 1028`、`fractional_bits = 18`；提示
  `the cipher key is secret`，每档生成 3 个 token。
- 平台事实（三台一致，由各实例自己从 `/proc`、内核 ring buffer 与
  `/dev` 读出）：Intel Xeon Platinum 8369B、4 vCPU、7523 MB 内存、
  EPC 段 `0x240000000-0x42fffffff`、`/dev/sgx_enclave`、Gramine 1.9、
  内核 `5.15.0-191-generic`。
- 每档都跑完整的 D7 流程：份额切分与逐节点分发、三棵 `gramine-sgx`、
  五类负例、close 覆写、清洁度扫描，一样不少。变的只有网络。

## 2. 运行方式

```bash
python -m infra.d8_three_hosts \
  --cluster <cluster.json> \
  --run-id d8-enclave-profiles-<stamp> \
  --out-dir artifacts/server/d8-enclave-profiles-<stamp> \
  --profiles lan,wan-40ms,wan-80ms \
  --prompt "the cipher key is secret" --max-new-tokens 3 \
  --ssh-user jiahao --ssh-key <key> --ssh-key-password <pass> \
  --sudo-password <pw> \
  --expect-commit df01452ef187a5bcf223dd082afce511508a7579 --seal
```

每一档走的就是 D7 那条驱动（`infra/d7_three_hosts.py`）本身，只是多带
`--net-profile` 与 `--sample-resources`：切份额、逐节点打 tar、在 P0 的 VPC
私网地址上起临时取包服务、渲染并签名各自的 manifest、起抓包、起节点；节点
就绪之后装档位、验 `FILTER-OK`、`ping` 对端量往返，然后起采样器与客户端；
客户端结束后回读结果、状态、逐台 TLS 摘要，跑 reveal 扫描与清洁度扫描，覆写
删除份额，`finally` 里停采样器、取回采样文件、拆档位。

档位挂在 `prio bands 3` 之下、命中 `dst 172.27.172.0/24` 的 u32 过滤器上
（`flowid 1:3` 就是 netem 那一条），所以承载驱动自身的控制通道不会被自己掐断；
只作出向整形，但三台都做，于是 MPC 链路两个方向都带上档位。采样器以
`pgrep -f 'd7[_]node'` 定位本次运行的那个 enclave 进程，每 0.5 s 记一次
`/proc/stat`、`/proc/meminfo` 与该进程的 RSS/CPU jiffies，原始样本随包提交
（`d8-resources-p{0,1,2}.jsonl`），报告里的利用率是把相邻两次的累计 ticks
再算一遍得到的，不是采样器自己算好的数。

抓包沿用 D7 的 `tcpdump -i eth0 -s 0 -B 262144`（256 MiB 环），每台只分析
自己那一段；原始 pcap 留在产生它的实例的 `/tmp/` 下，随包文件带上它们的字节数
与 sha256。

第一次把子网算错了：`posixpath.dirname("172.27.172.201")` 把地址当成文件名，
返回空串，过滤器于是渲染成 `dst 0/24`——装得上、`tc` 不报错、一个包也匹配不
到，标着 `wan-40ms` 的那一档实际跑在 LAN 延迟上。现在子网由 `peer_subnet()`
按 IPv4 前三段算出（对端不共用一个 /24 直接报错），装完必须看到 `FILTER-OK`，
量到的往返低于声明延迟的一半就判整档失败。修复之前的尝试没有提交证据。

## 3. 结果

### 3.1 三档对照

| 档位 | 客户端整段 s | 相对 lan | 线上流量 MB（三台合计） | 重传包 | 抓包空洞 | token | 最差 `max_abs_error` | 抓包判决 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `lan` | 16.534 | 1.0 | 3760.1 | 686 | 0 | 3200,3200,3200 | 0.065481 | `tls13_only` |
| `wan-40ms` | 164.21 | 9.93 | 3760.0 | 274 | 0 | 3200,3200,3200 | 0.064989 | `tls13_only` |
| `wan-80ms` | 274.871 | 16.62 | 3760.0 | 136 | 0 | 3200,3200,3200 | 0.065638 | `tls13_only` |

三档的 token 完全相同（也就与 D7 那一束相同：` secret secret secret`），线上
流量完全相同（在工作负载声明的端口上，每台各看到约 1.25 GB，三台合计
3760 MB），变的是时间：把每台出向的 40 ms 变成 80 ms，客户端整段从 164 s
拉到 275 s。重传随档位变慢而减少
（686 → 274 → 136 包），因为发送方被延迟拉长后很少超时重发。

### 3.2 注入延迟与实测往返

| 档位 | 每台注入 (ms) | 实测往返均值 (ms) | 逐台往返均值 (ms) |
| --- | --- | --- | --- |
| `lan` | 未注入 | 未测 | - |
| `wan-40ms` | 40 | 80.16 | P0 80.156 / P1 80.158 / P2 80.155 |
| `wan-80ms` | 80 | 160.15 | P0 160.152 / P1 160.158 / P2 160.153 |

每台每对端 5 个包全部回达、丢包 0。注入是单向的（只整形出向），所以标称
40 ms 的档位量到约 80 ms 往返，标称 80 ms 量到约 160 ms——这正是档位确实
生效的证据，也是驱动判定一个档位算不算跑成的依据。`lan` 不注入，因此也不
ping，它的往返没有被测过，表里留空而不是填 0。

### 3.3 逐步延迟

客户端自报的单步 wall time 与三个节点自报的 `elapsed_ms`（毫秒）：

| 档位 | 步 | 客户端 | P0 | P1 | P2 |
| --- | --- | --- | --- | --- | --- |
| `lan` | 1 | 5380.712 | 5001.217 | 4821.503 | 4860.821 |
| `lan` | 2 | 5285.279 | 4797.575 | 4849.526 | 4895.692 |
| `lan` | 3 | 5219.595 | 4760.427 | 4750.519 | 4783.789 |
| `wan-40ms` | 1 | 56483.730 | 55651.989 | 55354.794 | 55386.909 |
| `wan-40ms` | 2 | 52328.255 | 51777.387 | 51698.689 | 51733.955 |
| `wan-40ms` | 3 | 53259.576 | 52729.178 | 52604.112 | 52618.781 |
| `wan-80ms` | 1 | 93980.034 | 92866.986 | 92293.545 | 92488.097 |
| `wan-80ms` | 2 | 89053.249 | 88384.290 | 88181.358 | 88218.500 |
| `wan-80ms` | 3 | 88083.096 | 87429.214 | 87177.856 | 87198.108 |

同一步里三个节点的耗时彼此相差最多 3.7%（`lan` 第 1 步：4821.5 对 5001.2 ms），
两档 WAN 都在 1% 以内，三台是同步推进的。客户端自报的单步比最慢的节点多
0.4~1.1 s，这一段落在客户端自己那侧（结果帧重建、Argmax 比对与提交），本次
没有把它再拆细。档位变慢后单步被延迟主导：节点自报的单步从约 4.8 s 变成约
88~93 s。

### 3.4 宿主资源

采样窗口：`lan` 三台 28.01/25.26/23.21 s（46~55 个样本），`wan-40ms`
177.29/174.86/172.15 s（337~347 个样本），`wan-80ms` 287.25/286.68/284.64 s
（557~562 个样本）。CPU 利用率是宿主整体（`/proc/stat`）的忙占比。

| 档位 | 角色 | 样本 | CPU 均值 % | CPU 峰值 % | enclave RSS 峰值 MB | enclave CPU 秒 | 可用内存最低 MB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `lan` | P0 | 55 | 30.93 | 65.71 | 16.4 | 49.88 | 6273 |
| `lan` | P1 | 50 | 28.92 | 65.40 | 16.6 | 50.22 | 6470 |
| `lan` | P2 | 46 | 30.87 | 64.53 | 16.3 | 48.68 | 6500 |
| `wan-40ms` | P0 | 347 | 7.62 | 33.17 | 16.3 | 62.52 | 6263 |
| `wan-40ms` | P1 | 342 | 7.49 | 48.53 | 16.5 | 67.16 | 6452 |
| `wan-40ms` | P2 | 337 | 7.66 | 46.08 | 16.4 | 65.88 | 6477 |
| `wan-80ms` | P0 | 562 | 5.99 | 35.78 | 16.5 | 72.81 | 6246 |
| `wan-80ms` | P1 | 561 | 5.23 | 30.73 | 16.6 | 71.34 | 6450 |
| `wan-80ms` | P2 | 557 | 5.10 | 28.64 | 16.3 | 69.38 | 6469 |

CPU 均值从 `lan` 的约 29~31% 掉到 `wan-80ms` 的约 5~6%，因为宿主大部分时间在
等网络，被 `/proc/stat` 计成空闲；同一段窗口里 enclave 自己的 CPU 秒并没有
减少，反而从约 49~50 s 升到约 69~73 s。三台上的 enclave 进程各自只占约
16~17 MB 常驻内存，7.5 GB 内存里始终留着至少约 6.25 GB 可用。

EPC 只报到段大小（`0x240000000-0x42fffffff`，8 GB），这是内核 ring buffer
里能读到的那个数；本内核没有给每进程 EPC 常驻量的计数文件，报告里因此**没有**
EPC 占用这一列，而不是填一个估计值。

### 3.5 正确性与安全回归（三档都保持）

| 项 | `lan` | `wan-40ms` | `wan-80ms` |
| --- | --- | --- | --- |
| 生成 token | `[3200,3200,3200]` | 同左 | 同左 |
| 与浮点参考的 token 一致 | 3/3 | 3/3 | 3/3 |
| 安全 Argmax 与客户端重建 Argmax 一致 | 3/3 | 3/3 | 3/3 |
| 五类篡改/重放负例全部被拒 | `True` | `True` | `True` |
| 清洁度扫描 | `clean` | `clean` | `clean` |
| 三份抓包 `tls13_only`、非 TLS 字节 0 | `True` | `True` | `True` |
| 节点释放 | `True` | `True` | `True` |
| 整档判决 | `passed` | `passed` | `passed` |

- 五类负例（重复结果帧、篡改 `decode_step`、混用模型 manifest、重放输入帧、
  重放 JobTicket）在每档里都被拒，且与 D7 一样只落在 P1 上（重放帧与重放票据
  都发给它），`refusals` 里两条理由逐字相同。
- 每档生成的都是 ` secret secret secret`，与 D7 那一束逐 token 相同。
- 节点侧的 `shutdown` 三台都回 `{"released": true, "reply": "bye"}`，
  `teardown_finished` 全为 `True`。

### 3.6 会话清理、清洁度与抓包

九次节点运行（3 档 × 3 台）的 close 证据完全一致：

| 项 | 值 |
| --- | --- |
| `closed` / `session_dir_removed` | `True` / `True` |
| 溢写文件数 / 覆写字节 | 3 / 196839 |
| 会话密钥清零字节 | 80 |
| KV `buffers` / `entries` / `all_zero` / `unscrubbed` | 3 / 0 / `True` / `[]` |

close 之前的采样快照：`wan-40ms` 与 `wan-80ms` 各是 3 个文件、196839 字节
（三台各一份 `kv/step-0001.share`）；`lan` 那一档的采样点只赶上 2 个文件、
131226 字节，P0 的溢写还没落盘——这是采样时刻的问题，节点自己的 close 证据
在九次运行里都是 3 个文件、196839 字节。close 之后快照都是 0 文件 0 字节，
会话目录不存在。

清洁度扫描以本次运行发布过的 18 个 share 前缀为探针，搜 `/dev/shm` 会话根、
`/tmp`、workspace、`/var/log`、journal 与各进程的命令行/环境；九次运行全部
`verdict: clean`、`findings: 0`。staged 份额跑完由驱动覆写后删除：`lan` 每台
覆写 92542265 字节，两档 WAN 每台 92542270 字节，`share_present=no`、
`large_json_left: []`、`staging_scrub ... verdict: clean`。

抓包逐台统计（每台只分析自己那一段；三台的判决都是 `tls13_only`，
`non_tls_payload_bytes` 全为 0，空洞全为 0）：

| 档位 | 角色 | 线上字节 | 期望端口报文 | TLS 1.3 流 | 应用数据记录 | 重传包 | 原始 pcap 字节 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `lan` | P0 | 1254135872 | 133239 | 11 | 228870 | 225 | 1265064218 |
| `lan` | P1 | 1253057446 | 130776 | 8 | 228806 | 218 | 1263783738 |
| `lan` | P2 | 1252878410 | 130211 | 7 | 228748 | 243 | 1263558672 |
| `wan-40ms` | P0 | 1254111079 | 393427 | 11 | 228761 | 90 | 1286373173 |
| `wan-40ms` | P1 | 1253044924 | 417661 | 8 | 228866 | 88 | 1287294202 |
| `wan-40ms` | P2 | 1252857671 | 415818 | 7 | 228697 | 96 | 1286955919 |
| `wan-80ms` | P0 | 1254116650 | 527152 | 11 | 229097 | 50 | 1297343718 |
| `wan-80ms` | P1 | 1253035156 | 488555 | 8 | 229028 | 47 | 1293097254 |
| `wan-80ms` | P2 | 1252853988 | 509159 | 7 | 228985 | 39 | 1294605514 |

线上字节三档几乎不变（每台 1.25 GB），报文数却随档位上升（lan 13 万 →
wan-80ms 51 万），因为延迟拉长后同一个连接用更多的小报文推进。九份原始 pcap
共约 11.5 GB，留在产生它的实例的 `/tmp/` 下；随包的每份 `<档位>/d7-summary.json`
在 `captures` 里记下各台的字节数与 sha256。验收完成后这些 pcap 已从三台实例
上删除（见第 4 节）。

### 3.7 enclave 测量值

九次节点运行各自签名自己真正加载的那棵树，所以测量值互不相同（`distinct
measurements: 3`，每档如此）；三棵树持有不同份额，这是设计使然，与 D4/D7
同一情形。`sgx.enclave_size = 4G`、`sgx.max_threads = 64`、栈 2M、
模板 `d7_node.manifest.template`、启动器
`gramine-sgx /home/jiahao/a122-enclave/d8-enclave-profiles-20261014T1056Z-<档位>/d7_node`。

| 档位 | 角色 | MRENCLAVE | `d7-enclave.manifest` sha256 |
| --- | --- | --- | --- |
| `lan` | P0 | `38a01d93cccbf60daa3591d60400a4c92278fc91be4269aa8cfad6c745381f32` | `69c20a7bf890e2657921077420ffab61819ec647ce9266215be124aea8cdb2b0` |
| `lan` | P1 | `84b46cb06fb802e33bbe85c52dd303fa346ad9deda1946dee0772004f7ba1eda` | `cef709077893ad796928666c6f0fba850c3d8f2b4df8556a57f39fffe0421950` |
| `lan` | P2 | `256fee7a2e397e552b4745d5090ddcfbd17125a69232541597b5c3fc7dd3f839` | `de7e3e56950a14fdaf07d39c7a94b57630f348c33531bbcb688868eefa81fe57` |
| `wan-40ms` | P0 | `5bb2f08d0af3c03244455c82af03cc620e4e94faf2c2e496f4250f0fee4bd473` | `f005e7b893e8c4b7b615600238e785ee90dddf9def0fb4da7f8a5d849ba62317` |
| `wan-40ms` | P1 | `bdc098288f75f80382edeb54723972100b951dfbae454504f607c8f88f7ec428` | `ee98ea92d6445128df652534cf7e7a3d573c58a5948d86963f279572bfb33c3d` |
| `wan-40ms` | P2 | `33f08a0baf21fe9e72e3f5f98ac81d418f6cf7e79f432594d3411295a4e739b7` | `971bf33561b73867c90a2577fbdd97ff8597461a57b5c92255d327833e81ec5c` |
| `wan-80ms` | P0 | `d52ac0c74abc1994fbb0534ff569b795b685ea64e7955b81f82127c807497d53` | `ccd182d7bb029f4b6c7baa4438e5f6a58a95cf587d9d6fae9b44b96577d6401b` |
| `wan-80ms` | P1 | `bbdddb161fe4c7a0db4dc125342903541df472dec7aa87cd0ad5cd1a55d9cfb7` | `5fd0ddf79b9fdc4be4e9fb75c22b282a9a3f219a09b52412a8bb0b3549b9615c` |
| `wan-80ms` | P2 | `42e321af9fba53fef0a8d40e890abb296b2850f6b57f5437e9de52c4f8377c22` | `01e0de5df5b0c60a2524f04696746c60c42ae4954407725addf8ea73dbbad2ea` |

节点没有读取 `/dev/attestation/quote`，本文不据此声明任何 attestation 结论；
证书仍来自本次运行的本地 PKI，与 D4 第 7 节第 1 项同一条缺口。

## 4. 证据位置与复算

[docs/evidence/d8-enclave-profiles-20261014T1056Z](evidence/d8-enclave-profiles-20261014T1056Z)
共 81 个索引条目：顶层是摘要 `d8-enclave-profiles-20261014T1056Z-summary.json`、
报告 `d8-report.md`、运行说明 `README.md`，下面三档各 26 个文件
（`d7-summary.json`、`d7-client-result.json`、`d7-client.log`、
`d7-three-p{0,1,2}-node-status.json`、`d7-three-p{0,1,2}-node.log`、
`d7-three-P{0,1,2}-tls-summary.txt`、`d7-hygiene-p{0,1,2}.json`、
`d7-stage.json`、`d7-enclave-p{0,1,2}-sign.txt`、`d7-enclave.manifest`、
本档新增的 `d8-platform-p{0,1,2}.json` 与 `d8-resources-p{0,1,2}.jsonl`），
外加 `evidence-index.json` 与 `evidence.sha256`。九份原始 pcap 不在包里，
它们的字节数与 sha256 记在各档 `d7-summary.json` 的 `captures` 里。

摘要、报告与 README 都不是手写的：它们是同一遍从三档目录读回来的产物，所以
可以原地重算而不需要再上服务器——

```bash
python -m infra.d8_three_hosts \
  --out-dir docs/evidence/d8-enclave-profiles-20261014T1056Z \
  --run-id d8-enclave-profiles-20261014T1056Z \
  --expect-commit df01452ef187a5bcf223dd082afce511508a7579 --rebuild
```

`--rebuild` 的表里每个数字都来自 profile 目录里的 trace；它的时间戳取自 trace
本身（本包是最后一档的完成时刻 2026-10-14T11:12:14Z），所以连跑两次得到的是
逐字节相同的三个文件。本包封存后按上面的命令重算过，三个文件的 sha256 不变：

| 文件 | sha256 |
| --- | --- |
| `d8-enclave-profiles-20261014T1056Z-summary.json` | `c217c727793088bcc14610e87db846e20b8c3ddf6d23331f3e1a8df12e570054` |
| `d8-report.md` | `4e3c0d914c875c5adfe5d8cf9f989040da74c9cc8d61b9ae8e29ccdcf4ae6139` |
| `README.md` | `d86a9ed6569e1d4aa3be9f9eaee150abd64d16208475e9bedc2ccf930658f98c` |

重建时若某档 trace 记的提交与 `--expect-commit` 给的不一致，`--rebuild`
会直接报错，而不是盖上被要求的那个提交号。

本地复验：`python -m pytest tests/unit -q` 全绿，其中
`tests/unit/test_evidence_bundles.py` 校验本目录的索引、seal、LF 行尾与
"不含 PEM 私钥材料"。

验收完成后三台实例上做过清理：删除 `/tmp/` 下本次与冒烟运行的 4 份 pcap
（每台约 4.9 GB）、删除 `/dev/shm/a122-d7/*` 残留会话根、确认
`~/a122-d7/three/workspace/shares/` 为空、`~/a122-d7/dist` 不存在、
`tc qdisc show dev eth0` 只剩 `mq` 根（netem/prio 已拆），三台都不再有任何
份额大小的 JSON。实例本身的停机/释放属 D10 流程，按
[d10-release-acceptance.md](d10-release-acceptance.md) 由控制台执行。

## 5. 尚未覆盖

以下内容未被本次运行证明，不得按已通过计：

1. **没有开/关消融。** D7 冻结的程序没有软近似或量化的运行时开关，"打开/关闭
   softmax/GELU/rsqrt 近似"需要第二个冻结程序与第二组份额，本次没有做。因此
   验收门里"每项优化都有同条件对照"这一条**没有达成**；本次能证明的是同一份
   程序在半 LAN、40 ms、80 ms 三档下的时间、资源与安全判决。
2. **没有每进程 EPC 常驻量。** 本内核只暴露 EPC 段大小，`/proc` 里没有
   per-process 的 EPC 计数，报告里也就没有这一列。EPC 预算是本项目几何选择的
   依据，但本次没有重新量它。
3. **长度桶与 batch 未覆盖。** 1 层探针几何固定了窗口 8 与单条请求，长度分桶、
   批处理与更大的 prompt 都没有跑。
4. **档位不是链路仿真。** 延迟与速率由 `tc netem` 注入在对端子网上，往返来自
   本次运行自己的 `ping`，不是链路模型；丢包/抖动/乱序没有被注入。
5. **最差误差在三档之间小幅浮动**（0.064989~0.065638；D7 单次为 0.065001）。
   本次没有做重复运行去分离这个浮动的来源，能证明的是三档的 token 与 Argmax
   都与浮点参考一致。D7 的逐步误差本来就在 0.0609~0.0650 之间变化，同一量级。
6. **三份测量值不同是按设计如此**，不是缺陷；单一 MRENCLAVE 的形态见 D4 的
   staged 树流程。开发档的 Gramine 配置（`loader.log_level`、
   `loader.insecure__use_cmdline_argv`、`sgx.allowed_files`）与 D7 同一份模板，
   属当前开发配置。

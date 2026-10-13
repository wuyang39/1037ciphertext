# D4 三节点通信与 3PC RSS 验收记录

> 运行编号：单实例 `d4-20261012T143111Z`（提交 `d048827`），三实例正向
> `d4-3host-20261012T152216Z`（提交 `bcd8935`），三实例 fail-closed 负例
> `d4-negs-3host-20261012T154315Z`（提交 `a2d8026`）；后两次都由
> `infra.d4_three_hosts` 一条命令驱动。把三个节点放进 `gramine-sgx` 的复跑是
> 单实例 `d4-enclave-20261013T0530Z`（提交 `560deff`）、三实例正向
> `d4-enclave-3host-20261013T052121Z` 与三实例负例
> `d4-enclave-negs-3host-20261013T052407Z`（提交 `63937a0`）。
>
> 结论：**D4 传输层与算子网格通过，已在三台独立实例上复跑，三个 SPU 参与方
> 也已在 `gramine-sgx` enclave 内跑完整套流程**。1,024 组向量全部与固定点
> 参考一致，协议端口上的抓包只出现 TLS 1.3 记录，明文/证书/关闭 TLS 四类
> fail-closed 场景在 loopback、跨 VPC、enclave 三种形态下都拒绝。
>
> 范围限定：证书来自本次运行的本地 PKI，不是真实 attestation 放行的短期
> 身份；三实例 enclave 运行时每台实例各自签署自己的 manifest，因此三份
> 测量值互不相同（见 4.8）。见第 7 节。

本记录对应 [后续开发总计划.md](后续开发总计划.md) 第 7 节。

## 1. 验收环境

单实例运行在三台机器中的 SGX2 上，三实例运行把 P0/P1/P2 分到三台，并且在
每台上各自启动一个节点进程：

| 角色 | 实例 | 私网 | 公网（2026-10-13 重启后） | 单实例运行主机 |
| --- | --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ`（SGX1） | `172.27.172.201` | `106.14.207.224` | - |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z`（SGX2） | `172.27.172.202` | `47.117.34.67` | 2026-10-12 的单实例主机 |
| P2 | `iZuf6bd6qnhgtveg5khygdZ`（SGX3） | `172.27.172.203` | `47.116.200.143` | 2026-10-13 的单实例 enclave 主机 |

三台实例在 2026-10-13 重启后拿到新的弹性地址，`47.116.200.143` 从 P0 换到
了 P2，P0 变成 `106.14.207.224`。私网地址没有变，所以节点组成的 mesh 与
2026-10-12 的两次运行完全一致；上表里的公网地址只在 SSH 进实例时使用。

三台实例的软件环境一致：

| 项目 | 实测值 |
| --- | --- |
| 系统 | Ubuntu 22.04.5，内核 `5.15.0-191-generic` |
| CPU | Intel Xeon Platinum 8369B @ 2.70GHz，4 vCPU |
| SGX | `/dev/sgx_enclave`、`/dev/sgx_provision` 存在，`aesmd` active |
| Python | 3.11.17（`~/a122-venv311`） |
| SPU | `spu` 0.9.5（真实 YACL/BRPC C++ 后端，`spu/libspu.so`） |
| 其他库 | `cryptography` 48.0.1、`gmssl` 3.2.2、`pydantic` 2.14.1、`jsonschema` 4.26.0 |
| OpenSSL | 3.0.2 |
| 抓包 | tcpdump 4.99.1（`cap_net_raw,cap_net_admin`） |
| 单实例运行时长 | 14:31:11Z 起，14:32:19Z 写出 `d4-summary.json`，约 68 秒 |
| 三实例运行时长 | 15:22:16Z 起，15:23Z 封存，约 2 分钟（含三份抓包各自解析） |
| 三实例链路建立 | P0 2.882 s、P1 5.338 s、P2 4.146 s（BRPC 建连跨主机） |
| 单实例 enclave 运行 | 12:47Z 起，12:51Z 封存，约 4 分钟（三个进程各起一次 enclave） |
| 三实例 enclave 运行 | 05:21:21Z 起，05:23:14Z 封存；链路建立 P0 5.411 s |
| 三实例 enclave 负例 | 05:24:07Z 起，05:27:41Z 封存；四个场景逐个起停 enclave |
| enclave 参数 | `sgx.debug=false`，`sgx.remote_attestation="dcap"`，4 GB / 64 线程 / 2 MB 栈 |

## 2. 使用的工具

- [deploy/run_d4_accept.sh](../deploy/run_d4_accept.sh)：单实例运行的唯一入口，
  负责建工作区、跑网格与负例、抓包并封存证据。
- [infra/d4_acceptance.py](../infra/d4_acceptance.py)：`provision`、`loopback`
  与 `evidence` 三种模式，含明文探针与负例驱动。
- [infra/d4_workspace.py](../infra/d4_workspace.py)：证书、向量网格和九个节点
  配置（三个正常 + 四个负例）。
- [infra/d4_pki.py](../infra/d4_pki.py)：复用 `kas.ca.CertificateAuthority`
  签发 P0/P1/P2 证书，并生成"错误 CA""错误 SAN"的负例材料。
- [tee/enclave/spu_node.py](../tee/enclave/spu_node.py)：P0/P1/P2 节点进程，
  建立 BRPC 链路、执行网格并写出 `node-status.json`。
- [mpc/spu_backend](../mpc/spu_backend)：YACL/BRPC 传输与 mTLS 策略。
- [infra/pcap_tls.py](../infra/pcap_tls.py)：无 tshark 依赖的 pcap 解析器，
  重组 TCP 流并走 TLS 记录层；`python -m infra.pcap_tls` 可在任一台实例上
  只用自己的抓包复算判决。
- [infra/d4_evidence.py](../infra/d4_evidence.py)：证据装配、跨机封存与哈希。
- [infra/d4_three_hosts.py](../infra/d4_three_hosts.py)：三实例运行的操作机
  入口。校验每台实例的提交、发工作区、三台各自抓包与起节点、等驱动节点完成、
  收回各角色的摘要与状态，并调用 `finalise_cross_host` 封存；`negatives`
  子命令在同样三台上驱动 4.6 节的 fail-closed 负例。
- [deploy/run_d4_three_hosts.sh](../deploy/run_d4_three_hosts.sh)：上一个入口的
  脚本化包装，读 `deploy/d4-three-hosts.json` 作为集群描述；`MODE=negatives`
  切到跨机 fail-closed 负例。

## 3. 流程

单实例运行（`run_d4_accept.sh`）：

1. `--mode provision` 生成 KAS CA、三张角色证书、1,024 组向量和九个节点配置。
2. `tcpdump -i any` 开始抓取六个协议端口（BRPC `47100-47102`、share 通道
   `47200-47202`）。
3. 启动 P1、P2，等它们打出 ready 标记；此时 BRPC 链路已在进程内建立。
4. 对每个监听端口发一次 23 字节明文探针，记录拒绝方式。
5. 启动 P0，驱动 16 个批次共 1,024 组 RSS 向量，逐批与固定点参考比对。
6. 停止抓包，依次跑四个 fail-closed 负例，每一步都要求子进程非零退出。
7. 解析抓包、写入 `tls-summary.txt`，装配并封存证据目录。

三实例运行（`python -m infra.d4_three_hosts run`，操作机上一条命令）：

1. 读集群描述，逐台 `git rev-parse HEAD` 校验三台都在本次提交上，不一致就
   直接停下，不产生证据。
2. 在 P0 上 `--mode provision` 生成本次工作区，打成 tar；P1/P2 解到**同一
   绝对路径**下，三份工作区逐字节同源。
3. 三台各自 `tcpdump -i eth0` 抓六个协议端口，每份抓包都留在本机 `/tmp`。
4. 先启动 P1、P2，再启动 P0；每个进程读自己那份配置里的私网地址，链路因此
   跨越 VPC 私网而不是 loopback。
5. 等 P0 打出完成标记，停三份抓包；每个角色各自解析本机抓包，得出一份带
   本机摘要头的 TLS 摘要。
6. 逐个角色等它对端写完 `node-status.json` 再取回，连同节点日志、向量结果和
   通信 trace 收进同一个目录，做跨机证书互校、封存索引与排除清单。

跨机 fail-closed 负例（`python -m infra.d4_three_hosts negatives`，同样一条
命令）：先只起 P1、P2，它们各自开出两个监听端口后等其余 mesh，端口因此
处于"已监听、无业务"状态；操作机从 P0 向四个端口发明文探针（探针不参与
网格，也就不会和向量比速度）。随后每个负例在 P0 用前台子进程跑一份变异配置，
取真实退出状态，P1/P2 各自在本机跑严格配置并各自记录日志，逐步之间
`pkill` 清空节点进程。

## 4. 结果

### 4.1 正向网格

| 项目 | 单实例 | 三实例 |
| --- | --- | --- |
| 向量数 | 1024（16 批 × 64） | 1024（16 批 × 64） |
| 通过 / 失败 | **1024 / 0** | **1024 / 0** |
| 算子 | `add`、`mul`、`matmul`、`truncate`、`compare`、`reciprocal` | 同左 |
| 网格摘要 | `96b6c83502203292840fd9836f0efbe6f5fe49225aa5b110a6f2b3c27f3695d5` | 同左 |
| P0 / P1 / P2 状态 | `passed` / `served`（16 批）/ `served`（16 批） | 同左 |
| 链路建立耗时 | P1 4.147 s，P2 3.986 s | P0 2.882 s，P1 5.338 s，P2 4.146 s |
| teardown | 三个节点均 `teardown_finished: true` | 同左 |

两次运行的网格摘要完全相同，说明向量生成与算子结果在 loopback 和跨机两种
拓扑下可重复；三实例的链路建立更慢，是 TCP 建连与重试跨主机所致。

### 4.2 抓包结论

单实例（loopback，一份抓包，108,760 个报文）：

| 项目 | 结果 |
| --- | --- |
| 六个协议端口上的报文 | 108760 |
| TCP 流 | 94 |
| TLS 1.3 流 | 41 |
| TLS 1.2 或更低 | 0 |
| TLS 会话 | 47（其中 TLS 1.3 41） |
| application_data 记录 | 184263 |
| 握手消息 | 96 |
| 无法解释的非 TLS 字节 | **0** |
| 判决 | `tls13_only` |

三实例（每台一份抓包，各自只看到自己那两条私网链路）：

| 角色 | 报文 | TCP 流 | TLS 1.3 流 | TLS 1.2 或更低 | 会话 | 握手消息 | application_data | 非 TLS 字节 | 判决 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P0 | 71278 | 96 | 42 | 0 | 48 | 96 | 123098 | 0 | `tls13_only` |
| P1 | 70360 | 52 | 23 | 0 | 26 | 56 | 122766 | 0 | `tls13_only` |
| P2 | 70271 | 52 | 23 | 0 | 26 | 56 | 122776 | 0 | `tls13_only` |

三份抓包合起来覆盖完整三角：P0 看到 P0↔P1 与 P0↔P2，P1 看到 P1↔P0 与
P1↔P2，P2 看到 P2↔P0 与 P2↔P1。没有任何一份出现低于 TLS 1.3 的流量。

单实例抓包里另有 46 字节非 TLS 载荷，全部来自第 3.4 步的**故意明文探针**
（23 字节的 `A1-22-PLAINTEXT-PROBE\r\n`，出现两次）。解析器按"探针端点 +
探针标记"把这几字节单独记为 `expected_probe_bytes`，只有无法归属的明文
才会让判决失败。三实例运行没有发探针，因此三份抓包的非 TLS 字节都是 0。

### 4.3 fail-closed 场景

四个负例在单实例运行中执行，跨机复跑见 4.6：

| 场景 | 结果 | 拒绝理由（节点原始输出） | 耗时 |
| --- | --- | --- | --- |
| 明文探针 | **refused** | 四个监听端口无一处给出明文业务应答：`47101` 与 `47102` 为 `closed_or_tls_only`，`47201` 为 `connection_reset`，`47202` 为 `connection_refused` | - |
| `wrong-ca` | **refused** | `peer P2 certificate was not signed by the KAS CA` | 0.214 s |
| `wrong-san` | **refused** | `peer P2 certificate SAN does not match its role` | 0.214 s |
| `no-client-cert` | **refused** | `the BRPC link could not be established`（P0/P1/P2 三方一致拒绝） | 57.183 s |
| `tls-disabled` | **refused** | `the SPU link must not run without TLS`，进程直接退出、不回退 | 0.214 s |

四个证书/TLS 负例的退出状态均为 3，没有任何一个降级为明文或跳过校验。

### 4.4 材料一次性消费

三个角色的预处理材料各消费一次后 `remaining=0`，第二次申领被拒绝
（`denied: material is not available: consumed`），`one_time_consumption: true`。

### 4.5 三实例的证书互校

每个角色的 `node-status.json` 记下自己对两个对端的证书摘要，跨三份文件比对
后 6/6 一致：P0/P1/P2 的 `identity_sha256` 分别等于另外两方记录的
`peer_certificates` 值。也就是说 mesh 的每一条边都认证到同一个身份集合，
不存在某一方看到"另一张证书"的情况。

### 4.6 跨机 fail-closed 复跑

负例在跨 VPC 的三角上重跑一次（`d4-negs-3host-20261012T154315Z`，提交
`a2d8026`）。与单实例不同的是，变异方是操作机上的 P0，严格方 P1/P2 分立
在自己的实例上，所以每一次拒绝都跨过私网而不是 loopback：

| 场景 | 结果 | 拒绝理由（节点原始输出） | 耗时 |
| --- | --- | --- | --- |
| `wrong-ca` | **refused** | `peer P2 certificate was not signed by the KAS CA` | 0.672 s |
| `wrong-san` | **refused** | `peer P2 certificate SAN does not match its role` | 0.688 s |
| `no-client-cert` | **refused** | `the BRPC link could not be established`（P1 日志逐次 `SSL routines::peer did not return a certificate`，P1/P2 各自也报链路失败） | 57.406 s |
| `tls-disabled` | **refused** | `the SPU link must not run without TLS`，进程直接退出 | 0.640 s |

四个负例退出状态均为 3，`all_refused: true`、`unexpected_cases: []`。`wrong-ca`
与 `wrong-san` 在 0.7 秒内就否决，说明双方在校验阶段即中止握手，没有把链路
拖到超时。

明文探针只在 P1/P2 两个严格对端上发，操作机从 P0 连过去，四个监听端口全部
`connected: true`（`all_listeners_connected: true`），但没有一个给出业务应答
（`any_plaintext_service: false`）：

| 监听 | 结果 |
| --- | --- |
| `172.27.172.202:47101`（P1 BRPC） | connected，`no_plaintext_reply` |
| `172.27.172.202:47201`（P1 share） | connected，`connection_reset` |
| `172.27.172.203:47102`（P2 BRPC） | connected，`no_plaintext_reply` |
| `172.27.172.203:47202`（P2 share） | connected，`connection_reset` |

端口确实在监听（所以探针能建 TCP），只是不接受明文——这与 4.3 节单实例的
结论一致，区别是这次连的是私网地址。

### 4.7 单实例：三个节点在 `gramine-sgx` 内执行

`deploy/run_d4_gramine.sh` 把 loopback 模式接上一个 `--node-wrapper`：先渲染
并签名一个 manifest，再用 `gramine-sgx <manifest>` 替换原来直接启动解释器的
位置，于是 P0/P1/P2 三个进程各自在自己的 enclave 里起来，共享同一个测量值。

| 项目 | 取值 |
| --- | --- |
| 入口 | uv 装的解释器真实路径，`PYTHONPATH` 指向仓库与 site-packages |
| SGX 参数 | `sgx.debug=false`、`sgx.remote_attestation="dcap"`、4 GB / 64 线程 / 2 MB 栈 |
| 受信文件 | 解释器、`gramine.runtimedir()`、`/lib/x86_64-linux-gnu`、`/usr/lib/x86_64-linux-gnu`、uv 解释器目录、site-packages、仓库、工作区 |
| MRENCLAVE | `b28084fe356bb41100fbb45d0223ec703881334937da9e7568cbcc1e6445e4d4` |

| 项目 | 结果 |
| --- | --- |
| `rss_vectors` | passed，1024/1024，网格摘要 `96b6c83502203292840fd9836f0efbe6f5fe49225aa5b110a6f2b3c27f3695d5` |
| 四个 fail-closed 场景 | 全部 `refused` |
| `one_time_consumption` | true |
| `runtime.inside_enclave` | **true**，`transport` 为 `SPU/YACL/BRPC over TLS 1.3 inside a Gramine-SGX enclave` |
| 抓包判决 | `tls13_only`：45 条 TLS 1.3 流、0 条 TLS 1.2 或更低、非 TLS 载荷 0 字节 |
| 报文 | 六个协议端口 110824 个报文、184339 条 application_data；重传 156 个报文 / 79200 字节按序号去重，乱序 0、空洞 0、无法重组 0 |

抓包这次改为**按 TCP 序号重组**（`infra/pcap_tls.py`）。loopback 上会出现重传，
按抓包顺序直接拼接会把密文字节错位成假的明文；现在重传先按序号去重、乱序先
入队再按序号交付，`capture_complete` 与 `unreassembled_bytes` 和判决一起记录，
所以"非 TLS 字节为 0"是重组后的结论，而不是拼接顺序的巧合。

### 4.8 三实例：三个节点各自在 enclave 内执行

`infra.d4_three_hosts run --enclave-template ...` 在把工作区分发到三台之后，
在每台实例上分别渲染并签名 manifest（签名密钥在 P0 上生成后分发给另外两台，
保证三方用同一个签名者），再用 `gramine-sgx` 启动各自的节点：

| 项目 | 结果 |
| --- | --- |
| `rss_vectors` | 1024/1024，网格摘要 `96b6c83502203292840fd9836f0efbe6f5fe49225aa5b110a6f2b3c27f3695d5` |
| 角色判决 | P0 `passed`，P1/P2 各 `served` 16 批 |
| `runtime` | `inside_enclave: true`、`attestation_available: true`、链路建立 5.411 s、份额 706252 字节 |
| 证书互校 | 6/6 一致，`peer_certificates_match: true` |
| teardown | 三个角色均 `teardown_finished: true` |
| 抓包 | 三份各自 `tls13_only`，非 TLS 字节均为 0；TLS 1.3 流 P0 42、P1 23、P2 23 |

**三份测量值互不相同**，因为 Gramine 把整棵受信目录算进测量，而三台实例的
checkout、venv 与解释器目录并不是逐字节相同的树：

| 角色 | MRENCLAVE |
| --- | --- |
| P0 | `4726519aaaed3cddc14d702e3bbddcb286928e4a017770873e022a19ba3ed58a` |
| P1 | `1a28fc08a86bbbfbb2314b0caa284b03435d560372d227f6dfd55a1d58c3a61f` |
| P2 | `e398551a9dcde72cf1b41793c94014a86f1b29ab02cbf2206fcc72536e09ebcd` |

差别不来自代码：三台都在同一提交、`git status` 干净（runner 会先核对提交，
不干净就拒绝启动），差别来自 `.git` 的抓取历史、`__pycache__` 这类只在被
导入过的解释器目录里出现的文件。要三方共享同一个测量值，需要先把代码和运行
环境做成同一份 staged 树——单实例运行里三个进程共享一棵树，因此共享一个
测量值（4.7）。

负例同样在 enclave 内复跑（`d4-enclave-negs-3host-20261013T052407Z`）：

| 场景 | 结果 | 拒绝理由（节点原始输出） | 耗时 |
| --- | --- | --- | --- |
| `wrong-ca` | **refused** | `peer P2 certificate was not signed by the KAS CA` | 8.06 s |
| `wrong-san` | **refused** | `peer P2 certificate SAN does not match its role` | 8.25 s |
| `no-client-cert` | **refused** | `the BRPC link could not be established` | 76.17 s |
| `tls-disabled` | **refused** | `the SPU link must not run without TLS` | 8.06 s |

四个场景退出状态均为 3，`all_refused: true`，`unexpected_cases: []`。明文探针
仍只打到 P1/P2 的监听端口：四个端口全部 `connected: true`，没有一处给出明文
业务应答（`any_plaintext_service: false`）。

## 5. 关键值

| 项目 | 值 |
| --- | --- |
| 单实例节点证书 P0 | sha256 `1c4ed3b2c2caad70bd7acc603e80fa3716493500d0b145323e36e627d2f42b79` |
| 单实例节点证书 P1 | sha256 `d44739a89f6fc2e85e62f4951b885e3e1b1e5a3d3a426dc696e0d673262a6659` |
| 单实例节点证书 P2 | sha256 `0a1629ee201652d4b2fc3a05dfc8d2d5de638f90f99a01f3802b5c170a8a798a` |
| 三实例身份摘要 P0 | sha256 `bc1ab72602644fbd3779dfc2a537485b3e5b66931874560ac83cc96ea83a2c6f` |
| 三实例身份摘要 P1 | sha256 `04d383c1d26f16e7394b22246d97225141b9d3b2ccddb4f1e7ec38d72acd6188` |
| 三实例身份摘要 P2 | sha256 `b698f3a4b9a111f8999f0bad68640239b8a893d19113fc19526f56c79c5320f6` |
| 三实例 P0 批次份额摘要 | sha256 `3518f52e68f20eb51a410b31ab8bc69343d77f11f4ebaed048c0b3d6fb5530c5` |
| 单实例 `tls-pcap.pcap` | 216264133 字节，sha256 `f0b06cbcb38bd7afe92ec466d0b1c318bf8ee16e93f314414f508d2ef114fbd5` |
| 三实例 `d4-three-P0.pcap` | 144817498 字节，sha256 `1d62c96516c56c62bf2881892ae23dd2632efa465b137beb4a09f23ce08120e5` |
| 三实例 `d4-three-P1.pcap` | 143226938 字节，sha256 `6fe69e52756137608bdc43924e3ffc69ca26df7581ffba9041c40ac4a260d549` |
| 三实例 `d4-three-P2.pcap` | 143216390 字节，sha256 `9739bb92af40cc06cc3836023bd6a90fcdf57207fcd8f5417eab0cfd16cff9b8` |
| 单实例 evidence-index.json | sha256 `e01ecec23b29c735ee1873cb9d1e3aeabebdd7f21c86cdafc01ec46e9f353c7e` |
| 三实例 evidence-index.json | sha256 `f793c120dfd1ccb646eff2f9e0ee35deabdc90f3ac42ef37422a4d567268f2c5` |
| 三实例负例 evidence-index.json | sha256 `32b0d1c569aabe9044571e45d70afc1ed77625d3bc55bcf22b048a2692b0cc61` |
| 单实例 enclave MRENCLAVE | `b28084fe356bb41100fbb45d0223ec703881334937da9e7568cbcc1e6445e4d4` |
| 单实例 enclave manifest | 3104399 字节，sha256 `f041aa69055a30f83803a52dd9229ef34e6d7c84ab89e70b55748e039426a950` |
| 单实例 enclave `tls-pcap.pcap` | 216779569 字节，sha256 `4f770345cae217bce61e109115460936522a9263dfc759c6ca723c5a01ffd2bc` |
| 单实例 enclave evidence-index.json | sha256 `276cc7f7e27cbe1dadf6a9b4a9cce728c1ec19e911ca2527d6d7e07b23f806b9` |
| 三实例 enclave `d4-three-summary.json` | sha256 `e72dd76606584bf7f1ee7b86974f897757c0f3859268e393bfc5125c34da8f0c` |
| 三实例 enclave manifest | 3175308 字节，sha256 `50261815b81b7891b07ec0fc73ef369a46d643ff2ecc27ef269ca188d3851cfa`（P0 那份） |
| 三实例 enclave `d4-three-P0.pcap` | 145054142 字节，sha256 `e20b6898c82b839af3798268210ee357bef3734e1ae714cc5d9aadca1a2ec886` |
| 三实例 enclave `d4-three-P1.pcap` | 143475921 字节，sha256 `0adbfb1e3ea22f09b319151a94ef43dc151ca61cc87d73303c0d77470d7e55a5` |
| 三实例 enclave `d4-three-P2.pcap` | 143478805 字节，sha256 `34a4a61e101c93bc9215a15a9c7854923c23937648a36b24156d3307a7ca9126` |
| 三实例 enclave evidence-index.json | sha256 `5f9bd7d5f747e608c2fa3ac08eaacbc1d4321ea7e80d6c0b5a557c13e69a78dd` |
| 三实例 enclave 负例 evidence-index.json | sha256 `064e47454b1aabb0bf02bc667c2cdc09a7d6e6177050b1efb2148cd2a5cf951c` |

## 6. 证据位置

单实例运行证据在
[docs/evidence/d4-20261012T143111Z](evidence/d4-20261012T143111Z)，三实例正向
证据在 [docs/evidence/d4-3host-20261012T152216Z](evidence/d4-3host-20261012T152216Z)，
三实例负例证据在
[docs/evidence/d4-negs-3host-20261012T154315Z](evidence/d4-negs-3host-20261012T154315Z)；
单实例 enclave 证据在
[docs/evidence/d4-enclave-20261013T0530Z](evidence/d4-enclave-20261013T0530Z)，
三实例 enclave 正向与负例分别在
[docs/evidence/d4-enclave-3host-20261013T052121Z](evidence/d4-enclave-3host-20261013T052121Z)
和
[docs/evidence/d4-enclave-negs-3host-20261013T052407Z](evidence/d4-enclave-negs-3host-20261013T052407Z)；
每个目录都有一份 `README.md` 说明每个文件的含义。

四个封存目录里共八份原始抓包都超过 GitHub 单文件上限，未随仓库提交：入库
目录与封存索引逐字节一致，只少这些文件，只有它们的摘要、哈希和可复算脚本
入库。每个包的 `<bundle>.exclusions.json` 记录被排除文件的路径、字节数和
sha256，把原件放回目录只会收紧校验，不会绕过校验。

释放实例前，八份抓包已全部取回操作机的 `artifacts/server/`（`artifacts/`
不进仓库），逐个复算 sha256 与各自封存索引一致，并用
`python -m infra.pcap_tls <pcap> --d4-ports` 在操作机上复跑判决：

- 2026-10-12 三实例 `d4-three-P{0,1,2}.pcap`：三份都是 `tls13_only`
  （P0 42 条 TLS 1.3 流，P1/P2 各 23 条），非 TLS 字节 0。
- 2026-10-13 三实例 enclave `d4-three-P{0,1,2}.pcap`：三份都是 `tls13_only`
  （P0 42 条，P1/P2 各 23 条），非 TLS 字节 0，与 `d4-three-summary.json`
  记录的流数、包数和 application-data 记录数逐项吻合。
- 两份单实例抓包（`d4-20261012T143111Z`、`d4-enclave-20261013T0530Z`）：同样
  复算 sha256 并复跑判决，都是 `tls13_only`、非 TLS 字节 0。这两次运行把明文
  探针打在 127.0.0.1 的四个监听端口上，所以复跑时按 runner 的做法补上
  `--probe-endpoint` 与 `--probe-marker`，把 46（旧）与 92（enclave）字节
  归到 `expected_probe_bytes`，而不是当成泄露。

把任何一份抓包放回对应的 `docs/evidence/<bundle>/` 就能让封存目录重新完整，
校验只会更严。

## 7. 尚未覆盖

以下内容未被以上运行证明，不得按已通过计：

1. **KAS 证明链**：证书由 `kas.ca` 的签发路径产生，但 CA 与叶证书来自本次
   运行的本地 PKI，不是真实 attestation 放行出来的短期身份和 Lease。enclave
   内执行的代码路径已经跑通，缺的是"Quote → 验证 → 放行证书"这一段。
2. **三个 enclave 的测量值不一致**：三实例运行时每台各自签署自己的 manifest，
   测的是各自那棵树，因此 4.8 列出三个不同的 MRENCLAVE。要给出"三方运行同一
   份受测代码"的单一测量值，需要先把代码与运行环境做成同一份 staged 树。
3. **负例的次数**：错误 CA/SAN、无客户端证书、关闭 TLS 各跑过一次（4.6 与
   4.8），单次通过不足以排除"偶尔放行"，也没有做重复运行统计。
4. **D5 之后**：Tiny Decoder Block、两 token 自回归、正式英文 GPT-2 和性能
   对照均未执行。

复跑入口：

```bash
# 单实例（任一实例上）
cd ~/1037ciphertext
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_accept.sh

# 单实例，三个节点放进 gramine-sgx
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_gramine.sh

# 三实例（操作机上，cluster 文件给出三个私网地址与各自的 ssh 公网地址）
CLUSTER=deploy/d4-three-hosts.json SSHK=~/.ssh/a122_id_sgx \
  ./deploy/run_d4_three_hosts.sh

# 三实例 fail-closed 负例（同一条入口，只换 MODE）
MODE=negatives CLUSTER=deploy/d4-three-hosts.json SSHK=~/.ssh/a122_id_sgx \
  ./deploy/run_d4_three_hosts.sh

# 三实例，三个节点各自放进 gramine-sgx（只多一个 --enclave-template）
python -m infra.d4_three_hosts run \
  --cluster deploy/d4-three-hosts.json --out-dir artifacts/server/d4-enclave-3host \
  --ssh-key ~/.ssh/a122_id_sgx \
  --enclave-template tee/gramine/enclave/spu_node.manifest.template

# 三实例 fail-closed 负例，同样加 --enclave-template
python -m infra.d4_three_hosts negatives \
  --cluster deploy/d4-three-hosts.json --out-dir artifacts/server/d4-enclave-negs \
  --ssh-key ~/.ssh/a122_id_sgx \
  --enclave-template tee/gramine/enclave/spu_node.manifest.template
```

## 8. 跨机复跑留下的环境结论（2026-10-12）

- 私网互通：三台之间 `tcp/22` 全通；SGX1 → SGX2/SGX3 的 `47100` 实测可连，
  说明安全组已放行同 VPC 的协议端口，不需要改控制台规则。
- 依赖安装：SGX1/SGX3 的 `spu` 装到一半会卡在默认 PyPI 源（在 `jaxlib`
  上停了 47 分钟），改用阿里云源后 30 秒装完。安装入口固化为
  [deploy/install_spu_server.sh](../deploy/install_spu_server.sh)。
- 三台实例之间没有装互信密钥，跨机分发因此由操作机转发：工作区打成 tar
  后落到三台的同一绝对路径，节点进程仍各自在本机启动。
- 节点在**集体 teardown** 阶段踩到过一次第三方库竞态：2026-10-12 的一次运行里
  P2 在自己的 `runtime.stop()`（yacl 的 barrier + `stop_link`）中由 brpc 报
  `Check failed: false. error_code is 0` 后 abort，没写出 `node-status.json`；
  同一次运行的正向网格已经 1024/1024 通过，重启三台重跑即恢复正常。这条路径
  由 yacl/brpc 决定，本仓库现在只能做到"等对端写完状态再收集"和"缺文件时报出
  是哪个角色缺"，尚未从根上消除该竞态。

## 9. 把节点放进 enclave 时踩到的坑（2026-10-13）

按顺序记下，都是把 SPU 原生栈塞进 Gramine 时才会遇到的：

- **wrapper 要替换解释器，不能做前缀**。Gramine 交给应用的是
  `[entrypoint, *argv]`，所以命令行必须是 `gramine-sgx <manifest> -m
  tee.enclave.spu_node --config <cfg>`；如果写成"前缀"（`<manifest> python -m
  ...`），节点会把解释器路径当成脚本去打开。`--node-wrapper` 因此按"替换
  `sys.executable`"实现。
- **LibOS 的 cwd 是 `/`**。`-m` 会先去探 `/tee/__init__.py`，manifest 里加
  `loader.env.PYTHONSAFEPATH = "1"` 才回到挂载进来的仓库。
- **`sgx.trusted_files` 要覆盖整个 site-packages**。只信
  `spu/libspu.so` 不够，`cryptography` 之类的扩展模块一被 import 就
  `PermissionError`。
- **`gramine-sgx <name>` 按后缀找 manifest**。它要的是
  `<name>.manifest` 与 `<name>.manifest.sgx`；名字对不上会报
  `Invalid application path`。
- **签名密钥决定测量值**。每次新生成密钥，MRSIGNER 变，MRENCLAVE 也跟着变
  （SIGSTRUCT 本身在被测量的内存里）。三实例运行因此只生成一次密钥再分发。
- **enclave 内跑得动**：`load_libspu()` 大约 4.9 秒完成 dlopen 与
  `RuntimeConfig` 构造，`/dev/attestation` 存在，`sgx.remote_attestation="dcap"`
  能签能起。
- **enclave 进程退出更慢**，监听端口的释放随之变慢。三实例负例逐个场景起停
  节点时，`kill` 之后立刻重启会偶发 `OSError: [Errno 98] Address already in
  use`（对端日志里可见），但四个场景本身仍全部按预期拒绝。要连跑多轮，应该
  在起下一个场景前确认端口已经释放。
- **seal 与 shell 重定向的竞态**：`run_d4_gramine.sh` 起初把验收输出重定向进
  被 seal 的目录，而 runner 在打印判决之前就封存，导致索引记录的是日志的前半
  段。现在日志写在 bundle 外，跑完再拷进来并重新封存（`run_d4_accept.sh` 一直
  是这么做的）。

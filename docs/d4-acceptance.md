# D4 三节点通信与 3PC RSS 验收记录

> 运行编号：单实例 `d4-20261012T143111Z`（提交 `d048827`），三实例
> `d4-3host-20261012T152216Z`（提交 `bcd8935`，由 `infra.d4_three_hosts`
> 一条命令驱动）。
>
> 结论：**D4 传输层与算子网格通过，且已在三台独立实例上复跑**。1,024 组向量
> 全部与固定点参考一致，协议端口上的抓包只出现 TLS 1.3 记录，五类
> 明文/证书/TLS 关闭场景全部 fail-closed。
>
> 范围限定：链路两端都在**普通 Linux 进程内**终止 TLS，不在 `gramine-sgx`
> 内；证书来自本次运行的本地 PKI，不是真实 attestation 放行的短期身份。
> 三实例上的 fail-closed 负例尚未复跑，跨机只是正向网格加抓包。见第 7 节。

本记录对应 [后续开发总计划.md](后续开发总计划.md) 第 7 节。

## 1. 验收环境

单实例运行在三台机器中的 SGX2 上，三实例运行把 P0/P1/P2 分到三台，并且在
每台上各自启动一个节点进程：

| 角色 | 实例 | 私网 | 公网 | SGX2 单实例运行 |
| --- | --- | --- | --- | --- |
| P0 | `iZuf6bjvfplpwleemaipwmZ`（SGX1） | `172.27.172.201` | `47.116.200.143` | P0/P1/P2 三进程同机（loopback） |
| P1 | `iZuf6bd6qnhgtveg5khyf1Z`（SGX2） | `172.27.172.202` | `47.117.34.67` | 本记录的单实例主机 |
| P2 | `iZuf6bd6qnhgtveg5khygdZ`（SGX3） | `172.27.172.203` | `106.15.54.240` | - |

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
  收回各角色的摘要与状态，并调用 `finalise_cross_host` 封存。
- [deploy/run_d4_three_hosts.sh](../deploy/run_d4_three_hosts.sh)：上一个入口的
  脚本化包装，读 `deploy/d4-three-hosts.json` 作为集群描述。

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

四个负例在单实例运行中执行（三实例运行没有复跑，见第 7 节）：

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
| 三实例 evidence-index.json | sha256 `f03efb634c850939d699f8db8fc6d8791944b4c2501f22696a347a0552e30621` |

## 6. 证据位置

单实例运行证据在
[docs/evidence/d4-20261012T143111Z](evidence/d4-20261012T143111Z)，三实例运行
证据在 [docs/evidence/d4-3host-20261012T152216Z](evidence/d4-3host-20261012T152216Z)；
两个目录各有一份 `README.md` 说明每个文件的含义。

四份原始抓包都超过 GitHub 单文件上限，未随仓库提交：入库目录与封存索引
逐字节一致，只少这些文件，只有它们的摘要、哈希和可复算脚本入库。每个包的
`<bundle>.exclusions.json` 记录被排除文件的路径、字节数和 sha256，把原件放回
目录只会收紧校验，不会绕过校验。

## 7. 尚未覆盖

以下内容未被以上运行证明，不得按已通过计：

1. **三个 enclave 内执行**：SPU/YACL/BRPC 目前在普通 Linux 进程里运行，
   尚未放进 `gramine-sgx`。`communication-trace.json` 里的
   `inside_enclave: false` 就是 `runtime_label()` 检查 `/dev/attestation`
   的实测结论；"enclave 内 mTLS" 的说法要等这一步。
2. **KAS 证明链**：证书由 `kas.ca` 的签发路径产生，但 CA 与叶证书来自本次
   运行的本地 PKI，不是真实 attestation 放行出来的短期身份和 Lease。
3. **跨机 fail-closed 负例**：三实例运行只跑了正向网格和抓包。错误 CA/SAN、
   无客户端证书、关闭 TLS 与明文探针目前只在单实例上验证过，跨机复跑
   需要把负例配置分发到对应实例后再来一轮。
4. **D5 之后**：Tiny Decoder Block、两 token 自回归、正式英文 GPT-2 和性能
   对照均未执行。

复跑入口：

```bash
# 单实例（任一实例上）
cd ~/1037ciphertext
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_accept.sh

# 三实例（操作机上，cluster 文件给出三个私网地址与各自的 ssh 公网地址）
CLUSTER=deploy/d4-three-hosts.json SSHK=~/.ssh/a122_id_sgx \
  ./deploy/run_d4_three_hosts.sh
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

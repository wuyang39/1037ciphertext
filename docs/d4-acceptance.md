# D4 三节点通信与 3PC RSS 验收记录

> 运行编号：`d4-20261012T135923Z`，提交 `63e5c65`
>
> 结论：**D4 传输层与算子网格通过**。1,024 组向量全部与固定点参考一致，
> 协议端口上的抓包只出现 TLS 1.3 记录，五类明文/证书/TLS 关闭场景全部
> fail-closed。
>
> 范围限定：本次三个节点是**同一台实例上的三个进程**，链路走 loopback，
> TLS 在普通 Linux 进程内终止。三台独立实例、三个 `gramine-sgx` enclave 内
> 的复跑仍待执行，见第 7 节。

本记录对应 [后续开发总计划.md](后续开发总计划.md) 第 7 节。

## 1. 验收环境

| 项目 | 实测值 |
| --- | --- |
| 实例 | `iZuf6bd6qnhgtveg5khyf1Z`（`cn-shanghai`，公网 `47.117.34.67`） |
| 系统 | Ubuntu 22.04.5，内核 `5.15.0-191-generic` |
| CPU | Intel Xeon Platinum 8369B @ 2.70GHz，4 vCPU |
| SGX | `/dev/sgx_enclave`、`/dev/sgx_provision` 存在，`aesmd` active |
| Python | 3.11.17（`~/a122-venv311`） |
| SPU | `spu` 0.9.5（真实 YACL/BRPC C++ 后端，`spu/libspu.so`） |
| 其他库 | `cryptography` 48.0.1、`gmssl` 3.2.2、`pydantic` 2.14.1、`jsonschema` 4.26.0 |
| OpenSSL | 3.0.2 |
| 抓包 | tcpdump 4.99.1（`cap_net_raw,cap_net_admin`） |
| 运行时长 | 13:59:29Z 起，14:00:32Z 写出 `d4-summary.json`，约 63 秒 |

## 2. 使用的工具

- [deploy/run_d4_accept.sh](../deploy/run_d4_accept.sh)：本次运行的唯一入口，
  负责建工作区、跑网格与负例、抓包并封存证据。
- [infra/d4_acceptance.py](../infra/d4_acceptance.py)：`provision` 与 `loopback`
  两种模式，含明文探针与负例驱动。
- [infra/d4_workspace.py](../infra/d4_workspace.py)：证书、向量网格和九个节点
  配置（三个正常 + 四个负例）。
- [infra/d4_pki.py](../infra/d4_pki.py)：复用 `kas.ca.CertificateAuthority`
  签发 P0/P1/P2 证书，并生成"错误 CA""错误 SAN"的负例材料。
- [tee/enclave/spu_node.py](../tee/enclave/spu_node.py)：P0/P1/P2 节点进程，
  建立 BRPC 链路、执行网格并写出 `node-status.json`。
- [mpc/spu_backend](../mpc/spu_backend)：YACL/BRPC 传输与 mTLS 策略。
- [infra/pcap_tls.py](../infra/pcap_tls.py)：无 tshark 依赖的 pcap 解析器，
  重组 TCP 流并走 TLS 记录层。
- [infra/d4_evidence.py](../infra/d4_evidence.py)：证据装配、封存与哈希。

## 3. 流程

1. `--mode provision` 生成 KAS CA、三张角色证书、1,024 组向量和九个节点配置。
2. `tcpdump -i any` 开始抓取六个协议端口（BRPC `47100-47102`、share 通道
   `47200-47202`）。
3. 启动 P1、P2，等它们打出 ready 标记；此时 BRPC 链路已在进程内建立。
4. 对每个监听端口发一次 23 字节明文探针，记录拒绝方式。
5. 启动 P0，驱动 16 个批次共 1,024 组 RSS 向量，逐批与固定点参考比对。
6. 停止抓包，依次跑四个 fail-closed 负例，每一步都要求子进程非零退出。
7. 解析抓包、写入 `tls-summary.txt`，装配并封存证据目录。

## 4. 结果

### 4.1 正向网格

| 项目 | 结果 |
| --- | --- |
| 向量数 | 1024（16 批 × 64） |
| 通过 / 失败 | **1024 / 0** |
| 算子 | `add`、`mul`、`matmul`、`truncate`、`compare`、`reciprocal` |
| 网格摘要 | `96b6c83502203292840fd9836f0efbe6f5fe49225aa5b110a6f2b3c27f3695d5` |
| P0 / P1 / P2 状态 | `passed` / `served`（16 批）/ `served`（16 批） |
| 链路建立耗时 | P1 4.147 s，P2 3.992 s |
| teardown | 三个节点均 `teardown_finished: true` |

同一网格摘要在两次独立运行（`d4-20261012T135345Z` 与本次）中完全一致，
说明向量生成与算子结果可重复。

### 4.2 抓包结论

| 项目 | 结果 |
| --- | --- |
| 六个协议端口上的报文 | 108677 |
| TCP 流 | 94 |
| TLS 1.3 流 | 41 |
| TLS 1.2 或更低 | 0 |
| TLS 会话 | 47 |
| application_data 记录 | 184244 |
| 握手消息 | 96 |
| 无法解释的非 TLS 字节 | **0** |
| 判决 | `tls13_only` |

抓包里另有 46 字节非 TLS 载荷，全部来自第 3.4 步的**故意明文探针**
（23 字节的 `A1-22-PLAINTEXT-PROBE\r\n`，出现两次）。解析器按"探针端点 +
探针标记"把这几字节单独记为 `expected_probe_bytes`，只有无法归属的明文
才会让判决失败。

### 4.3 fail-closed 场景

| 场景 | 结果 | 拒绝理由（节点原始输出） | 耗时 |
| --- | --- | --- | --- |
| 明文探针 | **refused** | 四个监听端口无一处给出明文业务应答：两个 `closed_or_tls_only`、一个 `connection_reset`、一个 `connection_refused` | - |
| `wrong-ca` | **refused** | `peer P2 certificate was not signed by the KAS CA` | 0.214 s |
| `wrong-san` | **refused** | `peer P2 certificate SAN does not match its role` | 0.214 s |
| `no-client-cert` | **refused** | `the BRPC link could not be established`（P0/P1/P2 三方一致拒绝） | 57.132 s |
| `tls-disabled` | **refused** | `the SPU link must not run without TLS`，进程直接退出、不回退 | 0.214 s |

四个证书/TLS 负例的退出状态均为 3，没有任何一个降级为明文或跳过校验。

### 4.4 材料一次性消费

三个角色的预处理材料各消费一次后 `remaining=0`，第二次申领被拒绝
（`denied: material is not available: consumed`），`one_time_consumption: true`。

## 5. 关键值

| 项目 | 值 |
| --- | --- |
| 节点证书 P0 | sha256 `b297bc9539fe55b68b2791f94b1718e4fd4559828a6ff0b4993434561f6879aa` |
| 节点证书 P1 | sha256 `7c956094a5da2316ed63298841185dd7b8746aa05ef3235f2a6e51c0a41e13f9` |
| 节点证书 P2 | sha256 `48ec10dc2a860823ac898273e80abab2c163ec034390ab0df8a103030e9df4e7` |
| tls-pcap.pcap | 216345087 字节，sha256 `bf3ef5f57aab6dd8012d73b3356e5877567ec129a23e191bb589da17981197f9` |
| evidence-index.json | sha256 `0241b567a06d300f1a60ce7c857d92082a91c3f8ecbdb98930ed9cf8ded876c8` |

## 6. 证据位置

运行证据在
[docs/evidence/d4-20261012T135923Z](evidence/d4-20261012T135923Z)，逐文件说明
见 [docs/evidence/d4-20261012T135923Z.md](evidence/d4-20261012T135923Z.md)。
原始抓包 216 MB，超出 GitHub 单文件上限，未随仓库提交：入库目录与封存索引
逐字节一致，只少这一个文件，只有它的摘要、哈希和可复算脚本入库。

## 7. 尚未覆盖

以下内容未被本次运行证明，不得按已通过计：

1. **三个独立实例**：本次 P0/P1/P2 是同机三进程，私网地址、安全组、跨机
   端口开放和时钟差都还没验证。
2. **三个 enclave 内执行**：SPU/YACL/BRPC 目前在普通 Linux 进程里运行，
   尚未放进 `gramine-sgx`；"enclave 内 mTLS" 的说法要等这一步。
3. **KAS 证明链**：证书由 `kas.ca` 的签发路径产生，但 CA 与叶证书来自本次
   运行的本地 PKI，不是真实 attestation 放行出来的短期身份和 Lease。
4. **D5 之后**：Tiny Decoder Block、两 token 自回归、正式英文 GPT-2 和性能
   对照均未执行。

复跑入口是同一条命令，只需把 cluster 文件指向三台实例的私网地址、把节点
进程换成 `gramine-sgx`：

```bash
cd ~/1037ciphertext
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_accept.sh
```

# SGX 服务器验收清单

本清单只在取得 SGX v2/vSGX 服务器后执行。验收完成后立即关闭或释放实例，不在空闲状态保留实例。

## D1 证明

- [x] 正确 release 得到短期节点证书和 Lease。
- [x] 修改受测量文件被拒绝。
- [x] `sgx.debug=true` 被 KAS 拒绝。
- [x] 重放旧 challenge 被拒绝。
- [x] 替换临时公钥被拒绝。
- [x] 保存 Quote、验证报告、measurement、CSR/report-data 和拒绝日志。

- [x] 运行一个最小 SGX enclave 程序（`SampleEnclave`）。
- [x] 运行一个最小 Gramine-SGX 程序（Gramine 1.9，`sgx.debug=false`，取得 DCAP Quote）。

已完成项见 [d1-server-acceptance.md](d1-server-acceptance.md)。证明闭环运行
`d1-20261012T1810`，证据在 [docs/evidence/d1-20261012T1810](evidence/d1-20261012T1810)；
Gramine 运行 `d1-20261012T1830`，证据在
[docs/evidence/d1-20261012T1830](evidence/d1-20261012T1830)。

## D2 协议

- [ ] C↔P0/P1/P2 三路会话正常建立。
- [ ] 过期/伪造证书被拒绝。
- [ ] tag/AAD、重复/乱序 counter、跨 session、跨模型被拒绝。
- [ ] 已消费/过期 JobTicket 在进入 MPC 前被拒绝。

## D3 受保护文件

- [x] encrypted FS 由 16 字节 KDK 挂载，enclave 内整份读取加密份额。
- [x] 宿主直接读取、复制、字符串与字节搜索、篡改都得不到明文。
- [x] 错误 measurement、缺失 Lease 时 Worker 不启动。
- [x] `K_disk_i` 的放行由 KAS 证明结论驱动。
- [x] host 日志、`/tmp`、`$HOME` 和证据目录扫描无敏感材料；镜像与 core dump 待 D9。

已完成项见 [d3-encfs-acceptance.md](d3-encfs-acceptance.md)（运行
`d3-20261012T1930`），证据在
[docs/evidence/d3-20261012T1930](evidence/d3-20261012T1930)；KAS 放行
`K_disk_i`、固定 Worker 入口启动条件见
[d3-kas-release-acceptance.md](d3-kas-release-acceptance.md)（运行
`d3-kas-20261012T115025Z`），证据在
[docs/evidence/d3-kas-20261012T115025Z](evidence/d3-kas-20261012T115025Z)。

## D4-D6 三节点

- [x] YACL/BRPC 仅 TLS records，明文连接失败。（单实例三进程运行
  `d4-20261012T143111Z`：六个协议端口 108760 报文、41 条 TLS 1.3 流、
  0 字节无法归属的非 TLS 载荷）
- [x] 错误 CA、SAN、无客户端证书不能执行算子。（同上，三类负例均以退出码 3
  拒绝）
- [x] 关闭 TLS 时 Worker 启动失败，不回退。（同上，`the SPU link must not run
  without TLS`）
- [x] 至少 1,000 组 RSS 向量与固定点参考一致。（同上，1024 组全过，
  网格摘要 `96b6c835...`）
- [x] P0/P1/P2 跑在三台独立实例上，跨 VPC 私网完成 1,024 组向量。（运行
  `d4-3host-20261012T152216Z`：三份抓包各自 `tls13_only`、非 TLS 字节全 0，
  网格摘要与单实例一致，6/6 对端证书互校通过，三个节点都
  `teardown_finished: true`）
- [x] 三台独立实例上复跑四类 fail-closed 负例与明文探针。（运行
  `d4-negs-3host-20261012T154315Z`：变异方在 P0、严格方分居 P1/P2，四个负例
  均退出码 3 且理由与单实例一致，四个明文探针都建到 TCP 却拿不到业务应答）
- [x] 三个 `gramine-sgx` enclave 内复跑上述所有项目。（单实例运行
  `d4-enclave-20261013T0530Z`：三个进程共享 MRENCLAVE
  `b28084fe...`，1024 组全过、四个负例全拒、抓包 `tls13_only`、非 TLS 字节
  0；三实例运行 `d4-enclave-3host-20261013T052121Z` 与负例
  `d4-enclave-negs-3host-20261013T052407Z`：三台各自签名自己的 manifest，
  正向与四个负例同样全过。三份测量值互不相同，原因见
  [d4-acceptance.md](d4-acceptance.md) 4.8 节）
- [x] enclave 内把四类 fail-closed 负例连跑三次。（运行
  `d4-enclave-negs-repeat-3host-20261013T0907Z`：三次的四个场景全部退出码 3、
  拒绝理由逐句相同，`all_refused: true`、`unexpected_cases: []`，明文探针
  三次都连上监听端口且都没有业务应答；每台实例的 MRENCLAVE 在三次之间逐字节
  复现）
- [x] 三台实例跑同一份 staged 受测树，给出单一测量值。（运行
  `d4-enclave-shared-3host-20261013T1715Z`：仓库用 `git archive`、venv 从 P0
  经私网分发同一份 tar、三台统一清掉 `__pycache__` 并让宿主侧调用带
  `PYTHONDONTWRITEBYTECODE=1`，三份 manifest 渲染结果逐字节相同，MRENCLAVE
  三台都是 `8749c1db...`，`distinct_measurements: 1`；1024 组全过、三份抓包
  `tls13_only`、非 TLS 字节 0、证书互校 6/6。staging 目前是手工步骤，见
  [d4-acceptance.md](d4-acceptance.md) 第 7 节）
- [ ] 证书来自真实 attestation 放行：Quote → 验证 → 签发短期身份/Lease 的
  KAS 链路尚未实现。enclave 内执行已经跑通，缺的只是这一段。

三台实例的基线已经就绪（正向运行在提交 `bcd8935`、负例运行在 `a2d8026`，
`spu` 0.9.5、SGX 设备与 `aesmd` 正常、私网 `47100` 实测互通），见
[d4-acceptance.md](d4-acceptance.md) 第 8 节。
- [x] Tiny Decoder Block 在三个 enclave 完成。（运行
  `d5-enclave-3host-20261013T1057Z`：P0/P1/P2 各自在 `gramine-sgx` 内执行
  完整 Block，38/38 用例通过，`overflow_count` 全 0，9 个 Block 用例的 secure
  Argmax 结果与浮点参考逐个相等，三份抓包都是 `tls13_only`、非 TLS 字节 0，
  证书互校 6/6，三棵树的 reveal 扫描无未解释命中。权重是合成权重，正式英文
  GPT-2 属 D7。见 [d5-acceptance.md](d5-acceptance.md)）
- [x] 连续生成至少 2 token。（运行 `d6-enclave-3host-20261013T1324Z`：prompt
  `the cipher key is secret` 在三个 enclave 内连续生成 3 个 token
  `yes his small`，逐步的安全 Argmax 与客户端重建 logits 后的 Argmax 逐个相等，
  与 float64 参考的 `max_abs_error` 为 4.2e-4 ~ 8.0e-4）
- [x] ResultFrame 重复、篡改 `decode_step`、模型混用、输入/Ticket 重放均被拒绝。
  （同上运行：五类负例全部被拒，理由分别是结果帧不覆盖三角色、`decode_step`
  不匹配、模型不匹配、counter 重复/乱序、JobTicket 已被本节点接受）
- [x] 会话结束后 `/run/session`、临时目录和进程扫描无 Prompt share、KV、会话密钥。
  （同上运行：close 之前三台各有 1 份溢写份额共 4323 字节，close 之后会话目录
  被就地覆写并删除、`/dev/shm` 会话根为空、80 字节会话密钥清零、KV 无残留，
  随后的清洁度扫描与 reveal 扫描在三台都干净）

已完成项见 [d6-acceptance.md](d6-acceptance.md)（运行
`d6-enclave-3host-20261013T1324Z`，提交 `3e82e1b`），证据在
[docs/evidence/d6-enclave-3host-20261013T1324Z](evidence/d6-enclave-3host-20261013T1324Z)。
权重是合成权重，正式英文 GPT-2 属 D7；三台的测量值互不相同（默认驱动让每台
签名自己的树），与 D4 同类。

D4 已完成项的记录见 [d4-acceptance.md](d4-acceptance.md)，证据在
[docs/evidence/d4-20261012T143111Z](evidence/d4-20261012T143111Z)（单实例三进程）
、[docs/evidence/d4-3host-20261012T152216Z](evidence/d4-3host-20261012T152216Z)
（三实例正向）、
[docs/evidence/d4-negs-3host-20261012T154315Z](evidence/d4-negs-3host-20261012T154315Z)
（三实例负例），以及 2026-10-13 的三份 enclave 证据
[docs/evidence/d4-enclave-20261013T0530Z](evidence/d4-enclave-20261013T0530Z)
、[docs/evidence/d4-enclave-3host-20261013T052121Z](evidence/d4-enclave-3host-20261013T052121Z)
与
[docs/evidence/d4-enclave-negs-3host-20261013T052407Z](evidence/d4-enclave-negs-3host-20261013T052407Z)
，以及 enclave 内负例连跑三次的
[docs/evidence/d4-enclave-negs-repeat-3host-20261013T0907Z](evidence/d4-enclave-negs-repeat-3host-20261013T0907Z)
，和三个节点跑在同一份 staged 树上的
[docs/evidence/d4-enclave-shared-3host-20261013T1715Z](evidence/d4-enclave-shared-3host-20261013T1715Z)。
链路、证书、抓包、拒绝路径和 `gramine-sgx` 内的执行都是实测；真实 attestation
放行仍未验证。

## D7-D8 模型与指标

- [ ] 正式英文 GPT-2（`gpt2`）模型完成至少 1 token 生成。
- [ ] `model_hash`、tokenizer、`precision_plan`、epoch、Ticket 全部绑定。
- [ ] 每项优化有开/关对照，报告 token 一致率、误差、延迟、通信量、内存和安全回归。
- [ ] 原始 trace 可由固定脚本重算图表。

## D9-D10 交付

- [ ] P0/P1/P2 使用独立账号、管理员、密钥权限、安全组和审计域。
- [ ] 测试 LAN、`100 Mbps/40 ms`、`100 Mbps/80 ms`。
- [ ] 从新机器按安装手册部署一次。
- [ ] 冻结镜像 digest、release measurement、配置、模型 hash、报表脚本和证据 hash。
- [ ] 完成 15 分钟答辩演练。
- [ ] 关闭服务器并确认计费状态。

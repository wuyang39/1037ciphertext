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

- [ ] encrypted FS 由 `K_disk_i` 挂载。
- [ ] 宿主直接读取、复制、篡改得不到明文。
- [ ] 错误 measurement、缺失 Lease 时 Worker 不启动。
- [ ] 镜像、环境变量、host 日志和 core dump 扫描无敏感材料。

## D4-D6 三节点

- [ ] YACL/BRPC 仅 TLS records，明文连接失败。
- [ ] 错误 CA、SAN、无客户端证书不能执行算子。
- [ ] 关闭 TLS 时 Worker 启动失败，不回退。
- [ ] 至少 1,000 组 RSS 向量与固定点参考一致。
- [ ] Tiny Decoder Block 在三个 enclave 完成。
- [ ] 连续生成至少 2 token。
- [ ] ResultFrame 重复、篡改 `decode_step`、模型混用、输入/Ticket 重放均被拒绝。
- [ ] 会话结束后 `/run/session`、临时目录和进程扫描无 Prompt share、KV、会话密钥。

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

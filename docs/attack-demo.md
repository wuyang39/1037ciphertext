# A1-22 本地攻击负例演示

本地脚本：

```powershell
python infra/security_negative.py --output artifacts/evidence/negative-checks.json
```

当前覆盖的本地拒绝点：

- TLS 配置被降级到 `TLS1.2`：拒绝启动。
- BRPC builtin services 被打开：拒绝启动。
- 错误 CA、错误 SAN、缺失客户端证书：mock mTLS 拒绝。
- 加密文件使用错误磁盘密钥、错 epoch 或被篡改：拒绝解密。
- Worker 未取得 Lease 或错误 Key：拒绝启动。
- 仿真 reveal 被关闭时仍调用非线性 mock：拒绝执行。
- 旧 `share_epoch` 导入：拒绝。
- Ticket 过期、伪造、跨 session、跨模型和重复消费：D2 单元测试拒绝。

服务器阶段必须补充并保存证据的攻击：

1. 篡改 Worker 二进制或依赖。
2. 使用 debug enclave 或旧 Quote。
3. 替换 CSR 临时公钥。
4. 明文 BRPC、错误 CA/SAN 和无客户端证书。
5. 密钥释放请求重放、Ticket 重放和材料重复消费。
6. 抓取 P0/P1 磁盘、容器配置、host 日志、pcap 和进程信息，搜索 Prompt、share、KV、TLS 私钥和 `K_disk_i`。

每个负例必须记录发起时间、目标、拒绝点、返回码、审计事件和证据文件 hash。

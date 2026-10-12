# D3 KAS 放行磁盘密钥验收记录

> 运行编号：`d3-kas-20261012T115025Z`
>
> 结论：**D3 KAS 放行链路通过**。`K_disk_P0` 不再由宿主生成，KAS 只在
> DCAP Quote 满足登记策略时把它用 SM2 加密给 enclave 的临时公钥；宿主拿
> 不到密钥，Worker 在 startup hash、epoch、Lease 或测量值不匹配时全部
> fail-closed。

本记录接续 [d3-encfs-acceptance.md](d3-encfs-acceptance.md) 第 6 节遗留项
1、2，对应 [后续开发总计划.md](后续开发总计划.md) 第 6 节执行项
2、4、7。

## 1. 验收环境

| 项目 | 实测值 |
| --- | --- |
| 实例 | `iZuf6bjvfplpwleemaipwmZ`（`cn-shanghai`，与 D1/D3 同一台） |
| Gramine | 1.9（`gramine`、`gramine-ratls-dcap`），`sgx.debug=false`，`sgx.remote_attestation="dcap"` |
| enclave 内解释器 | `/usr/bin/python3` 3.10.12（用户级 `gmssl`） |
| KAS 解释器 | `~/a122-venv` Python 3.12.15 |
| KAS 端口 | `127.0.0.1:18443`（正确策略）、`127.0.0.1:18444`（错误测量值） |
| 系统 | Ubuntu 22.04.5，内核 `5.15.0-191-generic` |

## 2. 组件

- [crypto/enclave_key.py](../crypto/enclave_key.py)：REPORTDATA 绑定
  （临时公钥、role、release、challenge nonce）、Worker startup digest、
  PF 密钥派生（HKDF-SM3）和 128 字节 bundle 编解码。
- [crypto/sm2.py](../crypto/sm2.py)：SM2 `C1||C3||C2` 加解密，解密时校验
  `C3`。
- [kas/storage_keys.py](../kas/storage_keys.py)：`K_disk_i` 的确定性派生，
  与打包脚本同源。
- [kas/service.py](../kas/service.py)、[kas/app.py](../kas/app.py)：
  `POST /v1/release-storage-key-sealed`。
- [tee/enclave/encfs_worker.py](../tee/enclave/encfs_worker.py)：固定 Worker
  入口。
- [deploy/run_d3_kas_release.sh](../deploy/run_d3_kas_release.sh)：一键构建、
  渲染签名 manifest、打包加密集、驱动用例网格并采集证据。
- [infra/d3_kas_acceptance.py](../infra/d3_kas_acceptance.py)、
  [infra/d3_kas_release_evidence.py](../infra/d3_kas_release_evidence.py)：
  用例网格与判决采集。

## 3. 流程

1. 在 enclave 外生成只用一次的模型包，取 P0 份额与精度计划，并立即抹除
   包目录里的明文份额。
2. 渲染并签名 Worker manifest；`sgx.allowed_files` 只放行控制目录
   （`/control`，主机路径）与两个 ELF 解释器路径。
3. 第一次运行签名 Worker 只为测量：它把临时 SM2 公钥、role、release 与
   challenge nonce 写入 REPORTDATA，读出 DCAP Quote，1 秒内等不到密钥即退出。
4. 用该 Quote 的 MRENCLAVE/MRSIGNER 生成放行策略，启动 KAS；第二个 KAS 用
   `mrenclave = 00*32` 的错误策略。
5. 打包脚本用 KAS 主密钥派生的 `K_disk_P0` 把份额与精度计划加密成
   Gramine PF 存储，并抹除明文。
6. 每个用例：KAS 发 challenge → Worker 起 enclave、写 REPORTDATA、导出
   Quote 与临时公钥 → KAS 验 Quote、验 REPORTDATA 绑定、查一次性放行台账 →
   用 SM2 加密 128 字节 bundle（`key_id`、`startup_hash`、`share_epoch`、
   过期时间、`K_disk_P0`）→ 宿主转发给 Worker → Worker 解密并核对
   `key_id`、startup digest、epoch、有效期 → 写入
   `/dev/attestation/keys/a122_disk` → 整份读取加密份额。
7. 复核宿主侧：加密集字节搜索、全盘字节搜索与文件扫描。

## 4. 结果

| 情形 | 结果 | 说明 |
| --- | --- | --- |
| `accept-kas-sealed-release` | **accepted** | 放行 `200`；bundle 224 字节经 SM2 打开，startup digest、epoch、key_id、有效期全部匹配，装入 16 字节 PF 密钥并整份读完 46080 字节，退出码 0 |
| `deny-missing-sealed` | **rejected** | 放行 `200` 但宿主不转发，`sealed_seen=0`，退出码 3 |
| `deny-tampered-sealed` | **rejected** | 密文翻转 1 字节，`SM2 ciphertext integrity check failed`，`bundle_open_ok=0` |
| `deny-wrong-epoch` | **rejected** | enclave 声称 epoch 2、KAS 按 epoch 1 封装，`startup_hash_ok=0` |
| `deny-wrong-startup` | **rejected** | enclave 声称 `unregistered-model`，`startup_hash_ok=0` |
| `deny-replay-challenge` | **rejected** | 首次放行 `200`，同一 challenge 重放 `404（challenge is unknown or already consumed）` |
| `deny-second-seal` | **rejected** | 同 role/release/epoch/purpose 第二次放行 `409（storage key was already sealed for this node and epoch）`，且首个 Worker 仍读到了份额 |
| `deny-wrong-measurement` | **rejected** | 错误测量值策略的 KAS 返回 `403 MRENCLAVE does not match the release` |
| `deny-host-plaintext-in-store` | **rejected** | 53248 字节 PF 存储中找不到明文份额、首 64 字节与末 64 字节 |
| `deny-host-plaintext-anywhere` | **rejected** | 运行目录、`/tmp`、`/var/log`、`$HOME` 全盘字节搜索无命中 |

关键值：

| 项目 | 值 |
| --- | --- |
| MRENCLAVE | `88e73d97fe87362eac096f44df23ffd2b271cb8de7b99fa4c13d6c118a2f5cd2` |
| MRSIGNER | `4296167eed40572682c03bd4dba260ff16383d7299117d0de8ec22f52dc329b7` |
| 测量用 Quote | 4734 字节，sha256 `57a470dc302383700de8189f20e9d7e639d8032de60ee0bc14b1baed3560bf03` |
| 放行策略 | `a122-d3-kas-v1`，`tiny-local-v1`，到期 `2026-10-12T17:50:40+00:00` |
| 放行 key_id | `c9eca76f72b4c3261f91164bb7e4c0a7a6b9e0d19a175ac66d2009aca721bd24` |
| Worker startup digest | `42748f8b5597654dea6bbcd009546c8d557ef40ff6a4c8b17c7f75b2740f09a7` |
| 明文份额 | 46080 字节，sha256 `e4150b9bc6d172cb4b7e81c332f3d994c3116488175fa9b6901c013de7fa095b` |
| 明文前缀 | 前 4096 字节，sha256 `14cd7bb478ee7ee9be85f7bc184a84e11369c76349c4f9c1ccf286cbdc1a1d37` |
| 加密份额 | 53248 字节，sha256 `1b28b56e94b4586d1a4ab6c5267aef9239c793c9d25119df93e18fa811abafbe` |
| 密钥通道 | `/dev/attestation/keys/a122_disk` |

明文份额哈希与 `d3-20261012T1930` 完全一致：同一份份额，上一次由宿主生成
KDK 读取，本次由 KAS 证明后放行的密钥读取。

## 5. 证据

完整证据目录：
[docs/evidence/d3-kas-20261012T115025Z](evidence/d3-kas-20261012T115025Z)。

离线校验：

```bash
python -m infra.seal_evidence verify docs/evidence/d3-kas-20261012T115025Z
```

目录内含判决汇总 `d3-kas-summary.json`、逐用例原始输出与 JSON、渲染后的
`encfs_worker.manifest`、放行策略、KAS 日志、打包记录、宿主侧泄漏与扫描
结果，以及 `evidence-index.json` 与 `evidence.sha256`。

## 6. 本轮修复的真实环境问题

manifest 与用例骨架在 mock 里看不出来，只有实机才暴露：

1. `LD_LIBRARY_PATH` 里 `/usr/@ARCH_LIBDIR@` 渲染成 `/usr//lib/...`，Gramine
   视为未挂载路径；`@ARCH_LIBDIR@` 与 `@USR_LIBDIR@` 拆开后消失。
2. `PYTHONPATH` 被固定成 `/app`，把用户级 `gmssl` 的 site-packages 挤出
   guest 的 `sys.path`；改为把解释器自身的 `sys.path` 传进去再追加 `/app`。
3. chroot 挂载里的文件要先出现在 `sgx.allowed_files`，且该列表按**主机**
   路径解析；原模板写的是 guest 路径 `/control/`，导致 enclave 内
   `open()` 一律 `EACCES`。
4. `/control` 是单一挂载点，bootstrap 与各用例的 nonce 互相覆盖；改为每个
   用例使用 `/control/<case>` 子目录。
5. 证据校验要求 accept 用例的 `gramine-sgx exit status` 为 0，用例骨架原先
   没有把这行写进输出。
6. 加密集写在 `$WORK/store/secure`，manifest 挂载的却是 `$WORK/store`；
   两者对齐后 enclave 才能按 `/secure/<share>` 读到文件。

## 7. 遗留

1. challenge 与放行报文走本机 loopback HTTP，证明结论由 Quote 承载，信道
   本身未经认证；Worker 与 KAS 的 RA-TLS 属于 D6。
2. challenge 台账与一次性放行台账保存在 KAS 进程内存，重启即清空（用例网格
   正是靠这一点为每个用例取得干净台账）。
3. SM2 bundle 的完整性依赖 SM3 `C3` 校验与 bundle 魔数，没有额外 MAC，也没有
   前向保密。
4. KAS 主密钥仍由 runner 在宿主上按次生成，证据只记录派生出的 `key_id`；
   把主密钥交给 KMS/HSM 托管仍未完成。
5. Gramine encrypted FS 不防关闭后的回滚，旧但真实的存储副本仍会被接受。
6. 测试模型是 46080 字节的一次性份额；正式英文 GPT-2（`gpt2`）与三节点份额
   分离属于 D4/D7。

## 8. 复现

```bash
git clone https://github.com/wuyang39/1037ciphertext.git
cd 1037ciphertext
sudo bash deploy/install_gramine_server.sh
uv venv --python 3.12 ~/a122-venv
uv pip install --python ~/a122-venv/bin/python \
  'cryptography>=48,<49' 'gmssl>=3.2.2,<4' 'pydantic>=2.5,<3' 'jsonschema>=4.26,<5'
/usr/bin/python3 -m pip install --user gmssl
PYTHON=~/a122-venv/bin/python SYSTEM_PYTHON=/usr/bin/python3 \
  bash deploy/run_d3_kas_release.sh
```

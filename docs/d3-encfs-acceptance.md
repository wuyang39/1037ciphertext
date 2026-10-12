# D3 Gramine encrypted-FS 验收记录

> 运行编号：`d3-20261012T1930`
>
> 结论：**D3 受保护文件通过**。enclave 内可完整读取加密份额，宿主读取、
> 复制、篡改以及错误密钥均拿不到明文。

本记录对应 [后续开发总计划.md](后续开发总计划.md) 第 6 节。D4 及之后阶段
尚未执行。

## 1. 验收环境

| 项目 | 实测值 |
| --- | --- |
| 实例 | `iZuf6bjvfplpwleemaipwmZ`（`cn-shanghai`，与 D1 同一台） |
| Gramine | 1.9（`gramine`、`gramine-ratls-dcap`） |
| 加密文件工具 | `gramine-sgx-pf-crypt`、`gramine-sgx-pf-tamper` |
| 系统 | Ubuntu 22.04.5，内核 `5.15.0-191-generic` |
| `sgx.debug` | `false` |

## 2. 使用的工具

- [tee/gramine/encfs](../tee/gramine/encfs)：`encfs_probe`，从 stdin 读 16 字节
  密钥写入 `/dev/attestation/keys/<name>`，再把加密文件整份读完并输出前缀。
- [deploy/run_d3_encfs.sh](../deploy/run_d3_encfs.sh)：一键构建测试包、加密、
  删除明文、驱动六种情形并采集宿主侧证据。
- [infra/build_model_package.py](../infra/build_model_package.py)：生成 Tiny 模型的
  测试用明文份额与精度计划。
- [infra/d3_host_scan.py](../infra/d3_host_scan.py)、
  [infra/d3_encfs_evidence.py](../infra/d3_encfs_evidence.py)：宿主扫描与判决。

## 3. 流程

1. 在 enclave 外生成只用一次的 Tiny 模型包，取 `shares/P0.bin` 与
   `precision_plan.json` 作为待保护材料。
2. 用 `gramine-sgx-pf-crypt gen-key` 生成 16 字节 KDK（本次由宿主生成，作为
   KAS 待放行 `K_disk_P0` 的替身）。
3. `gramine-sgx-pf-crypt encrypt` 把两份材料写入 Gramine PF 存储；工具会把
   输出路径写进文件头，Gramine 在打开时校验该路径。
4. 删除全部明文副本，只保留加密存储。
5. 在 `gramine-sgx` 内运行探针：写入 KDK、整份读取、输出长度与前缀哈希。

## 4. 结果

| 情形 | 结果 | 说明 |
| --- | --- | --- |
| `accept-encrypted-share` | **accepted** | 46080 字节整份读完，前缀哈希与明文一致 |
| `deny-missing-key` | **rejected** | 未安装密钥，`EACCES` |
| `deny-wrong-key` | **rejected** | 16 字节错误密钥，`EACCES` |
| `deny-tampered-store` | **rejected** | 宿主翻转 1 字节，完整性校验失败，`EACCES` |
| `deny-copied-store` | **rejected** | 存储被复制到别的路径，内嵌路径不匹配，`EACCES` |
| `deny-host-plaintext-in-store` | **rejected** | 53248 字节 PF 存储中找不到明文份额、首 64 字节和末 64 字节 |
| `deny-host-plaintext-anywhere` | **rejected** | `artifacts/`、`/tmp`、`/var/log`、`$HOME` 全盘字节搜索无命中 |

关键值：

| 项目 | 值 |
| --- | --- |
| 明文份额 | 46080 字节，sha256 `e4150b9bc6d172cb4b7e81c332f3d994c3116488175fa9b6901c013de7fa095b` |
| 明文前缀 | 前 4096 字节，sha256 `14cd7bb478ee7ee9be85f7bc184a84e11369c76349c4f9c1ccf286cbdc1a1d37` |
| 加密存储文件 | 53248 字节，sha256 `9e963ebcb24afb272910695098f9e5520aa26e1d804fd7e9326bd69add79ef2f` |
| KDK（替身） | 16 字节，sha256 `af60382f98e640e385632817f4fca75a6b71c63bd0c8a1d70ace5effbe4d94ab` |
| 密钥通道 | `/dev/attestation/keys/a122_disk` |

## 5. 证据

完整证据目录：[docs/evidence/d3-20261012T1930](evidence/d3-20261012T1930)。

离线校验：

```bash
python -m infra.seal_evidence verify docs/evidence/d3-20261012T1930
```

目录内含 `d3-summary.json`、七种情形的原始日志与 JSON、两份 manifest、
`host-leak.txt`、`host-substring-search.txt`、`host-scan.json`、`shares.json`
和 `evidence.sha256`。

## 6. 本轮完成与遗留

已完成：

1. 真实 Gramine encrypted FS 挂载、整份读取和明文删除。
2. 宿主读取、复制、字符串搜索、字节搜索和篡改五类测试。
3. 缺密钥、错误密钥、篡改和复制存储四种 fail-closed 情形。
4. 生产 manifest 模板按实机 Gramine 1.9 schema 改写并实测通过
   （见第 7 节），同时补齐静态校验规则。
5. 后续运行 `d3-kas-20261012T115025Z` 把宿主生成的 KDK 换成 KAS 证明后放行
   的 `K_disk_P0`，并把固定 Worker 入口接上真实启动条件，见
   [d3-kas-release-acceptance.md](d3-kas-release-acceptance.md)。

遗留：

1. 镜像、环境变量和 core dump 扫描本轮覆盖到 `artifacts/`、`/tmp`、
   `/var/log` 与 `$HOME`；容器镜像与 core dump 采集待 D9。
2. D4–D10 尚未开始。

本节原先的两项遗留（KDK 由宿主生成、固定 Worker 入口未接入真实入口）已由
运行 `d3-kas-20261012T115025Z` 关闭，见
[d3-kas-release-acceptance.md](d3-kas-release-acceptance.md)。

## 7. 生产 manifest 修正

D1 记录已经指出 `tee/gramine/a122.manifest.template` 与实机 Gramine 1.9 不兼容。
本轮在实机 `graminelibos.Manifest.check()` 上逐条确认并修正：

| 原写法 | 1.9 的实际要求 | 修正 |
| --- | --- | --- |
| `loader.entrypoint = "file:<app>"` | 该键必须是 TOML 表，指向签名的 libsys | 应用入口改到 `libos.entrypoint` |
| `sgx.attestation_quote_type = "ecdsa"` | 1.9 schema 无此键，严格模式下直接报错 | 删除 |
| `fs.allowed_files` / `fs.allowed_dirs` | 额外文件白名单属于 `sgx.allowed_files` | 合并到 `sgx.allowed_files` |

修正后 `python -m infra.validate_gramine_manifest --values
deploy/gramine-values.example.json` 通过，渲染结果也通过实机
`graminelibos.Manifest.check()`。

## 8. 复现

```bash
git clone https://github.com/wuyang39/1037ciphertext.git
cd 1037ciphertext
sudo bash deploy/install_gramine_server.sh
uv venv --python 3.12 ~/a122-venv
uv pip install --python ~/a122-venv/bin/python \
  'cryptography>=48,<49' 'gmssl>=3.2.2,<4' 'pydantic>=2.5,<3' 'jsonschema>=4.26,<5'
uv pip install --python ~/a122-venv/bin/python \
  --index-url https://download.pytorch.org/whl/cpu torch
PYTHON=~/a122-venv/bin/python bash deploy/run_d3_encfs.sh
```

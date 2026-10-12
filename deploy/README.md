# A1-22 部署与本地联调

本目录提供不依赖真实 SGX 的本机 Linux/WSL 验证入口。服务器阶段脚本应在
D1 真实 Quote 通过后，基于这里的结果继续扩展，不能把本目录输出标记为 SGX
验收。

## 本机完整检查

Windows PowerShell：

```powershell
.\deploy\run_local_checks.ps1
```

Ubuntu/WSL：

```bash
chmod +x deploy/run_local_checks.sh deploy/run_local_nodes.sh
./deploy/run_local_checks.sh
```

脚本会执行：

1. 全部单元测试和 Python 编译检查。
2. 本地安全负例和 D1-D9 攻击矩阵。
3. D1 Linux/SGX 环境自检，并明确返回 `pending` 或 `accepted`。
4. 真实 localhost TCP/TLS 1.3 三节点 RSS 加法演示。
5. Tiny 模型导出、量化、三份额拆分和可选加密份额包。
6. release 构建、manifest 校验、源码脱敏扫描和证据目录封存。

输出默认写入 `artifacts/local-validation/`，不会提交到 Git。

## 三节点快速运行

```powershell
.\deploy\run_local_nodes.ps1
```

```bash
./deploy/run_local_nodes.sh
```

结果中的 `host_process_tls_termination=true` 表示 TLS 在普通 Linux 进程终止。
服务器阶段必须把证书和连接迁入 enclave，并由 YACL/BRPC 提供实际链路。

## 服务器阶段入口

服务器启动后先执行：

```bash
python -m infra.d1_environment_check --require-hardware \
  --output artifacts/server/d1-environment.json
```

该命令只有同时检测到 Linux、CPU SGX、`/dev/sgx_enclave`、
`/dev/sgx_provision`、`aesmd` 和 PCCS 配置时才会返回成功。环境检查成功仍
不代表 Quote 和 KAS 闭环完成。

## D1 服务器脚本

```bash
sudo bash deploy/install_gramine_server.sh   # 配置 packages.gramineproject.io 并安装 Gramine
bash deploy/install_spu_server.sh            # 建 3.11 venv 并安装 spu + 验收依赖
bash deploy/run_d1_gramine.sh                # 最小 Gramine-SGX 程序 + DCAP Quote 校验
bash deploy/run_d1_server.sh                 # 三种 Quote 探针 + KAS 闭环与四项拒绝负例
bash deploy/run_d3_encfs.sh                  # Gramine encrypted FS 挂载、明文删除与宿主侧拒绝
bash deploy/run_d3_kas_release.sh            # KAS 放行 K_disk_i + 固定 Worker 入口的真实启动条件
bash deploy/run_d4_accept.sh                 # D4 三节点传输、1,024 组 RSS 向量、抓包与五类 fail-closed
```

`run_d1_gramine.sh` 与 `run_d1_server.sh` 写入 `artifacts/server/<run-id>/d1/`；
`run_d3_encfs.sh` 写入 `artifacts/server/<run-id>/d3/`；`run_d3_kas_release.sh`
写入 `artifacts/server/<run-id>/d3-kas/`；`run_d4_accept.sh` 写入
`artifacts/server/<run-id>/d4/`。五个脚本都只用一次性签名密钥，不把私钥或
`K_disk_i` 放进证据目录。

`run_d4_accept.sh` 需要带 `spu` 的 3.11 解释器和 tcpdump 的抓包权限：

```bash
./deploy/install_spu_server.sh               # 每个 D4 节点都装同一个 spu 版本
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)"
PYTHON=~/a122-venv311/bin/python bash deploy/run_d4_accept.sh
```

`install_spu_server.sh` 默认用阿里云 PyPI 镜像：cn-shanghai 的实例走默认源会
在 `jaxlib` 上长时间停住，换源后同一条命令几十秒装完。

它默认把 P0/P1/P2 跑成同机三进程，是跨三台实例、三个 `gramine-sgx` 节点前
的固定彩排入口；结论与范围限定见 [d4-acceptance.md](../docs/d4-acceptance.md)。

`run_d3_kas_release.sh` 需要两个解释器：`PYTHON`（KAS 侧，带 `cryptography`
的 3.12 venv）与 `SYSTEM_PYTHON`（enclave 内加载的 `/usr/bin/python3`，需要
能 `import gmssl`）。用法：

```bash
export PYTHON=~/a122-venv/bin/python
export SYSTEM_PYTHON=/usr/bin/python3
bash deploy/run_d3_kas_release.sh            # 运行号取 UTC 时间戳
```

## 本机与服务器之间的代码同步

仓库里的证据目录包含运行产物，直接 clone 或 pull 即可；如果服务器到 GitHub
不稳，用 bundle 离线同步：

```powershell
git bundle create "$env:TEMP\a122-sync.bundle" main
scp "$env:TEMP\a122-sync.bundle" jiahao@<server>:~/
```

```bash
cd ~/1037ciphertext
git bundle unbundle ~/a122-sync.bundle          # 只打印 ref 与提交号
git update-ref refs/heads/a122-incoming <提交号>
git merge --ff-only a122-incoming
```

Ubuntu 22.04 自带 git 2.34，`git fetch <bundle> main:<新分支>` 会误报
`[up to date]`，所以这里用 `bundle unbundle` 加 `update-ref` 两步。

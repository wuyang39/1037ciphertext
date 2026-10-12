# D1 真实证明工具

本目录存放只能在真实 SGX 机器上运行、用于 D1 证明验收的两个工具。

## `quote_probe/`

最小 SGX enclave + 宿主程序，用 Intel DCAP 出进程（AESM）模式生成真实
ECDSA Quote，并把调用方给出的 64 字节 `REPORTDATA` 绑进 Quote。
`kas/binding.py` 把临时节点公钥、角色、release 和一次性 nonce 绑定成同一个
`REPORTDATA`，所以这个探针就是让 KAS 闭环跑在真实硬件上的入口。

```bash
make SGX_DEBUG=0            # 非 debug 启动，KAS 应放行
make SGX_DEBUG=1            # debug 启动，KAS 应拒绝
./quote_probe --report-data <128 位 hex> --out quote.bin
```

`SGX_DEBUG_FLAG` 由 SGX SDK 的 `sgx_urts.h` 根据 app 的构建模式决定，并传给
`sgx_create_enclave`，因此同一个 enclave 二进制在两种模式下会得到
`ATTRIBUTES.DEBUG=0` 或 `1`，而 `MRENCLAVE` 不变。这正是 D1 拒绝负例需要的
对照。

## `dcap_verifier/`

`a122_dcap_verify` 是 `kas/dcap.py` 使用的 `KAS_DCAP_VERIFY_BIN` 适配器：

```bash
make
./a122_dcap_verify --quote quote.bin --json
```

它用 Intel DCAP QVL 校验 Quote 的签名链和 TCB，并输出 KAS 需要的 JSON
（`mrenclave`、`mrsigner`、`isvsvn`、`debug`、`report_data_b64`），另外附带
DCAP 校验结果、结果前缀和 collateral 过期状态作为证据字段。

判定规则与 `sgx_qve_header.h` 一致：`0x0000` 以及 `0xA001`–`0xA003`、
`0xA007`、`0xA008` 视为通过（其中后几种是非终结性告警）；`INVALID_SIGNATURE`、
`REVOKED`、`UNSPECIFIED` 等终结性结果返回非零，使 KAS fail-closed。

这些都是 D1 部署工具，本机（无 SGX）无法运行；本机只能对 `infra/sgx_quote.py`
做结构解析测试。

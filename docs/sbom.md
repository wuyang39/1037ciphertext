# A1-22 Software Bill of Materials

本文件记录当前本地仓库的软件组件；服务器阶段应以实际镜像 digest 重新生成并冻结。

## Python 直接依赖

| 组件 | 约束 | 用途 |
|---|---|---|
| `cryptography` | `>=48,<49` | TLS 证书、CSR、CA 验证 |
| `fastapi` | `>=0.109,<0.110` | KAS HTTP 接口 |
| `gmssl` | `>=3.2.2,<4` | SM2/SM3/SM4 兼容原语 |
| `jsonschema` | `>=4.26,<5` | 协议 schema 校验 |
| `numpy` | `>=2.4,<3` | 模型导出、量化和 trace 数据处理 |
| `pydantic` | `>=2.5,<3` | KAS 请求/响应模型 |
| `torch` | `>=2.12,<3` | 明文参考模型和导出 |
| `uvicorn` | `>=0.27,<0.28` | KAS 本地/服务器运行 |

## 测试依赖

| 组件 | 约束 |
|---|---|
| `httpx` | `>=0.27,<0.28` |
| `pytest` | `>=9.1,<10` |

## 外部运行时

- Gramine、Intel SGX SDK、DCAP Quote Verification Library
- YACL/BRPC 及实际编译 hash
- 正式 SGX 镜像中的 Python wheel 和系统动态库

## 待服务器阶段冻结

1. `pip freeze` 输出和 wheel hash。
2. OCI image digest。
3. Gramine manifest 与测量结果。
4. YACL/BRPC 源码 commit、编译参数和 `spu_build_hash`。
5. DCAP QVL 版本、PCCS 配置和 Quote 验证报告。

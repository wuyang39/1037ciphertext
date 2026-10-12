#!/usr/bin/env bash
#
# Install the SGX runtime and the SPU python environment on a D4 node.
#
# Idempotent: re-running refreshes the packages and the venv. Every D4 node
# needs the same `spu` build, including the YACL/BRPC backend used for the
# cross-node links, so the version is pinned here rather than resolved per host.
#
# The default PyPI index stalls from cn-shanghai (one attempt sat idle for 47
# minutes on the jaxlib wheel), so the in-region Aliyun mirror is the default
# and `PIP_INDEX` switches it back.
#
# Usage:
#   ./deploy/install_spu_server.sh                  # install/refresh
#   ./deploy/install_spu_server.sh --check          # verify without installing
#
set -euo pipefail

VENV="${VENV:-$HOME/a122-venv311}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"
SPU_VERSION="${SPU_VERSION:-0.9.5}"
PIP_INDEX="${PIP_INDEX:-https://mirrors.aliyun.com/pypi/simple/}"
export UV_LOCK_TIMEOUT="${UV_LOCK_TIMEOUT:-1800}"
export UV_HTTP_TIMEOUT="${UV_HTTP_TIMEOUT:-300}"

export PATH="$HOME/.local/bin:$PATH"

if ! command -v uv >/dev/null; then
    echo "==> installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
uv --version

if [ "${1:-}" != "--check" ]; then
    if [ ! -x "$VENV/bin/python" ]; then
        echo "==> creating the $PYTHON_VERSION venv at $VENV"
        uv venv --python "$PYTHON_VERSION" "$VENV"
    fi
    echo "==> installing spu $SPU_VERSION and the acceptance dependencies"
    uv pip install --python "$VENV/bin/python" \
        --index-url "$PIP_INDEX" \
        --index-strategy unsafe-best-match \
        "spu==$SPU_VERSION" cryptography gmssl pydantic jsonschema
fi

echo "==> environment check"
"$VENV/bin/python" -V
"$VENV/bin/python" - <<'PY'
import importlib.metadata as meta

import spu
import spu.libspu  # noqa: F401  (the YACL/BRPC backend)

print("spu", meta.version("spu"), spu.__file__)
print("libspu ok")
PY
ls -l "$VENV/lib/python$("$VENV/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/spu/libspu.so"

echo "==> host SGX state"
ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
systemctl is-active aesmd 2>&1 || true

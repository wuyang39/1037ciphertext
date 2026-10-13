#!/usr/bin/env bash
#
# D4 acceptance with all three SPU parties inside gramine-sgx enclaves.
#
# This is the same grid and the same refusal cases as deploy/run_d4_accept.sh,
# except that every node process is started by the LibOS: the runner renders
# and signs one manifest, then hands `infra.d4_acceptance` a --node-wrapper of
# `gramine-sgx <manifest>`, so P0, P1 and P2 each come up in their own enclave
# with the same MRENCLAVE.
#
# The nodes still terminate TLS themselves with the run's local PKI; releasing
# those certificates from a verified DCAP Quote is the KAS step that follows.
#
# Usage:
#   ./deploy/run_d4_gramine.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d4-enclave-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d4"
WORK="$OUTPUT_ROOT/$RUN_ID/work/d4"
# The runner seals $OUT when it finishes, so its own log must live outside the
# evidence directory until the run is over. A redirect into $OUT would keep
# growing after the index was written and leave the seal describing a file that
# is no longer the one on disk.
ACCEPT_LOG="$OUTPUT_ROOT/$RUN_ID/d4-enclave-acceptance.txt"
PYTHON="${PYTHON:-$HOME/a122-venv311/bin/python}"
VENV="${VENV:-$(dirname "$(dirname "$PYTHON")")}"
SITE="${SITE:-$VENV/lib/python$( "$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])' )/site-packages}"
LIBSPU="${LIBSPU:-$SITE/spu/libspu.so}"
# The interpreter inside the enclave is the one uv installed; the venv is a set
# of symlinks around it, and the LibOS needs the real path.
UV_PYTHON="$(readlink -f "$PYTHON")"
UV_ROOT="$(dirname "$(dirname "$UV_PYTHON")")"
ARCH_LIBDIR="${ARCH_LIBDIR:-/lib/x86_64-linux-gnu}"
USR_LIBDIR="${USR_LIBDIR:-/usr/lib/x86_64-linux-gnu}"
ENCLAVE_SIZE="${ENCLAVE_SIZE:-4G}"
MAX_THREADS="${MAX_THREADS:-64}"
STACK_SIZE="${STACK_SIZE:-2M}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"
VECTORS="${VECTORS:-1024}"
BATCH="${BATCH:-64}"
NODE_TIMEOUT="${NODE_TIMEOUT:-900}"

for tool in gramine-manifest gramine-sgx-sign gramine-sgx gramine-sgx-gen-private-key tcpdump; do
    if ! command -v "$tool" >/dev/null; then
        echo "error: $tool is not installed" >&2
        exit 1
    fi
done
if [ ! -e /dev/sgx_enclave ]; then
    echo "error: /dev/sgx_enclave is missing; this host cannot back an enclave" >&2
    exit 1
fi
if [ ! -f "$LIBSPU" ]; then
    echo "error: libspu.so is not at $LIBSPU" >&2
    exit 1
fi

echo "run_id      : $RUN_ID"
echo "evidence    : $OUT"
echo "workspace   : $WORK/workspace"
echo "python      : $PYTHON ($("$PYTHON" -V 2>&1))"
echo "enclave     : size=$ENCLAVE_SIZE threads=$MAX_THREADS stack=$STACK_SIZE"
echo "instance_id : $INSTANCE_ID"

# The runner seals $OUT, so its own logs stay outside it.
rm -rf "$WORK" "$OUT"
mkdir -p "$WORK/enclave" "$OUT"

echo "==> provisioning the D4 workspace (PKI, vectors, node configs)"
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d4_acceptance \
    --mode provision \
    --workspace "$WORK/workspace" \
    --run-id "$RUN_ID" \
    --vectors "$VECTORS" \
    --batch "$BATCH" \
    > "$OUT/d4-enclave-provision.json" 2>&1

echo "==> rendering and signing the node manifest"
sed -e "s|@PYTHON@|$UV_PYTHON|g" \
    -e "s|@ARCH_LIBDIR@|$ARCH_LIBDIR|g" \
    -e "s|@USR_LIBDIR@|$USR_LIBDIR|g" \
    -e "s|@UV_ROOT@|$UV_ROOT|g" \
    -e "s|@SITE@|$SITE|g" \
    -e "s|@REPO@|$ROOT|g" \
    -e "s|@WORKSPACE@|$WORK/workspace|g" \
    -e "s|@LIBSPU@|$LIBSPU|g" \
    -e "s|@ENCLAVE_SIZE@|$ENCLAVE_SIZE|g" \
    -e "s|@MAX_THREADS@|$MAX_THREADS|g" \
    -e "s|@STACK_SIZE@|$STACK_SIZE|g" \
    "$ROOT/tee/gramine/enclave/spu_node.manifest.template" \
    > "$WORK/enclave/spu_node.manifest.template"
(
    cd "$WORK/enclave"
    gramine-manifest spu_node.manifest.template > spu_node.manifest
    gramine-sgx-gen-private-key sign.pem
    gramine-sgx-sign --manifest spu_node.manifest \
        --output spu_node.manifest.sgx --key sign.pem
) > "$OUT/spu_node-sign.txt" 2>&1
# The measurement the three nodes share; the signer prints it while sealing.
grep -i -m1 "^Measurement" "$OUT/spu_node-sign.txt" || true
cp "$WORK/enclave/spu_node.manifest" "$OUT/spu_node.manifest"
{
    echo "# run_id"
    echo "$RUN_ID"
    echo
    echo "# gramine"
    dpkg -l 'gramine*' 2>/dev/null | awk '/^ii/{print $2, $3}'
    gramine-sgx --version 2>&1
    echo
    echo "# interpreter"
    "$PYTHON" -V 2>&1
    readlink -f "$PYTHON"
    echo
    echo "# libspu"
    ls -l "$LIBSPU"
    echo
    echo "# sgx devices and aesmd"
    ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
    systemctl is-active aesmd 2>&1
    echo
    echo "# manifest parameters"
    echo "enclave_size=$ENCLAVE_SIZE max_threads=$MAX_THREADS stack=$STACK_SIZE"
} > "$OUT/d4-enclave-env.txt" 2>&1

echo "==> running the grid, the refusals and the capture with enclave nodes"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d4_acceptance \
    --mode loopback \
    --workspace "$WORK/workspace" \
    --out-dir "$OUT" \
    --run-id "$RUN_ID" \
    --python "$PYTHON" \
    --node-wrapper "gramine-sgx $WORK/enclave/spu_node" \
    --node-timeout "$NODE_TIMEOUT" \
    --vectors "$VECTORS" \
    --batch "$BATCH" \
    --capture \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION" \
    > "$ACCEPT_LOG" 2>&1
STATUS=$?
set -e

# Now that the log is complete, bring it inside the bundle and re-seal, so the
# index covers the whole log rather than the prefix that existed mid-run.
if [ -f "$ACCEPT_LOG" ]; then
    cp "$ACCEPT_LOG" "$OUT/d4-enclave-acceptance.txt"
fi
if [ -f "$OUT/evidence-index.json" ]; then
    PYTHONPATH="$ROOT" "$PYTHON" -m infra.seal_evidence seal "$OUT" >/dev/null
fi

echo "==> acceptance status: $STATUS"
ls -1 "$OUT"
if [ -f "$OUT/d4-summary.json" ]; then
    "$PYTHON" - "$OUT/d4-summary.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps(summary["verdicts"], indent=2, sort_keys=True))
print("evidence_complete:", summary["evidence_complete"])
print("missing:", summary["missing_files"])
PY
fi
exit "$STATUS"

#!/usr/bin/env bash
#
# D4 acceptance: the three-node transport, the 3PC RSS grid, and the
# fail-closed cases.
#
# On one host the runner starts P0/P1/P2 as separate processes that speak the
# real SPU/YACL/BRPC stack over TLS 1.3, drives 1,024 grid vectors from P0, then
# runs every refusal case:
#
#   positive grid   : add, mul, matmul, truncate, compare, reciprocal
#   plaintext probe : a plaintext request against each live listener
#   wrong-ca        : a peer certificate signed by another CA
#   wrong-san       : a peer certificate whose SAN names the wrong role
#   no-client-cert  : the local side presents no certificate
#   tls-disabled    : TLS turned off, the node must refuse to start
#
# The run captures the loopback traffic with tcpdump and seals the evidence
# directory: certificates, the capture and its TLS-only summary, the vector
# results, the communication trace and the refusal logs.
#
# The same script is the rehearsal for the three-instance run; there the nodes
# are `gramine-sgx` processes on separate hosts and the cluster file points at
# the private addresses instead of loopback.
#
# Usage:
#   ./deploy/run_d4_accept.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d4-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d4"
WORK="$OUTPUT_ROOT/$RUN_ID/work/d4"
LOGS="$OUTPUT_ROOT/$RUN_ID/logs"
PYTHON="${PYTHON:-python3}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"
VECTORS="${VECTORS:-1024}"
BATCH="${BATCH:-64}"

if [ ! -e /dev/sgx_enclave ]; then
    echo "warning: /dev/sgx_enclave is missing; this host cannot back a real enclave" >&2
fi

if ! command -v tcpdump >/dev/null; then
    echo "error: tcpdump is not installed" >&2
    exit 1
fi
# Capturing on the "any" device needs both capabilities. Reuse the ones a
# previous run installed, and only try to grant them when they are missing.
if ! getcap "$(command -v tcpdump)" 2>/dev/null | grep -q cap_net_raw; then
    if ! sudo -n setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)" 2>/dev/null; then
        echo "error: tcpdump lacks cap_net_raw; run 'sudo setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)' first" >&2
        exit 1
    fi
fi

echo "run_id      : $RUN_ID"
echo "evidence    : $OUT"
echo "workspace   : $WORK"
echo "instance_id : $INSTANCE_ID"
echo "python      : $PYTHON ($("$PYTHON" -V 2>&1))"

# The runner seals everything under $OUT, so its own logs stay outside: a
# redirect into the evidence directory would keep growing after the seal.
rm -rf "$WORK" "$OUT" "$LOGS"
mkdir -p "$WORK" "$OUT" "$LOGS"

echo "==> provisioning the D4 workspace (PKI, vectors, node configs)"
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d4_acceptance \
    --mode provision \
    --workspace "$WORK/workspace" \
    --run-id "$RUN_ID" \
    --vectors "$VECTORS" \
    --batch "$BATCH" \
    > "$LOGS/d4-provision.log" 2>&1

echo "==> running the positive grid, the fail-closed cases and the capture"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d4_acceptance \
    --mode loopback \
    --workspace "$WORK/workspace" \
    --out-dir "$OUT" \
    --run-id "$RUN_ID" \
    --python "$PYTHON" \
    --node-timeout 600 \
    --capture \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION" \
    > "$LOGS/d4-acceptance.log" 2>&1
STATUS=$?
set -e

echo "==> D4 evidence written to $OUT"
ls -1 "$OUT"
if [ -f "$OUT/d4-summary.json" ]; then
    echo
    echo "==> verdicts"
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

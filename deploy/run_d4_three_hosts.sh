#!/usr/bin/env bash
#
# D4 acceptance across three instances.
#
# Runs from the operator machine, which needs ssh access to all three hosts.
# It provisions the workspace on P0, ships the same tar to P1 and P2 at the
# same absolute path, starts one capture and one node per host, drives the
# 1,024-vector grid from P0, then pulls back the per-role summaries, node
# status, logs, vectors and communication trace and seals them.
#
# The nodes are ordinary processes over ssh; swapping in `gramine-sgx` is a
# change to the start command, not to this sequence.
#
# Usage:
#   CLUSTER=deploy/d4-three-hosts.json ./deploy/run_d4_three_hosts.sh
#   SSHK=~/.ssh/a122_id_sgx SSHP=secret ./deploy/run_d4_three_hosts.sh --dry-run
#   MODE=negatives ./deploy/run_d4_three_hosts.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${MODE:-run}"
RUN_ID="${RUN_ID:-d4-${MODE}-3host-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${OUT:-$ROOT/artifacts/server/$RUN_ID/d4-three}"
CLUSTER="${CLUSTER:-$ROOT/deploy/d4-three-hosts.json}"
PYTHON="${PYTHON:-python3}"

if [ ! -f "$CLUSTER" ]; then
    echo "error: cluster file not found: $CLUSTER" >&2
    echo "copy deploy/d4-three-hosts.example.json and fill in the three hosts" >&2
    exit 1
fi

echo "run_id  : $RUN_ID"
echo "cluster : $CLUSTER"
echo "evidence: $OUT"
echo "mode    : $MODE"

ARGS=(
    -m infra.d4_three_hosts "$MODE"
    --cluster "$CLUSTER"
    --out-dir "$OUT"
    --run-id "$RUN_ID"
)
[ -n "${SSHK:-}" ] && ARGS+=(--ssh-key "$SSHK")
[ -n "${SSHP:-}" ] && ARGS+=(--ssh-key-password "$SSHP")
[ -n "${SSH_USER:-}" ] && ARGS+=(--ssh-user "$SSH_USER")
if [ "$MODE" = "run" ]; then
    [ -n "${IFACE:-}" ] && ARGS+=(--iface "$IFACE")
    [ -n "${VECTORS:-}" ] && ARGS+=(--vectors "$VECTORS")
    [ -n "${BATCH:-}" ] && ARGS+=(--batch "$BATCH")
fi

cd "$ROOT"
PYTHONPATH="$ROOT" "$PYTHON" "${ARGS[@]}" "$@"

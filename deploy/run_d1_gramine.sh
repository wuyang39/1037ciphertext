#!/usr/bin/env bash
#
# D1 Gramine-SGX acceptance.
#
# Builds, signs and runs the minimal Gramine enclave probe from
# tee/gramine/hello, captures the DCAP quote it emits and verifies that quote
# with the deployment DCAP verifier. The D1 plan requires this minimal
# Gramine-SGX run before Gramine is trusted for the encrypted-FS stage.
#
# Usage:
#   ./deploy/run_d1_gramine.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d1-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d1"
WORK="$OUTPUT_ROOT/$RUN_ID/work/gramine-hello"
PYTHON="${PYTHON:-python3}"
VERIFIER="${VERIFIER:-$ROOT/tee/attestation/dcap_verifier/a122_dcap_verify}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"

for tool in gramine-manifest gramine-sgx-sign gramine-sgx cc; do
    if ! command -v "$tool" >/dev/null; then
        echo "error: $tool is not installed" >&2
        exit 1
    fi
done
if [ ! -e /dev/sgx_enclave ]; then
    echo "error: /dev/sgx_enclave is missing" >&2
    exit 1
fi

mkdir -p "$OUT" "$WORK"
rm -rf "${WORK:?}"/*
cp -r "$ROOT/tee/gramine/hello/." "$WORK/"

echo "run_id      : $RUN_ID"
echo "evidence    : $OUT"
echo "instance_id : $INSTANCE_ID"

{
    echo "# gramine packages"
    dpkg -l 'gramine*' 2>/dev/null | awk '/^ii/{print $2, $3}'
    echo
    echo "# gramine-sgx version"
    gramine-sgx --version 2>&1
    echo
    echo "# sgx devices"
    ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
    echo
    echo "# aesmd"
    systemctl is-active aesmd 2>&1
    echo
    echo "# dcap qcnl"
    cat /etc/sgx_default_qcnl.conf 2>&1
} > "$OUT/gramine-env.txt" 2>&1

echo "==> building hello probe"
cc -O2 -Wall -Wextra -o "$WORK/hello" "$WORK/hello.c"

echo "==> rendering manifest"
(
    # Relative ``file:`` URIs resolve against the working directory, so the
    # render step runs next to the probe it measures.
    cd "$WORK"
    gramine-manifest hello.manifest.template > hello.manifest
)
cp "$WORK/hello.manifest" "$OUT/gramine-hello.manifest"

echo "==> signing enclave"
(
    cd "$WORK"
    # The signing key decides MRSIGNER. It is generated per run and never
    # leaves the ignored work directory; a frozen release key replaces it
    # before any model material is loaded.
    gramine-sgx-gen-private-key "$WORK/enclave-key.pem"
    gramine-sgx-sign --manifest hello.manifest --output hello.manifest.sgx \
        --key "$WORK/enclave-key.pem"
)

echo "==> running gramine-sgx"
set +e
(
    cd "$WORK"
    gramine-sgx ./hello
) > "$OUT/gramine-hello.txt" 2> "$OUT/gramine-hello.stderr.txt"
STATUS=$?
set -e
echo "# gramine-sgx exit status: $STATUS" >> "$OUT/gramine-hello.txt"

if [ "$STATUS" -ne 0 ]; then
    echo "error: gramine-sgx failed with status $STATUS" >&2
    cat "$OUT/gramine-hello.stderr.txt" >&2
    exit "$STATUS"
fi

echo "==> verifying the Gramine quote"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d1_gramine_evidence \
    --output "$OUT" \
    --hello-output "$OUT/gramine-hello.txt" \
    --verifier "$VERIFIER" \
    --run-id "$RUN_ID" \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION"
EVIDENCE_STATUS=$?
set -e

echo "==> D1 Gramine evidence written to $OUT"
ls -1 "$OUT" | grep -i gramine || true
exit "$EVIDENCE_STATUS"

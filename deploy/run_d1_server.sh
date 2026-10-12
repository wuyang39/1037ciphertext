#!/usr/bin/env bash
#
# D1 server acceptance runner.
#
# Builds the SGX quote probe in three flavours and drives the real KAS
# attestation closed loop on an SGX-capable host:
#
#   * release  : SGX_DEBUG=0, the quote the KAS must accept
#   * debug    : SGX_DEBUG=1, ATTRIBUTES.DEBUG=1, the KAS must reject
#   * tampered : release build with a modified enclave image, the KAS must
#                reject it because MRENCLAVE no longer matches the release
#
# Usage:
#   ./deploy/run_d1_server.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d1-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d1"
SECRETS="$OUTPUT_ROOT/$RUN_ID/kas-secrets"
WORK="$OUTPUT_ROOT/$RUN_ID/work"
SGX_SDK="${SGX_SDK:-/opt/intel/sgxsdk}"
PYTHON="${PYTHON:-python3}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"

if [ ! -d "$SGX_SDK" ]; then
    echo "error: SGX SDK not found at $SGX_SDK" >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$SGX_SDK/environment" >/dev/null 2>&1 || true

mkdir -p "$OUT" "$SECRETS" "$WORK"

echo "run_id      : $RUN_ID"
echo "evidence    : $OUT"
echo "secrets     : $SECRETS"
echo "instance_id : $INSTANCE_ID"

echo "==> capturing environment evidence"
{
    echo "# host"
    uname -a
    echo
    echo "# os-release"
    head -5 /etc/os-release 2>&1
    echo
    echo "# cpu"
    lscpu 2>/dev/null | sed -n '1,20p'
    echo
    echo "# memory"
    free -m 2>&1
    echo
    echo "# disk"
    df -h / 2>&1
} > "$OUT/instance-check.txt" 2>&1

{
    echo "# SGX flags in /proc/cpuinfo"
    grep -o -E "sgx[a-z_]*" /proc/cpuinfo 2>/dev/null | sort -u
    echo
    echo "# SGX devices"
    ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
    echo
    echo "# aesmd"
    systemctl is-active aesmd 2>&1
    echo
    echo "# /etc/sgx_default_qcnl.conf"
    cat /etc/sgx_default_qcnl.conf 2>&1
} > "$OUT/cpuinfo-and-devices.txt" 2>&1

PYTHONPATH="$ROOT" "$PYTHON" -m infra.d1_environment_check \
    --output "$OUT/d1-environment.json" >/dev/null 2>&1 || true

if [ "${CAPTURE_SAMPLE_ENCLAVE:-1}" = "1" ]; then
    echo "==> running Intel SGX SampleEnclave"
    SAMPLE_WORK="$WORK/sample-enclave"
    rm -rf "$SAMPLE_WORK"
    mkdir -p "$SAMPLE_WORK"
    cp -r "$SGX_SDK/SampleCode/SampleEnclave" "$SAMPLE_WORK/"
    (
        cd "$SAMPLE_WORK/SampleEnclave" && make >/dev/null 2>&1 && ./app < /dev/null
    ) > "$OUT/sample-enclave.txt" 2>&1 || true
fi

echo "==> building DCAP verifier"
make -C "$ROOT/tee/attestation/dcap_verifier" >/dev/null

echo "==> building release quote probe"
cp -r "$ROOT/tee/attestation/quote_probe" "$WORK/probe-release"
make -C "$WORK/probe-release" SGX_SDK="$SGX_SDK" SGX_DEBUG=0 >/dev/null
SIGNING_KEY="$WORK/probe-release/Enclave/Enclave_private_sample.pem"

echo "==> building debug quote probe"
cp -r "$ROOT/tee/attestation/quote_probe" "$WORK/probe-debug"
cp "$SIGNING_KEY" "$WORK/probe-debug/Enclave/Enclave_private_sample.pem"
make -C "$WORK/probe-debug" SGX_SDK="$SGX_SDK" SGX_DEBUG=1 >/dev/null

echo "==> building tampered quote probe"
cp -r "$ROOT/tee/attestation/quote_probe" "$WORK/probe-tampered"
cp "$SIGNING_KEY" "$WORK/probe-tampered/Enclave/Enclave_private_sample.pem"
cat > "$WORK/probe-tampered/Enclave/Enclave.cpp" <<'ENCLAVE_CPP'
#include "Enclave_t.h"

#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

/* D1 tamper probe: a modified enclave image must produce a different
 * MRENCLAVE, so the KAS rejects it against the registered release. */
static volatile unsigned a122_tamper_marker = 0x41313232u; /* "A122" */

uint32_t enclave_create_report(const sgx_target_info_t *p_qe3_target,
                               const sgx_report_data_t *p_report_data,
                               sgx_report_t *p_report) {
    sgx_report_data_t report_data = {{0}};
    if (p_report_data != NULL) {
        report_data = *p_report_data;
    }
    if (a122_tamper_marker == 0xDEADBEEFu) {
        return (uint32_t)SGX_ERROR_UNEXPECTED;
    }
    return (uint32_t)sgx_create_report(p_qe3_target, &report_data, p_report);
}
ENCLAVE_CPP
make -C "$WORK/probe-tampered" SGX_SDK="$SGX_SDK" SGX_DEBUG=0 >/dev/null

echo "==> driving the KAS attestation closed loop"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d1_server_acceptance \
    --output "$OUT" \
    --secrets "$SECRETS" \
    --release-probe "$WORK/probe-release" \
    --debug-probe "$WORK/probe-debug" \
    --tampered-probe "$WORK/probe-tampered" \
    --verifier "$ROOT/tee/attestation/dcap_verifier/a122_dcap_verify" \
    --run-id "$RUN_ID" \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION"
STATUS=$?
set -e

echo "==> D1 evidence written to $OUT"
ls -1 "$OUT"
exit "$STATUS"

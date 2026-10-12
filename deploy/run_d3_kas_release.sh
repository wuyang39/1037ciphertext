#!/usr/bin/env bash
#
# D3 KAS-driven storage-key acceptance.
#
# Closes the two leftovers of the first Gramine encrypted-FS run:
#
#   * K_disk_i is no longer generated on the host. The KAS derives it and
#     releases it only as an SM2 ciphertext addressed to an enclave key that a
#     verified DCAP Quote binds in REPORTDATA.
#   * The fixed Worker entry starts only when the KAS-signed bundle matches the
#     release, the share epoch, the released key identifier, and the measured
#     Worker startup fingerprint.
#
# The shell entry point prepares the artifacts and then hands the case grid to
# infra/d3_kas_acceptance.py, which owns the enclave and KAS orchestration.
#
# Cases: accept, missing sealed key, tampered sealed key, wrong epoch, wrong
# startup binding, replayed challenge, second release for one epoch, and a
# release policy with a wrong measurement.
#
# Usage:
#   ./deploy/run_d3_kas_release.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d3-kas-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d3-kas"
WORK="$OUTPUT_ROOT/$RUN_ID/work/d3-kas"
PYTHON="${PYTHON:-python3}"
SYSTEM_PYTHON="${SYSTEM_PYTHON:-/usr/bin/python3}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"
KEY_NAME="${KEY_NAME:-a122_disk}"
ENCLAVE_SIZE="${ENCLAVE_SIZE:-2G}"
RELEASE_ID="${RELEASE_ID:-a122-d3-kas-v1}"
SHARE_EPOCH="${SHARE_EPOCH:-1}"
MODEL_VERSION="${MODEL_VERSION:-tiny-local-v1}"
KAS_PORT="${KAS_PORT:-18443}"
# The two library directories are substituted separately so the rendered
# manifest cannot end up with a "/usr//lib/..." path that Gramine treats as
# unmounted. PYTHONPATH_GUEST is folded into the manifest below.
ARCH_LIBDIR="${ARCH_LIBDIR:-/lib/x86_64-linux-gnu}"
USR_LIBDIR="${USR_LIBDIR:-/usr/lib/x86_64-linux-gnu}"
SHARE_NAME="model-share-P0.bin"
PLAN_NAME="precision-plan-P0.json"

log() { printf '==> %s\n' "$*"; }

for tool in gramine-manifest gramine-sgx-sign gramine-sgx \
            gramine-sgx-gen-private-key gramine-sgx-pf-crypt cc curl; do
    if ! command -v "$tool" >/dev/null; then
        echo "error: $tool is not installed" >&2
        exit 1
    fi
done
if [ ! -e /dev/sgx_enclave ]; then
    echo "error: /dev/sgx_enclave is missing" >&2
    exit 1
fi
if ! "$SYSTEM_PYTHON" -c "import gmssl" >/dev/null 2>&1; then
    echo "error: the in-enclave interpreter ($SYSTEM_PYTHON) cannot import gmssl" >&2
    echo "       install it with: $SYSTEM_PYTHON -m pip install --user gmssl" >&2
    exit 1
fi

mkdir -p "$OUT" "$WORK"
rm -rf "${WORK:?}"/*
mkdir -p "$WORK/kas" "$WORK/enclave" "$WORK/plain" "$WORK/store" "$WORK/bin" \
    "$WORK/control"

PACKAGE="$WORK/package"
PLAIN="$WORK/plain"
STORE_ROOT="$WORK/store"
STORE="$STORE_ROOT/secure"

{
    echo "# gramine packages"
    dpkg -l 'gramine*' 2>/dev/null | awk '/^ii/{print $2, $3}'
    echo
    echo "# interpreters"
    "$PYTHON" -V 2>&1
    "$SYSTEM_PYTHON" -V 2>&1
    "$SYSTEM_PYTHON" -c "import gmssl; print('gmssl', gmssl.__file__)" 2>&1
    echo
    echo "# sgx devices"
    ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
    echo
    echo "# aesmd"
    systemctl is-active aesmd 2>&1
    echo
    echo "# uname"
    uname -a
} > "$OUT/d3-kas-env.txt" 2>&1

log "building the test-only model package"
PYTHONPATH="$ROOT" "$PYTHON" -m infra.build_model_package \
    --output "$PACKAGE" \
    --model-version "$MODEL_VERSION" \
    --share-epoch "$SHARE_EPOCH" > "$OUT/model-package-build.json"
cp "$PACKAGE/shares/P0.bin" "$PLAIN/$SHARE_NAME"
cp "$PACKAGE/precision_plan.json" "$PLAIN/$PLAN_NAME"
cp "$PLAIN/$SHARE_NAME" "$WORK/needle.bin"

MODEL_MANIFEST_HASH="$("$PYTHON" -c '
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
' "$PACKAGE/package-manifest.json")"
PRECISION_PLAN_HASH="$("$PYTHON" -c '
import json, sys
print(json.load(open(sys.argv[1]))["precision_plan_hash"])
' "$PACKAGE/package-manifest.json")"
{
    echo "model_manifest_hash=$MODEL_MANIFEST_HASH"
    echo "precision_plan_hash=$PRECISION_PLAN_HASH"
} >> "$OUT/d3-kas-env.txt"

log "building the DCAP verifier the KAS uses"
(
    cd "$ROOT/tee/attestation/dcap_verifier"
    make clean > /dev/null
    make > /dev/null
)
cp "$ROOT/tee/attestation/dcap_verifier/a122_dcap_verify" "$WORK/bin/"

log "generating KAS secrets"
STORAGE_MASTER_HEX="$("$PYTHON" -c 'import secrets; print(secrets.token_bytes(32).hex())')"
PYTHONPATH="$ROOT" "$PYTHON" - "$WORK/kas" <<'PY'
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crypto.sm2 import SM2KeyPair

target = Path(sys.argv[1])
now = dt.datetime.now(dt.timezone.utc)
key = ec.generate_private_key(ec.SECP256R1())
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 KAS CA")])
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5))
    .not_valid_after(now + dt.timedelta(days=2))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
(target / "kas-ca-key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(target / "kas-ca-cert.pem").write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)
(target / "ticket-signing-key.hex").write_text(
    SM2KeyPair.generate().private_key + "\n",
    encoding="ascii",
)
PY
chmod 700 "$WORK/kas"

log "rendering and signing the enclave Worker"
# The in-enclave interpreter needs the same sys.path the host records, so the
# user-site gmssl install stays importable once /app is prepended.
PYTHONPATH_GUEST="$(env -u PYTHONPATH "$SYSTEM_PYTHON" -c \
    'import sys; print(":".join(p for p in sys.path if p))')"
sed -e "s|@ENCLAVE_SIZE@|$ENCLAVE_SIZE|g" \
    -e "s|@PYTHON@|$SYSTEM_PYTHON|g" \
    -e "s|@ARCH_LIBDIR@|$ARCH_LIBDIR|g" \
    -e "s|@USR_LIBDIR@|$USR_LIBDIR|g" \
    -e "s|@PYTHONPATH@|$PYTHONPATH_GUEST|g" \
    -e "s|@REPO_GUEST_DIR@|/app|g" \
    -e "s|@REPO_HOST_DIR@|$ROOT|g" \
    -e "s|@CONTROL_GUEST_DIR@|/control|g" \
    -e "s|@CONTROL_HOST_DIR@|$WORK/control|g" \
    -e "s|@SECURE_GUEST_DIR@|/secure|g" \
    -e "s|@SECURE_HOST_DIR@|$STORE_ROOT|g" \
    -e "s|@KEY_NAME@|$KEY_NAME|g" \
    "$ROOT/tee/gramine/enclave/encfs_worker.manifest.template" \
    > "$WORK/enclave/encfs_worker.manifest.template"
(
    cd "$WORK/enclave"
    gramine-manifest encfs_worker.manifest.template > encfs_worker.manifest
    gramine-sgx-gen-private-key sign.pem
    gramine-sgx-sign --manifest encfs_worker.manifest \
        --output encfs_worker.manifest.sgx --key sign.pem
)
cp "$WORK/enclave/encfs_worker.manifest" "$OUT/encfs_worker.manifest"

log "packaging the encrypted store with the KAS-derived disk key"
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_packager \
    --master-hex "$STORAGE_MASTER_HEX" \
    --role P0 \
    --release-id "$RELEASE_ID" \
    --share-epoch "$SHARE_EPOCH" \
    --purpose model-store \
    --plaintext-dir "$PLAIN" \
    --store-dir "$STORE" \
    --output "$OUT/packaging.json" \
    --scrub-plaintext | tee "$OUT/packaging.txt"

log "running the D3 case grid"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_kas_acceptance \
    --root "$ROOT" \
    --work "$WORK" \
    --out "$OUT" \
    --python "$PYTHON" \
    --system-python "$SYSTEM_PYTHON" \
    --release-id "$RELEASE_ID" \
    --share-epoch "$SHARE_EPOCH" \
    --model-version "$MODEL_VERSION" \
    --model-manifest-hash "$MODEL_MANIFEST_HASH" \
    --precision-plan-hash "$PRECISION_PLAN_HASH" \
    --storage-master-hex "$STORAGE_MASTER_HEX" \
    --key-name "$KEY_NAME" \
    --share-name "$SHARE_NAME" \
    --kas-port "$KAS_PORT" \
    --cloud-region "$CLOUD_REGION" \
    --instance-id "$INSTANCE_ID" \
    > "$OUT/acceptance.txt" 2>&1
ACCEPTANCE_STATUS=$?
set -e
cp "$WORK/kas/release-policy.json" "$OUT/kas-release-policy.json" 2>/dev/null || true

log "capturing the host-side view of the encrypted store"
{
    echo "# store listing"
    ls -l "$STORE"
    echo
    echo "# host cat of the encrypted share (first 256 bytes, xxd)"
    xxd -l 256 "$STORE/$SHARE_NAME"
    echo
    echo "# host strings of the encrypted share"
    strings -n 8 "$STORE/$SHARE_NAME" | head -20 || true
    echo
    echo "# plaintext share directory after packaging (expected to be scrubbed)"
    ls -l "$PLAIN"
    echo
    echo "# packager key files left behind (expected: none)"
    ls -l /dev/shm 2>/dev/null | grep a122-pfkey || echo "none"
} > "$OUT/host-leak.txt" 2>&1

echo "==> host byte-substring search for the plaintext share"
PYTHONPATH="$ROOT" "$PYTHON" - "$PLAIN/$SHARE_NAME" "$STORE/$SHARE_NAME" \
    > "$OUT/host-substring-search.txt" 2>&1 <<'PY'
import sys
from pathlib import Path

plain = Path(sys.argv[1])
stored = Path(sys.argv[2]).read_bytes()
if plain.is_file():
    needles = {"full_share": plain.read_bytes()}
else:
    needles = {}
needles["first_64_bytes"] = b"" if not needles else needles["full_share"][:64]
for name, needle in needles.items():
    print(f"{name}: length={len(needle)} found_in_store={bool(needle) and needle in stored}")
print(f"plaintext_share_on_host={plain.is_file()} stored_bytes={len(stored)}")
PY

log "scanning the instance for plaintext share material"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_host_scan \
    --output "$OUT/host-scan.json" \
    --needle-file "$WORK/needle.bin" \
    --root "$OUTPUT_ROOT/$RUN_ID" \
    --root /tmp \
    --root /var/log \
    --root "$HOME" \
    --skip "$WORK/needle.bin" \
    > "$OUT/host-scan.txt" 2>&1
SCAN_STATUS=$?
set -e
{
    echo "# needle bytes: $(stat -c%s "$WORK/needle.bin")"
    echo "# host scan status: $SCAN_STATUS (0 means no plaintext share on the host)"
    echo
    echo "# files on the host whose name matches the share"
    find "$HOME" /tmp -name "$SHARE_NAME" 2>/dev/null | head -20 || true
} >> "$OUT/host-scan.txt"
rm -f "$WORK/needle.bin"

log "collecting the D3 KAS-release verdicts"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_kas_release_evidence \
    --output "$OUT" \
    --run-id "$RUN_ID" \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION"
EVIDENCE_STATUS=$?
set -e

echo "==> acceptance status: $ACCEPTANCE_STATUS"
echo "==> evidence status: $EVIDENCE_STATUS"
ls -1 "$OUT"
if [ "$EVIDENCE_STATUS" -ne 0 ] || [ "$ACCEPTANCE_STATUS" -ne 0 ]; then
    exit 1
fi

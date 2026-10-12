#!/usr/bin/env bash
#
# D3 Gramine encrypted-FS acceptance.
#
# Builds a test-only model package, encrypts its P0 share and preprocessing
# plan into a Gramine encrypted-files store, and then probes that store from
# inside a real Gramine-SGX enclave:
#
#   accept-encrypted-share : the enclave reads the share with the right key
#   deny-missing-key       : no KDK provisioned, the mount must refuse
#   deny-wrong-key         : a different 16-byte KDK must not decrypt
#   deny-tampered-store    : a host byte flip must be detected as integrity loss
#   deny-copied-store      : the store copied to another path must be refused
#
# The host-side leak checks (direct read, string search, byte-substring search
# for the plaintext share) are captured alongside the enclave results.
#
# Usage:
#   ./deploy/run_d3_encfs.sh [RUN_ID]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-${RUN_ID:-d3-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/artifacts/server}"
OUT="$OUTPUT_ROOT/$RUN_ID/d3"
WORK="$OUTPUT_ROOT/$RUN_ID/work/d3-encfs"
PYTHON="${PYTHON:-python3}"
CLOUD_REGION="${CLOUD_REGION:-cn-shanghai}"
INSTANCE_ID="${INSTANCE_ID:-$(hostname)}"
KEY_NAME="${KEY_NAME:-a122_disk}"
ENCLAVE_SIZE="${ENCLAVE_SIZE:-2G}"
SHARE_NAME="model-share-P0.bin"
PLAN_NAME="precision-plan-P0.json"

for tool in gramine-manifest gramine-sgx-sign gramine-sgx \
            gramine-sgx-gen-private-key gramine-sgx-pf-crypt cc; do
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

STORE="$WORK/secure"
COPY_STORE="$WORK/secure-copy"
PLAIN="$WORK/plain"
mkdir -p "$STORE" "$PLAIN"

echo "run_id      : $RUN_ID"
echo "evidence    : $OUT"
echo "instance_id : $INSTANCE_ID"
echo "key_name    : $KEY_NAME"

{
    echo "# gramine packages"
    dpkg -l 'gramine*' 2>/dev/null | awk '/^ii/{print $2, $3}'
    echo
    echo "# encrypted-files tools"
    gramine-sgx-pf-crypt --help 2>&1 | sed -n '1,6p'
    echo
    echo "# sgx devices"
    ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1
    echo
    echo "# aesmd"
    systemctl is-active aesmd 2>&1
    echo
    echo "# argv"
    printf '%s\n' "$(uname -a)"
} > "$OUT/encfs-env.txt" 2>&1

echo "==> building the test-only model package (plaintext, outside the enclave)"
PYTHONPATH="$ROOT" "$PYTHON" -m infra.build_model_package \
    --output "$WORK/package" > "$OUT/model-package-build.json"
cp "$WORK/package/shares/P0.bin" "$PLAIN/$SHARE_NAME"
cp "$WORK/package/precision_plan.json" "$PLAIN/$PLAN_NAME"

echo "==> generating the stand-in disk key"
gramine-sgx-pf-crypt gen-key -w "$WORK/kdk.bin" >/dev/null

echo "==> encrypting the share into the Gramine PF store"
gramine-sgx-pf-crypt encrypt -i "$PLAIN" -o "$STORE" -w "$WORK/kdk.bin" \
    > "$OUT/pf-crypt-encrypt.txt" 2>&1

echo "==> compiling the enclave probe"
cp -r "$ROOT/tee/gramine/encfs/." "$WORK/"
cc -O2 -Wall -Wextra -o "$WORK/encfs_probe" "$WORK/encfs_probe.c"

render_manifest() {
    local target="$1" guest_dir="$2"
    sed -e "s|@ENCLAVE_SIZE@|$ENCLAVE_SIZE|" \
        -e "s|@SECURE_GUEST_DIR@|$guest_dir|" \
        -e "s|@SECURE_HOST_DIR@|$guest_dir|" \
        -e "s|@KEY_NAME@|$KEY_NAME|" \
        "$WORK/encfs.manifest.template" > "$WORK/$target.template"
    (
        cd "$WORK"
        gramine-manifest "$target.template" > "$target.manifest"
        gramine-sgx-sign --manifest "$target.manifest" \
            --output "$target.manifest.sgx" --key "$WORK/sign.pem" >/dev/null
    )
    cp "$WORK/$target.manifest" "$OUT/$target.manifest"
}

echo "==> signing the enclave"
gramine-sgx-gen-private-key "$WORK/sign.pem" >/dev/null
render_manifest encfs "$STORE"

run_probe() {
    # run_probe <label> <manifest-name> <key-file-or-empty> <guest-file>
    local label="$1" manifest="$2" keyfile="$3" guest_file="$4"
    if [ -n "$keyfile" ]; then
        (
            cd "$WORK"
            cat "$keyfile" | gramine-sgx "./$manifest" "$KEY_NAME" "$guest_file"
        ) > "$OUT/$label.txt" 2>&1 || true
    else
        (
            cd "$WORK"
            cat /dev/null | gramine-sgx "./$manifest" "$KEY_NAME" "$guest_file"
        ) > "$OUT/$label.txt" 2>&1 || true
    fi
}

echo "==> capturing the host-side view of the encrypted store"
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
    echo "# plaintext share kept for comparison only, then removed"
    ls -l "$PLAIN"
} > "$OUT/host-leak.txt" 2>&1

echo "==> host byte-substring search for the plaintext share"
PYTHONPATH="$ROOT" "$PYTHON" - "$PLAIN/$SHARE_NAME" "$STORE/$SHARE_NAME" \
    > "$OUT/host-substring-search.txt" 2>&1 <<'PY'
import sys
from pathlib import Path

plain = Path(sys.argv[1]).read_bytes()
stored = Path(sys.argv[2]).read_bytes()
needles = {"full_share": plain, "first_64_bytes": plain[:64], "last_64_bytes": plain[-64:]}
for name, needle in needles.items():
    print(f"{name}: length={len(needle)} found_in_store={needle in stored}")
print(f"plaintext_bytes={len(plain)} stored_bytes={len(stored)}")
PY

echo "==> recording plaintext hashes, then deleting the plaintext copies"
PYTHONPATH="$ROOT" "$PYTHON" - "$OUT" "$PLAIN" "$SHARE_NAME" "$PLAN_NAME" \
    "$STORE" "$WORK/kdk.bin" > /dev/null 2>&1 <<'PY'
import hashlib
import json
import sys
from pathlib import Path

from infra.evidence import sha256_file

out, plain_dir, share_name, plan_name, store_dir, kdk = (
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4],
    Path(sys.argv[5]), Path(sys.argv[6]),
)
record = {
    "share_name": share_name,
    "share_bytes": (plain_dir / share_name).stat().st_size,
    "share_sha256": sha256_file(plain_dir / share_name),
    "share_prefix_bytes": 4096,
    "share_prefix_sha256": hashlib.sha256(
        (plain_dir / share_name).read_bytes()[:4096]
    ).hexdigest(),
    "plan_name": plan_name,
    "plan_bytes": (plain_dir / plan_name).stat().st_size,
    "plan_sha256": sha256_file(plain_dir / plan_name),
    "kdk_sha256": sha256_file(kdk),
    "store_files": [
        {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(store_dir.iterdir())
        if path.is_file()
    ],
}
(out / "shares.json").write_text(
    json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
PY
cp "$PLAIN/$SHARE_NAME" "$WORK/needle.bin"
rm -f "$PLAIN/$SHARE_NAME" "$PLAIN/$PLAN_NAME"
rmdir "$PLAIN"
# The package builder also wrote plaintext shares. D3 keeps only the encrypted
# store, so the P0 plaintext share is removed from that build output too.
rm -f "$WORK/package/shares/P0.bin"
echo "plaintext P0 share files left under work: $(find "$WORK" -name "$SHARE_NAME" | wc -l)" \
    >> "$OUT/host-leak.txt"

echo "==> accept: enclave reads the encrypted share"
run_probe encfs-accept encfs "$WORK/kdk.bin" "$STORE/$SHARE_NAME"

echo "==> deny: no key provisioned"
run_probe encfs-deny-missing-key encfs "" "$STORE/$SHARE_NAME"

echo "==> deny: wrong key"
head -c 16 /dev/urandom > "$WORK/wrong-kdk.bin"
run_probe encfs-deny-wrong-key encfs "$WORK/wrong-kdk.bin" "$STORE/$SHARE_NAME"

echo "==> deny: tampered store (host byte flip)"
cp "$STORE/$SHARE_NAME" "$WORK/share.backup"
PYTHONPATH="$ROOT" "$PYTHON" - "$STORE/$SHARE_NAME" > /dev/null 2>&1 <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
offset = len(data) // 2
data[offset] ^= 0x5A
path.write_bytes(bytes(data))
print(f"flipped byte at offset {offset}")
PY
run_probe encfs-deny-tampered-store encfs "$WORK/kdk.bin" "$STORE/$SHARE_NAME"
cp "$WORK/share.backup" "$STORE/$SHARE_NAME"

echo "==> deny: store copied to another path"
cp -r "$STORE" "$COPY_STORE"
render_manifest encfs-copy "$COPY_STORE"
run_probe encfs-deny-copied-store encfs-copy "$WORK/kdk.bin" \
    "$COPY_STORE/$SHARE_NAME"

echo "==> scanning the instance for plaintext share material"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_host_scan \
    --output "$OUT/host-scan.json" \
    --needle-file "$WORK/needle.bin" \
    --root "$OUTPUT_ROOT" \
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
    echo
    echo "# gramine processes observed during the run"
    ps -eo pid,args | grep -i gramine | grep -v grep | head -5 || true
} >> "$OUT/host-scan.txt"
rm -f "$WORK/needle.bin"

echo "==> collecting the D3 verdicts"
set +e
PYTHONPATH="$ROOT" "$PYTHON" -m infra.d3_encfs_evidence \
    --output "$OUT" \
    --run-id "$RUN_ID" \
    --instance-id "$INSTANCE_ID" \
    --cloud-region "$CLOUD_REGION"
STATUS=$?
set -e

echo "==> D3 evidence written to $OUT"
ls -1 "$OUT"
exit "$STATUS"

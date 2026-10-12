"""The fixed Worker entry that runs inside a Gramine-SGX enclave.

Startup order, and every step fails closed:

1. generate a temporary SM2 key inside the enclave;
2. bind that key, the role, the release, and the KAS challenge nonce into
   REPORTDATA and read the DCAP Quote;
3. publish the Quote and public key to a host-visible control directory;
4. wait for the KAS-sealed bundle that the host relays back;
5. open the bundle inside the enclave and check the key identifier, the Worker
   startup fingerprint, the share epoch, and the release expiry;
6. install the derived 16-byte key as the Gramine encrypted-FS key;
7. read the protected model share end to end.

The host mediates steps 3 and 4, so it controls neither the key nor the checks:
the bundle is an SM2 ciphertext addressed to the temporary enclave key, and the
KAS only produces it for a Quote that satisfies the release policy.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

from crypto.enclave_key import (
    EnclaveKeyError,
    enclave_report_data,
    open_bundle,
    protected_files_key,
    worker_startup_digest,
)
from crypto.sm2 import SM2KeyPair


REPORT_DATA_PATH = "/dev/attestation/user_report_data"
QUOTE_PATH = "/dev/attestation/quote"
KEY_PATH_TEMPLATE = "/dev/attestation/keys/%s"
BEGIN_MARKER = "A1_22_ENCFS_BEGIN"
END_MARKER = "A1_22_ENCFS_END"
DEFAULT_TIMEOUT_SECONDS = 180
POLL_INTERVAL_SECONDS = 0.2


class EnclaveWorkerRejected(RuntimeError):
    """The Worker entry refused to start the measured inference path."""


class _Fields:
    """Line-oriented ``key=value`` output that the evidence parser reads."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def set(self, name: str, value: object) -> None:
        self._values[name] = str(value)

    def emit(self) -> None:
        for name in sorted(self._values):
            print(f"{name}={self._values[name]}", flush=True)


def _write_report_data(fields: _Fields, report_data: bytes) -> None:
    with open(REPORT_DATA_PATH, "wb") as handle:
        handle.write(report_data)
    fields.set("report_data_len", len(report_data))
    fields.set("report_data_sha256", hashlib.sha256(report_data).hexdigest())


def _read_quote(control: Path, fields: _Fields) -> None:
    with open(QUOTE_PATH, "rb") as handle:
        quote = handle.read()
    if not quote:
        raise EnclaveWorkerRejected("Gramine returned an empty DCAP Quote")
    (control / "quote.bin").write_bytes(quote)
    fields.set("quote_bytes", len(quote))
    fields.set("quote_sha256", hashlib.sha256(quote).hexdigest())


def _wait_for_sealed(control: Path, timeout: float, fields: _Fields) -> bytes:
    deadline = time.monotonic() + timeout
    sealed_path = control / "sealed.hex"
    (control / "ready").write_text("ready\n", encoding="ascii")
    while time.monotonic() < deadline:
        if sealed_path.is_file():
            document = sealed_path.read_text(encoding="ascii").strip()
            if document:
                fields.set("sealed_seen", 1)
                fields.set("sealed_bytes", len(document) // 2)
                return bytes.fromhex(document)
        time.sleep(POLL_INTERVAL_SECONDS)
    fields.set("sealed_seen", 0)
    raise EnclaveWorkerRejected("the sealed storage key never arrived")


def _install_protected_files_key(key_name: str, key: bytes, fields: _Fields) -> None:
    path = KEY_PATH_TEMPLATE % key_name
    with open(path, "wb") as handle:
        written = handle.write(key)
    if written != len(key):
        raise EnclaveWorkerRejected("the encrypted-FS key was only partly written")
    fields.set("pf_key_bytes", written)


def _read_protected_file(
    guest_file: Path,
    prefix_bytes: int,
    fields: _Fields,
) -> None:
    digest = hashlib.sha256()
    prefix = bytearray()
    total = 0
    with open(guest_file, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            if len(prefix) < prefix_bytes:
                take = min(prefix_bytes - len(prefix), len(chunk))
                prefix.extend(chunk[:take])
            total += len(chunk)
    fields.set("read_ok", 1)
    fields.set("content_len", total)
    fields.set("content_sha256", digest.hexdigest())
    fields.set("content_prefix_sha256", hashlib.sha256(bytes(prefix)).hexdigest())


def _check_bundle(
    *,
    sealed: bytes,
    private_key: str,
    args: argparse.Namespace,
    fields: _Fields,
    now_unix: int | None = None,
) -> dict[str, object]:
    try:
        bundle = open_bundle(private_key, sealed)
    except EnclaveKeyError as exc:
        fields.set("bundle_open_ok", 0)
        fields.set("bundle_error", str(exc))
        raise EnclaveWorkerRejected("the sealed storage-key bundle was refused") from exc
    fields.set("bundle_open_ok", 1)
    key_id_match = not args.expected_key_id or bundle["key_id"] == args.expected_key_id
    fields.set("key_id_match", int(key_id_match))
    if not key_id_match:
        raise EnclaveWorkerRejected("released key identifier does not match the release")

    expected_startup = worker_startup_digest(
        role=args.role,
        release_id=args.release_id,
        model_version=args.model_version,
        model_manifest_hash=args.model_manifest_hash,
        precision_plan_hash=args.precision_plan_hash,
        share_epoch=args.share_epoch,
        expected_storage_key_id=str(bundle["key_id"]),
    )
    fields.set("startup_hash_ok", int(expected_startup == bundle["startup_hash"]))
    fields.set("startup_hash", expected_startup)
    if expected_startup != bundle["startup_hash"]:
        raise EnclaveWorkerRejected(
            "the KAS did not authorize this Worker startup configuration"
        )

    fields.set("share_epoch_ok", int(bundle["share_epoch"] == args.share_epoch))
    if bundle["share_epoch"] != args.share_epoch:
        raise EnclaveWorkerRejected("released share epoch does not match the startup")

    now = int(time.time()) if now_unix is None else now_unix
    fields.set("release_expires_at_unix", bundle["expires_at_unix"])
    fields.set("host_now_unix", now)
    fields.set("lease_fresh_ok", int(now < int(bundle["expires_at_unix"])))
    if now >= int(bundle["expires_at_unix"]):
        raise EnclaveWorkerRejected("the released storage key has expired")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-dir", type=Path, required=True)
    parser.add_argument("--key-name", default="a122_disk")
    parser.add_argument("--guest-file", type=Path, required=True)
    parser.add_argument("--role", default="P0")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--share-epoch", type=int, required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--model-manifest-hash", required=True)
    parser.add_argument("--precision-plan-hash", required=True)
    parser.add_argument("--expected-key-id", default="")
    parser.add_argument("--prefix-bytes", type=int, default=4096)
    parser.add_argument(
        "--release-timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    args = parser.parse_args(argv)

    control = args.control_dir
    control.mkdir(parents=True, exist_ok=True)
    fields = _Fields()
    fields.set("role", args.role)
    fields.set("release_id", args.release_id)
    fields.set("share_epoch", args.share_epoch)
    fields.set("model_version", args.model_version)
    fields.set("read_ok", 0)
    print(BEGIN_MARKER, flush=True)

    try:
        nonce = bytes.fromhex(
            (control / "nonce.hex").read_text(encoding="ascii").strip()
        )
        key_pair = SM2KeyPair.generate()
        fields.set("enclave_public_key", key_pair.public_key)
        _write_report_data(
            fields,
            enclave_report_data(
                public_key=key_pair.public_key,
                role=args.role,
                release_id=args.release_id,
                nonce=nonce,
            ),
        )
        _read_quote(control, fields)
        (control / "enclave_public_key.hex").write_text(
            key_pair.public_key + "\n",
            encoding="ascii",
        )
        sealed = _wait_for_sealed(control, args.release_timeout, fields)
        bundle = _check_bundle(
            sealed=sealed,
            private_key=key_pair.private_key,
            args=args,
            fields=fields,
        )
        pf_key = protected_files_key(bundle["storage_key"])
        _install_protected_files_key(args.key_name, pf_key, fields)
        fields.set("key_installed", 1)
        del pf_key, bundle, sealed, key_pair
        _read_protected_file(args.guest_file, args.prefix_bytes, fields)
    except (EnclaveWorkerRejected, EnclaveKeyError, OSError, ValueError) as exc:
        fields.set("reject_reason", f"{type(exc).__name__}: {exc}")
        fields.set("key_installed", 0)
        fields.emit()
        print(END_MARKER, flush=True)
        return 3

    fields.set("worker_started", 1)
    fields.emit()
    print(END_MARKER, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

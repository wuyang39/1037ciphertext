"""Attested enclave-key binding and sealed storage-key bundles.

The KAS releases a per-node disk key only after a DCAP Quote whose REPORTDATA
binds the enclave's freshly generated SM2 public key. The key travels back as
an SM2 ciphertext that only that enclave can open, so the host relaying the
bytes never learns ``K_disk_i``.

This module is the enclave-safe surface for that exchange. A Gramine-SGX
enclave imports it, so it depends only on ``hashlib``/``hmac`` and the
repository's own SM2/SM3 code: no pydantic, FastAPI, or ``tee`` package, whose
imports pull in native extension modules that an enclave must not need.

Sharing the startup fingerprint here is what lets the KAS and the enclave
derive the same value from the same tuple of measured startup inputs.
"""

from __future__ import annotations

import hashlib
import hmac

from .sm2 import SM2Error, sm2_decrypt, sm2_encrypt, validate_sm2_public_key
from .sm3 import hkdf


REPORT_DATA_DOMAIN = b"A1-22:enclave-key-report-data:v1\0"
STORAGE_KEY_ID_DOMAIN = b"A1-22:storage-key-id:v1\0"
PF_KEY_SALT = b"A1-22:pf-key-salt:v1\0"
PF_KEY_INFO = b"A1-22:gramine-protected-files-key:v1\0"
PF_KEY_BYTES = 16

BUNDLE_MAGIC = b"A122DSK1"
BUNDLE_VERSION = 1
BUNDLE_BYTES = 128
_BUNDLE_KEY_ID_OFFSET = 16
_BUNDLE_STARTUP_OFFSET = 48
_BUNDLE_EPOCH_OFFSET = 80
_BUNDLE_EXPIRY_OFFSET = 88
_BUNDLE_KEY_OFFSET = 96

STORAGE_KEY_BYTES = 32

STARTUP_DOMAIN = b"A1-22:worker-startup:v1\0"


class EnclaveKeyError(ValueError):
    """A sealed bundle or REPORTDATA binding is malformed."""


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise EnclaveKeyError("binding field is too long")
    return len(value).to_bytes(4, "big") + value


def enclave_report_data(
    *,
    public_key: str,
    role: str,
    release_id: str,
    nonce: bytes,
) -> bytes:
    """Bind the enclave SM2 key, role, release, and fresh KAS nonce."""
    public_key = validate_sm2_public_key(public_key)
    if len(nonce) != 32:
        raise EnclaveKeyError("KAS nonce must be 32 bytes")
    transcript = b"".join(
        (
            REPORT_DATA_DOMAIN,
            _length_prefixed(bytes.fromhex(public_key)),
            _length_prefixed(role.encode("utf-8")),
            _length_prefixed(release_id.encode("utf-8")),
            _length_prefixed(nonce),
        )
    )
    return hashlib.sha256(transcript).digest() + b"\x00" * 32


def verify_enclave_report_data(
    actual: bytes,
    *,
    public_key: str,
    role: str,
    release_id: str,
    nonce: bytes,
) -> bool:
    """Constant-time check of the 64-byte REPORTDATA against the binding."""
    try:
        expected = enclave_report_data(
            public_key=public_key,
            role=role,
            release_id=release_id,
            nonce=nonce,
        )
    except (EnclaveKeyError, SM2Error):
        return False
    return hmac.compare_digest(actual, expected)


def storage_key_id(storage_key: bytes) -> str:
    """Return the KAS storage-key identifier for a derived key."""
    if len(storage_key) != STORAGE_KEY_BYTES:
        raise EnclaveKeyError("storage key must contain 32 bytes")
    return hashlib.sha256(STORAGE_KEY_ID_DOMAIN + storage_key).hexdigest()


def worker_startup_digest(
    *,
    role: str,
    release_id: str,
    model_version: str,
    model_manifest_hash: str,
    precision_plan_hash: str,
    share_epoch: int,
    expected_storage_key_id: str,
) -> str:
    """Return the hex startup fingerprint for one measured Worker entry."""
    material = b"|".join(
        (
            role.encode("ascii"),
            release_id.encode("utf-8"),
            model_version.encode("utf-8"),
            model_manifest_hash.encode("ascii"),
            precision_plan_hash.encode("ascii"),
            str(share_epoch).encode("ascii"),
            expected_storage_key_id.encode("ascii"),
        )
    )
    return hashlib.sha256(STARTUP_DOMAIN + material).hexdigest()


def protected_files_key(storage_key: bytes) -> bytes:
    """Derive the 16-byte Gramine encrypted-FS key from a released key."""
    if len(storage_key) != STORAGE_KEY_BYTES:
        raise EnclaveKeyError("storage key must contain 32 bytes")
    return hkdf(
        salt=PF_KEY_SALT,
        input_key_material=storage_key,
        info=PF_KEY_INFO,
        length=PF_KEY_BYTES,
    )


def encode_bundle(
    *,
    key_id: str,
    startup_hash: str,
    share_epoch: int,
    expires_at_unix: int,
    storage_key: bytes,
) -> bytes:
    """Encode the fixed-layout plaintext that the KAS seals to the enclave."""
    if len(storage_key) != STORAGE_KEY_BYTES:
        raise EnclaveKeyError("storage key must contain 32 bytes")
    if not 0 <= share_epoch < 2**64:
        raise EnclaveKeyError("share_epoch is out of range")
    if not 0 <= expires_at_unix < 2**64:
        raise EnclaveKeyError("expires_at is out of range")
    try:
        key_id_raw = bytes.fromhex(key_id)
        startup_raw = bytes.fromhex(startup_hash)
    except ValueError as exc:
        raise EnclaveKeyError("bundle digests must be hexadecimal") from exc
    if len(key_id_raw) != 32 or len(startup_raw) != 32:
        raise EnclaveKeyError("bundle digests must be 32 bytes")
    if not hmac.compare_digest(
        bytes.fromhex(storage_key_id(storage_key)),
        key_id_raw,
    ):
        raise EnclaveKeyError("key_id does not match the storage key")
    bundle = bytearray(BUNDLE_BYTES)
    bundle[0 : len(BUNDLE_MAGIC)] = BUNDLE_MAGIC
    bundle[len(BUNDLE_MAGIC)] = BUNDLE_VERSION
    bundle[_BUNDLE_KEY_ID_OFFSET : _BUNDLE_KEY_ID_OFFSET + 32] = key_id_raw
    bundle[_BUNDLE_STARTUP_OFFSET : _BUNDLE_STARTUP_OFFSET + 32] = startup_raw
    bundle[_BUNDLE_EPOCH_OFFSET : _BUNDLE_EPOCH_OFFSET + 8] = share_epoch.to_bytes(
        8, "big"
    )
    bundle[_BUNDLE_EXPIRY_OFFSET : _BUNDLE_EXPIRY_OFFSET + 8] = (
        expires_at_unix.to_bytes(8, "big")
    )
    bundle[_BUNDLE_KEY_OFFSET : _BUNDLE_KEY_OFFSET + 32] = storage_key
    return bytes(bundle)


def decode_bundle(bundle: bytes) -> dict[str, object]:
    """Decode and self-check a sealed bundle plaintext."""
    if not isinstance(bundle, bytes) or len(bundle) != BUNDLE_BYTES:
        raise EnclaveKeyError("sealed bundle must be exactly 128 bytes")
    if bundle[: len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise EnclaveKeyError("sealed bundle magic is invalid")
    if bundle[len(BUNDLE_MAGIC)] != BUNDLE_VERSION:
        raise EnclaveKeyError("sealed bundle version is unsupported")
    if any(bundle[len(BUNDLE_MAGIC) + 1 : _BUNDLE_KEY_ID_OFFSET]):
        raise EnclaveKeyError("sealed bundle reserved bytes are not zero")
    key_id_raw = bundle[_BUNDLE_KEY_ID_OFFSET : _BUNDLE_KEY_ID_OFFSET + 32]
    startup_raw = bundle[_BUNDLE_STARTUP_OFFSET : _BUNDLE_STARTUP_OFFSET + 32]
    storage_key = bundle[_BUNDLE_KEY_OFFSET : _BUNDLE_KEY_OFFSET + 32]
    derived_key_id = bytes.fromhex(storage_key_id(storage_key))
    if not hmac.compare_digest(derived_key_id, key_id_raw):
        raise EnclaveKeyError("sealed bundle key identifier does not match the key")
    return {
        "key_id": key_id_raw.hex(),
        "startup_hash": startup_raw.hex(),
        "share_epoch": int.from_bytes(
            bundle[_BUNDLE_EPOCH_OFFSET : _BUNDLE_EPOCH_OFFSET + 8], "big"
        ),
        "expires_at_unix": int.from_bytes(
            bundle[_BUNDLE_EXPIRY_OFFSET : _BUNDLE_EXPIRY_OFFSET + 8], "big"
        ),
        "storage_key": storage_key,
    }


def seal_bundle(enclave_public_key: str, bundle: bytes) -> bytes:
    """Seal an encoded bundle to the attested enclave public key."""
    if len(bundle) != BUNDLE_BYTES:
        raise EnclaveKeyError("sealed bundle must be exactly 128 bytes")
    return sm2_encrypt(enclave_public_key, bundle)


def open_bundle(enclave_private_key: str, sealed: bytes) -> dict[str, object]:
    """Open a sealed bundle inside the enclave and self-check its contents."""
    try:
        bundle = sm2_decrypt(enclave_private_key, sealed)
    except SM2Error as exc:
        raise EnclaveKeyError(f"sealed bundle could not be opened: {exc}") from exc
    return decode_bundle(bundle)


__all__ = [
    "BUNDLE_BYTES",
    "BUNDLE_MAGIC",
    "BUNDLE_VERSION",
    "EnclaveKeyError",
    "PF_KEY_BYTES",
    "STARTUP_DOMAIN",
    "STORAGE_KEY_BYTES",
    "decode_bundle",
    "enclave_report_data",
    "encode_bundle",
    "open_bundle",
    "protected_files_key",
    "seal_bundle",
    "storage_key_id",
    "verify_enclave_report_data",
    "worker_startup_digest",
]

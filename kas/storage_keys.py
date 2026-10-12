"""Purpose-bound disk-key derivation shared by the KAS and the packager.

The same derivation must run in two places inside the KAS trust domain: the
online release endpoint and the offline packager that builds the Gramine
encrypted-FS store. Keeping it here guarantees the store and the enclave agree
byte for byte.
"""

from __future__ import annotations

from crypto.enclave_key import storage_key_id
from crypto.sm3 import hkdf, sm3


STORAGE_KEY_CONTEXT_DOMAIN = b"A1-22:storage-key:v1\0"
STORAGE_KEY_SALT = b"A1-22:storage-key-salt:v1\0"
STORAGE_KEY_BYTES = 32


def derive_storage_key(
    *,
    storage_key_master: bytes,
    role: str,
    release_id: str,
    share_epoch: int,
    purpose: str,
) -> tuple[bytes, str]:
    """Return ``(key, key_id)`` for one node, epoch, and storage purpose."""
    if len(storage_key_master) < 32:
        raise ValueError("storage key master must contain at least 32 bytes")
    context = b"".join(
        (
            STORAGE_KEY_CONTEXT_DOMAIN,
            role.encode("ascii"),
            b"\0",
            release_id.encode("utf-8"),
            b"\0",
            share_epoch.to_bytes(8, "big"),
            b"\0",
            purpose.encode("ascii"),
        )
    )
    key = hkdf(
        salt=sm3(STORAGE_KEY_SALT),
        input_key_material=storage_key_master,
        info=context,
        length=STORAGE_KEY_BYTES,
    )
    return key, storage_key_id(key)


__all__ = [
    "STORAGE_KEY_BYTES",
    "STORAGE_KEY_CONTEXT_DOMAIN",
    "STORAGE_KEY_SALT",
    "derive_storage_key",
]

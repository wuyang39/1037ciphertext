"""SM3 hash and HKDF helpers used by the D2 session protocol."""

from __future__ import annotations

import hashlib


SM3_BYTES = 32
_SM3 = "sm3"


def _require_bytes(value: bytes, *, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def sm3(data: bytes) -> bytes:
    """Return the SM3 digest of ``data``."""
    _require_bytes(data, name="data")
    try:
        return hashlib.new(_SM3, data).digest()
    except ValueError:
        from gmssl import func, sm3 as gmssl_sm3

        return bytes.fromhex(gmssl_sm3.sm3_hash(func.bytes_to_list(data)))


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    """Return HMAC-SM3 for ``data`` under ``key``."""
    _require_bytes(key, name="key")
    _require_bytes(data, name="data")
    block_size = 64
    if len(key) > block_size:
        key = sm3(key)
    key = key.ljust(block_size, b"\x00")
    inner = bytes(value ^ 0x36 for value in key)
    outer = bytes(value ^ 0x5C for value in key)
    return sm3(outer + sm3(inner + data))


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """RFC 5869 extract step instantiated with HMAC-SM3."""
    _require_bytes(salt, name="salt")
    _require_bytes(input_key_material, name="input_key_material")
    return hmac_sm3(salt, input_key_material)


def hkdf_expand(
    pseudorandom_key: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """RFC 5869 expand step instantiated with HMAC-SM3."""
    _require_bytes(pseudorandom_key, name="pseudorandom_key")
    _require_bytes(info, name="info")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    if length > 255 * SM3_BYTES:
        raise ValueError("HKDF-SM3 output length exceeds 255 blocks")

    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac_sm3(
            pseudorandom_key,
            previous + info + bytes([counter]),
        )
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def hkdf(
    *,
    salt: bytes,
    input_key_material: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """One-shot RFC 5869 HKDF using SM3."""
    pseudorandom_key = hkdf_extract(salt, input_key_material)
    return hkdf_expand(pseudorandom_key, info, length)

"""SM2 signatures and ECDH over the SM2 P-256 curve.

The coordinate arithmetic is kept local because the Python GmSSL verifier can
raise on a valid signature whose verification point addition reaches infinity.
This implementation keeps that case explicit and returns ``False`` instead.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Optional

from gmssl import sm2

from .sm3 import sm3


SM2_ORDER = int(sm2.default_ecc_table["n"], 16)
SM2_FIELD = int(sm2.default_ecc_table["p"], 16)
SM2_CURVE_A = int(sm2.default_ecc_table["a"], 16)
SM2_CURVE_B = int(sm2.default_ecc_table["b"], 16)
_G_RAW = bytes.fromhex(sm2.default_ecc_table["g"])
SM2_GENERATOR = (
    int.from_bytes(_G_RAW[:32], "big"),
    int.from_bytes(_G_RAW[32:], "big"),
)
SM2_DEFAULT_ID = b"1234567812345678"
SM2_BYTES = 32
SM2_C1_BYTES = SM2_BYTES * 2
SM2_C3_BYTES = SM2_BYTES
SM2_CIPHERTEXT_OVERHEAD = SM2_C1_BYTES + SM2_C3_BYTES
_POINT_INFINITY = None
_MAX_ENCRYPTION_ATTEMPTS = 128


class SM2Error(ValueError):
    """Raised for malformed SM2 keys or signatures."""


def _normalize_hex(value: str, *, name: str, byte_length: int) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SM2Error(f"{name} is not valid hexadecimal") from exc
    if len(raw) != byte_length:
        raise SM2Error(f"{name} must be {byte_length} bytes")
    return raw.hex()


def _parse_public_point(public_key: str) -> tuple[int, int]:
    if not isinstance(public_key, str) or len(public_key) != SM2_BYTES * 4:
        raise SM2Error("public_key must encode the 64-byte uncompressed point")
    try:
        raw = bytes.fromhex(public_key)
    except ValueError as exc:
        raise SM2Error("public_key is not valid hexadecimal") from exc
    x = int.from_bytes(raw[:SM2_BYTES], "big")
    y = int.from_bytes(raw[SM2_BYTES:], "big")
    if x >= SM2_FIELD or y >= SM2_FIELD:
        raise SM2Error("public_key coordinates are outside the SM2 field")
    if x == 0 and y == 0:
        raise SM2Error("public_key is the point at infinity")
    if (
        y * y - (x * x * x + SM2_CURVE_A * x + SM2_CURVE_B)
    ) % SM2_FIELD != 0:
        raise SM2Error("public_key is not on the SM2 curve")
    return x, y


def _validate_public_point(public_key: str) -> str:
    point = _parse_public_point(public_key)
    raw = bytes.fromhex(public_key)
    return raw.hex()


def validate_sm2_public_key(public_key: str) -> str:
    """Validate and return a lowercase 64-byte SM2 public point."""
    return _validate_public_point(public_key)


def _encode_point(point: tuple[int, int] | None) -> str:
    if point is None:
        raise SM2Error("SM2 point is at infinity")
    x, y = point
    return (
        x.to_bytes(SM2_BYTES, "big") + y.to_bytes(SM2_BYTES, "big")
    ).hex()


def _jacobian_double(
    point: tuple[int, int, int] | None,
) -> tuple[int, int, int] | None:
    if point is None:
        return None
    x, y, z = point
    if z == 0 or y == 0:
        return None
    yy = y * y % SM2_FIELD
    s = 4 * x * yy % SM2_FIELD
    zz = z * z % SM2_FIELD
    m = (3 * x * x + SM2_CURVE_A * zz * zz) % SM2_FIELD
    x3 = (m * m - 2 * s) % SM2_FIELD
    y3 = (m * (s - x3) - 8 * yy * yy) % SM2_FIELD
    z3 = 2 * y * z % SM2_FIELD
    return x3, y3, z3


def _jacobian_add(
    left: tuple[int, int, int] | None,
    right: tuple[int, int, int] | None,
) -> tuple[int, int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1z1 = z1 * z1 % SM2_FIELD
    z2z2 = z2 * z2 % SM2_FIELD
    u1 = x1 * z2z2 % SM2_FIELD
    u2 = x2 * z1z1 % SM2_FIELD
    s1 = y1 * z2 * z2z2 % SM2_FIELD
    s2 = y2 * z1 * z1z1 % SM2_FIELD
    h = (u2 - u1) % SM2_FIELD
    r = (s2 - s1) % SM2_FIELD
    if h == 0:
        if r == 0:
            return _jacobian_double(left)
        return None
    hh = h * h % SM2_FIELD
    hhh = h * hh % SM2_FIELD
    v = u1 * hh % SM2_FIELD
    x3 = (r * r - hhh - 2 * v) % SM2_FIELD
    y3 = (r * (v - x3) - s1 * hhh) % SM2_FIELD
    z3 = z1 * z2 * h % SM2_FIELD
    return x3, y3, z3


def _scalar_multiply(
    scalar: int,
    point: tuple[int, int],
) -> tuple[int, int] | None:
    if not 0 < scalar < SM2_ORDER:
        raise SM2Error("scalar is outside the SM2 group order")
    result = None
    addend = (point[0], point[1], 1)
    while scalar:
        if scalar & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        scalar >>= 1
    if result is None:
        return None
    x, y, z = result
    if z == 0:
        return None
    inverse = pow(z, SM2_FIELD - 2, SM2_FIELD)
    inverse_squared = inverse * inverse % SM2_FIELD
    return (
        x * inverse_squared % SM2_FIELD,
        y * inverse_squared * inverse % SM2_FIELD,
    )


def _message_digest(public_key: str, data: bytes) -> int:
    x, y = _parse_public_point(public_key)
    public_raw = x.to_bytes(SM2_BYTES, "big") + y.to_bytes(SM2_BYTES, "big")
    za_input = (
        (len(SM2_DEFAULT_ID) * 8).to_bytes(2, "big")
        + SM2_DEFAULT_ID
        + SM2_CURVE_A.to_bytes(SM2_BYTES, "big")
        + SM2_CURVE_B.to_bytes(SM2_BYTES, "big")
        + SM2_GENERATOR[0].to_bytes(SM2_BYTES, "big")
        + SM2_GENERATOR[1].to_bytes(SM2_BYTES, "big")
        + public_raw
    )
    return int.from_bytes(sm3(sm3(za_input) + data), "big")


def _sign_with_scalar(
    private_key: str,
    public_key: str,
    data: bytes,
    scalar: int,
) -> bytes:
    if not 1 <= scalar < SM2_ORDER:
        raise SM2Error("SM2 signing scalar is outside the group order")
    point = _scalar_multiply(scalar, SM2_GENERATOR)
    if point is None:
        raise SM2Error("SM2 signing scalar produced the point at infinity")
    e = _message_digest(public_key, data)
    private_scalar = int(private_key, 16)
    r = (e + point[0]) % SM2_ORDER
    if r == 0 or r + scalar == SM2_ORDER:
        raise SM2Error("SM2 signing scalar produced an invalid r")
    inverse = pow(private_scalar + 1, SM2_ORDER - 2, SM2_ORDER)
    s = inverse * (scalar - r * private_scalar) % SM2_ORDER
    if s == 0:
        raise SM2Error("SM2 signing scalar produced an invalid s")
    return r.to_bytes(SM2_BYTES, "big") + s.to_bytes(SM2_BYTES, "big")


@dataclass(frozen=True)
class SM2KeyPair:
    """SM2 private/public key pair in 32-byte and 64-byte hex encodings."""

    private_key: str
    public_key: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "private_key",
            _normalize_hex(
                self.private_key,
                name="private_key",
                byte_length=SM2_BYTES,
            ),
        )
        object.__setattr__(
            self,
            "public_key",
            _validate_public_point(self.public_key),
        )

    @classmethod
    def generate(cls) -> "SM2KeyPair":
        private_scalar = secrets.randbelow(SM2_ORDER - 1) + 1
        return cls.from_private_key(private_scalar.to_bytes(SM2_BYTES, "big").hex())

    @classmethod
    def from_private_key(cls, private_key: str) -> "SM2KeyPair":
        private_key = _normalize_hex(
            private_key,
            name="private_key",
            byte_length=SM2_BYTES,
        )
        scalar = int(private_key, 16)
        if not 1 <= scalar < SM2_ORDER:
            raise SM2Error("private_key is outside the SM2 scalar field")
        public_key = _encode_point(_scalar_multiply(scalar, SM2_GENERATOR))
        return cls(private_key=private_key, public_key=public_key)

    def sign(self, data: bytes, *, random_hex: Optional[str] = None) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("SM2 signed data must be bytes")
        if random_hex is not None:
            scalar_hex = _normalize_hex(
                random_hex,
                name="random_hex",
                byte_length=SM2_BYTES,
            )
            return _sign_with_scalar(
                self.private_key,
                self.public_key,
                data,
                int(scalar_hex, 16),
            )
        for _ in range(128):
            scalar = secrets.randbelow(SM2_ORDER - 1) + 1
            try:
                return _sign_with_scalar(
                    self.private_key,
                    self.public_key,
                    data,
                    scalar,
                )
            except SM2Error:
                continue
        raise SM2Error("SM2 signer could not find a valid nonce")

    def verify(self, signature: bytes, data: bytes) -> bool:
        return verify_sm2(signature, data, self.public_key)

    def exchange(self, peer_public_key: str) -> bytes:
        """Return the 64-byte SM2 ECDH point shared with ``peer_public_key``."""
        peer_point = _parse_public_point(peer_public_key)
        shared = _scalar_multiply(int(self.private_key, 16), peer_point)
        return bytes.fromhex(_encode_point(shared))


def verify_sm2(signature: bytes, data: bytes, public_key: str) -> bool:
    """Verify a compact 64-byte ``r || s`` SM3-with-ZA signature."""
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    if not isinstance(data, bytes):
        return False
    try:
        public_point = _parse_public_point(public_key)
    except SM2Error:
        return False
    r = int.from_bytes(signature[:SM2_BYTES], "big")
    s = int.from_bytes(signature[SM2_BYTES:], "big")
    if not (1 <= r < SM2_ORDER and 1 <= s < SM2_ORDER):
        return False
    t = (r + s) % SM2_ORDER
    if t == 0:
        return False
    left = _scalar_multiply(s, SM2_GENERATOR)
    right = _scalar_multiply(t, public_point)
    point = _jacobian_add(
        None if left is None else (left[0], left[1], 1),
        None if right is None else (right[0], right[1], 1),
    )
    if point is None:
        return False
    x, y, z = point
    if z == 0:
        return False
    inverse = pow(z, SM2_FIELD - 2, SM2_FIELD)
    inverse_squared = inverse * inverse % SM2_FIELD
    affine_x = x * inverse_squared % SM2_FIELD
    e = _message_digest(public_key, data)
    return r == (e + affine_x) % SM2_ORDER


def _kdf(x2: bytes, y2: bytes, length: int) -> bytes:
    """SM3-based key derivation function from GM/T 0003.4-2012."""
    if length <= 0:
        raise SM2Error("KDF output length must be positive")
    material = x2 + y2
    output = bytearray()
    counter = 1
    while len(output) < length:
        output.extend(sm3(material + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:length])


def sm2_encrypt(
    public_key: str,
    data: bytes,
    *,
    scalar_hex: Optional[str] = None,
) -> bytes:
    """Encrypt ``data`` to an SM2 public key and return ``C1 || C3 || C2``.

    ``scalar_hex`` exists for deterministic tests; production callers leave it
    unset so the ephemeral scalar comes from ``secrets``.
    """
    if not isinstance(data, bytes) or not data:
        raise SM2Error("SM2 plaintext must be a non-empty byte sequence")
    public_point = _parse_public_point(public_key)
    if scalar_hex is not None:
        fixed_scalar = int(
            _normalize_hex(
                scalar_hex,
                name="scalar_hex",
                byte_length=SM2_BYTES,
            ),
            16,
        )
        if not 1 <= fixed_scalar < SM2_ORDER:
            raise SM2Error("scalar_hex is outside the SM2 scalar field")
        attempts = 1
    else:
        fixed_scalar = 0
        attempts = _MAX_ENCRYPTION_ATTEMPTS

    for _ in range(attempts):
        scalar = fixed_scalar or (secrets.randbelow(SM2_ORDER - 1) + 1)
        c1_point = _scalar_multiply(scalar, SM2_GENERATOR)
        shared = _scalar_multiply(scalar, public_point)
        if c1_point is None or shared is None:
            if fixed_scalar:
                raise SM2Error("SM2 encryption reached the point at infinity")
            continue
        x2 = shared[0].to_bytes(SM2_BYTES, "big")
        y2 = shared[1].to_bytes(SM2_BYTES, "big")
        mask = _kdf(x2, y2, len(data))
        if not any(mask):
            if fixed_scalar:
                raise SM2Error("SM2 KDF produced an all-zero mask")
            continue
        c2 = bytes(left ^ right for left, right in zip(data, mask, strict=True))
        c3 = sm3(x2 + data + y2)
        c1 = (
            c1_point[0].to_bytes(SM2_BYTES, "big")
            + c1_point[1].to_bytes(SM2_BYTES, "big")
        )
        return c1 + c3 + c2
    raise SM2Error("SM2 encryption could not find a usable ephemeral scalar")


def sm2_decrypt(private_key: str, ciphertext: bytes) -> bytes:
    """Decrypt an SM2 ``C1 || C3 || C2`` ciphertext and verify its C3 tag."""
    if not isinstance(ciphertext, bytes) or len(ciphertext) <= SM2_CIPHERTEXT_OVERHEAD:
        raise SM2Error("SM2 ciphertext is malformed")
    normalized = _normalize_hex(
        private_key,
        name="private_key",
        byte_length=SM2_BYTES,
    )
    c1 = ciphertext[:SM2_C1_BYTES]
    c3 = ciphertext[SM2_C1_BYTES:SM2_CIPHERTEXT_OVERHEAD]
    c2 = ciphertext[SM2_CIPHERTEXT_OVERHEAD:]
    point = _parse_public_point(c1.hex())
    scalar = int(normalized, 16)
    if not 1 <= scalar < SM2_ORDER:
        raise SM2Error("private_key is outside the SM2 scalar field")
    shared = _scalar_multiply(scalar, point)
    if shared is None:
        raise SM2Error("SM2 shared point is at infinity")
    x2 = shared[0].to_bytes(SM2_BYTES, "big")
    y2 = shared[1].to_bytes(SM2_BYTES, "big")
    mask = _kdf(x2, y2, len(c2))
    plaintext = bytes(left ^ right for left, right in zip(c2, mask, strict=True))
    if not hmac.compare_digest(sm3(x2 + plaintext + y2), c3):
        raise SM2Error("SM2 ciphertext integrity check failed")
    return plaintext


__all__ = [
    "SM2Error",
    "SM2KeyPair",
    "sm2_decrypt",
    "sm2_encrypt",
    "validate_sm2_public_key",
    "verify_sm2",
]

"""Small SM2 wrapper with canonical compact signatures."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional

from gmssl import sm2


SM2_ORDER = int(sm2.default_ecc_table["n"], 16)
SM2_BYTES = 32


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
        if len(self.public_key) != SM2_BYTES * 4:
            raise SM2Error("public_key must encode the 64-byte uncompressed point")
        try:
            public_raw = bytes.fromhex(self.public_key)
        except ValueError as exc:
            raise SM2Error("public_key is not valid hexadecimal") from exc
        object.__setattr__(self, "public_key", public_raw.hex())

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
        crypt = sm2.CryptSM2(private_key=private_key, public_key="", asn1=False)
        public_key = crypt._kg(scalar, crypt.ecc_table["g"])
        return cls(private_key=private_key, public_key=public_key)

    def sign(self, data: bytes, *, random_hex: Optional[str] = None) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("SM2 signed data must be bytes")
        crypt = sm2.CryptSM2(
            private_key=self.private_key,
            public_key=self.public_key,
            asn1=False,
        )
        signature_hex = crypt.sign_with_sm3(data, random_hex_str=random_hex)
        signature = bytes.fromhex(signature_hex)
        if len(signature) != 64:
            raise SM2Error("SM2 signer returned a non-compact signature")
        return signature

    def verify(self, signature: bytes, data: bytes) -> bool:
        return verify_sm2(signature, data, self.public_key)


def verify_sm2(signature: bytes, data: bytes, public_key: str) -> bool:
    """Verify a compact 64-byte ``r || s`` SM3-with-ZA signature."""
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    if not isinstance(data, bytes):
        return False
    public_key = _normalize_hex(
        public_key,
        name="public_key",
        byte_length=SM2_BYTES * 2,
    )
    if len(public_key) != SM2_BYTES * 4:
        raise SM2Error("public_key must encode the 64-byte uncompressed point")
    crypt = sm2.CryptSM2(private_key="", public_key=public_key, asn1=False)
    return bool(crypt.verify_with_sm3(signature.hex(), data))

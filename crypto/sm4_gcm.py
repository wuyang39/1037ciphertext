"""SM4-GCM with an OpenSSL-native default and an explicit Python test oracle."""

from __future__ import annotations

import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm4 import SM4_ENCRYPT, CryptSM4


SM4_KEY_BYTES = 16
SM4_BLOCK_BYTES = 16
SM4_GCM_TAG_BYTES = 16
SM4_GCM_NONCE_BYTES = 12
_GF_R = 0xE1000000000000000000000000000000


class SM4GCMError(ValueError):
    """Base class for SM4-GCM input and authentication failures."""


class AuthenticationError(SM4GCMError):
    """Raised when the GCM tag does not authenticate the frame."""


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _gf_multiply(left: int, right: int) -> int:
    """Multiply two GCM field elements in GF(2^128)."""
    result = 0
    value = right
    for bit in range(128):
        if left & (1 << (127 - bit)):
            result ^= value
        if value & 1:
            value = (value >> 1) ^ _GF_R
        else:
            value >>= 1
    return result


def _ghash(hash_subkey: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    if len(hash_subkey) != SM4_BLOCK_BYTES:
        raise SM4GCMError("GHASH subkey must be 16 bytes")

    state = 0
    for offset in range(0, len(aad), SM4_BLOCK_BYTES):
        block = aad[offset : offset + SM4_BLOCK_BYTES].ljust(
            SM4_BLOCK_BYTES, b"\x00"
        )
        state = _gf_multiply(
            state ^ int.from_bytes(block, "big"),
            int.from_bytes(hash_subkey, "big"),
        )
    for offset in range(0, len(ciphertext), SM4_BLOCK_BYTES):
        block = ciphertext[offset : offset + SM4_BLOCK_BYTES].ljust(
            SM4_BLOCK_BYTES, b"\x00"
        )
        state = _gf_multiply(
            state ^ int.from_bytes(block, "big"),
            int.from_bytes(hash_subkey, "big"),
        )

    length_block = (
        (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )
    state = _gf_multiply(
        state ^ int.from_bytes(length_block, "big"),
        int.from_bytes(hash_subkey, "big"),
    )
    return state.to_bytes(SM4_BLOCK_BYTES, "big")


def _increment32(counter: bytes) -> bytes:
    if len(counter) != SM4_BLOCK_BYTES:
        raise SM4GCMError("GCM counter block must be 16 bytes")
    low = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    return counter[:12] + low.to_bytes(4, "big")


class PurePythonSM4GCM:
    """Legacy pure-Python SM4-GCM oracle, never selected implicitly."""

    provider_name = "python-gmssl-oracle"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != SM4_KEY_BYTES:
            raise SM4GCMError("SM4-GCM key must be exactly 16 bytes")
        self._key = key
        self._cipher = CryptSM4(mode=SM4_ENCRYPT, padding_mode=None)
        self._cipher.set_key(key, SM4_ENCRYPT)

    def _encrypt_block(self, block: bytes) -> bytes:
        if len(block) != SM4_BLOCK_BYTES:
            raise SM4GCMError("SM4 input block must be 16 bytes")
        return self._cipher.crypt_ecb(block)

    def _initial_counter(self, nonce: bytes) -> bytes:
        if len(nonce) != SM4_GCM_NONCE_BYTES:
            raise SM4GCMError("SM4-GCM nonce must be exactly 12 bytes")
        return nonce + b"\x00\x00\x00\x01"

    def _crypt(self, initial_counter: bytes, data: bytes) -> bytes:
        output = bytearray()
        counter = initial_counter
        for offset in range(0, len(data), SM4_BLOCK_BYTES):
            stream = self._encrypt_block(counter)
            block = data[offset : offset + SM4_BLOCK_BYTES]
            output.extend(_xor(block, stream[: len(block)]))
            counter = _increment32(counter)
        return bytes(output)

    def _tag(
        self,
        *,
        initial_counter: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes:
        hash_subkey = self._encrypt_block(b"\x00" * SM4_BLOCK_BYTES)
        authentication = _ghash(hash_subkey, aad, ciphertext)
        mask = self._encrypt_block(initial_counter)
        return _xor(mask, authentication)

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        """Encrypt ``plaintext`` and return ``(ciphertext, tag)``."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")
        initial_counter = self._initial_counter(nonce)
        ciphertext = self._crypt(_increment32(initial_counter), plaintext)
        tag = self._tag(
            initial_counter=initial_counter,
            aad=aad,
            ciphertext=ciphertext,
        )
        return ciphertext, tag

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """Authenticate and decrypt a ciphertext."""
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
        if not isinstance(tag, bytes) or len(tag) != SM4_GCM_TAG_BYTES:
            raise SM4GCMError("SM4-GCM tag must be exactly 16 bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")

        initial_counter = self._initial_counter(nonce)
        expected_tag = self._tag(
            initial_counter=initial_counter,
            aad=aad,
            ciphertext=ciphertext,
        )
        if not hmac.compare_digest(expected_tag, tag):
            raise AuthenticationError("SM4-GCM authentication failed")
        return self._crypt(_increment32(initial_counter), ciphertext)


class SM4GCM:
    """OpenSSL-native SM4-GCM encryptor with a 16-byte authentication tag."""

    provider_name = "openssl-native-sm4-gcm"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != SM4_KEY_BYTES:
            raise SM4GCMError("SM4-GCM key must be exactly 16 bytes")
        try:
            self._algorithm = algorithms.SM4(key)
        except AttributeError as exc:
            raise SM4GCMError("native SM4 is unavailable in this OpenSSL build") from exc
        self._key = key

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if not isinstance(nonce, bytes) or len(nonce) != SM4_GCM_NONCE_BYTES:
            raise SM4GCMError("SM4-GCM nonce must be exactly 12 bytes")

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes]:
        """Encrypt with the native provider and return ``(ciphertext, tag)``."""
        self._validate_nonce(nonce)
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")
        encryptor = Cipher(
            self._algorithm,
            modes.GCM(nonce),
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """Authenticate and decrypt through the native OpenSSL provider."""
        self._validate_nonce(nonce)
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
        if not isinstance(tag, bytes) or len(tag) != SM4_GCM_TAG_BYTES:
            raise SM4GCMError("SM4-GCM tag must be exactly 16 bytes")
        if not isinstance(aad, bytes):
            raise TypeError("aad must be bytes")
        try:
            decryptor = Cipher(
                self._algorithm,
                modes.GCM(nonce, tag),
            ).decryptor()
            decryptor.authenticate_additional_data(aad)
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as exc:
            raise AuthenticationError("SM4-GCM authentication failed") from exc


__all__ = [
    "AuthenticationError",
    "PurePythonSM4GCM",
    "SM4GCM",
    "SM4GCMError",
    "SM4_BLOCK_BYTES",
    "SM4_GCM_NONCE_BYTES",
    "SM4_GCM_TAG_BYTES",
    "SM4_KEY_BYTES",
]

from __future__ import annotations

from crypto import SM2KeyPair, verify_sm2


def test_sm2_sign_and_verify_compact_signature() -> None:
    key_pair = SM2KeyPair.generate()
    signature = key_pair.sign(b"canonical manifest bytes", random_hex="01" * 32)
    assert len(signature) == 64
    assert key_pair.verify(signature, b"canonical manifest bytes")
    assert verify_sm2(signature, b"canonical manifest bytes", key_pair.public_key)
    assert not key_pair.verify(signature, b"tampered")
    assert not key_pair.verify(signature[:-1] + bytes([signature[-1] ^ 1]), b"canonical manifest bytes")


def test_sm2_private_key_is_deterministic() -> None:
    private_key = "01" * 32
    first = SM2KeyPair.from_private_key(private_key)
    second = SM2KeyPair.from_private_key(private_key)
    assert first == second

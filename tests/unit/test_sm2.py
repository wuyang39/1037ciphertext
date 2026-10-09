from __future__ import annotations

from gmssl import sm2

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


def test_sm2_sm3_signature_interoperates_with_gmssl() -> None:
    key_pair = SM2KeyPair.from_private_key("01" * 32)
    signature = key_pair.sign(b"interoperability", random_hex="02" * 32)
    assert signature.hex() == (
        "100fba97d8c45afb60f6688b4c9dacafaa88e57da253d26e8eae9f045c532bfa"
        "4d6d28b5bdb718a9d3c92a7eb663a1613bb92e3eded2fb3d54c3d9bbc8fc6c67"
    )
    gmssl_crypt = sm2.CryptSM2(
        private_key=key_pair.private_key,
        public_key=key_pair.public_key,
        asn1=False,
    )
    assert gmssl_crypt.verify_with_sm3(signature.hex(), b"interoperability")

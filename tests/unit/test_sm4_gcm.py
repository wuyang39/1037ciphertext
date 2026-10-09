from __future__ import annotations

import pytest

from crypto.sm4_gcm import AuthenticationError, SM4GCM, SM4GCMError


def test_sm4_gcm_rfc8998_vector() -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    nonce = bytes.fromhex("00001234567800000000abcd")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    plaintext = bytes.fromhex(
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
        "ccccccccccccccccdddddddddddddddd"
        "eeeeeeeeeeeeeeeeffffffffffffffff"
        "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
    )
    ciphertext, tag = SM4GCM(key).encrypt(nonce, plaintext, aad)
    assert ciphertext.hex() == (
        "17f399f08c67d5ee19d0dc9969c4bb7d"
        "5fd46fd3756489069157b282bb200735"
        "d82710ca5c22f0ccfa7cbf93d496ac15"
        "a56834cbcf98c397b4024a2691233b8d"
    )
    assert tag.hex() == "83de3541e4c2b58177e065a9bf7b62ec"
    assert SM4GCM(key).decrypt(nonce, ciphertext, tag, aad) == plaintext


def test_sm4_gcm_gbt36624_empty_vector() -> None:
    ciphertext, tag = SM4GCM(bytes(16)).encrypt(bytes(12), b"")
    assert ciphertext == b""
    assert tag.hex() == "232f0cfe308b49ea6fc88229b5dc858d"


def test_sm4_gcm_rejects_tag_aad_and_ciphertext_changes() -> None:
    cipher = SM4GCM(bytes(range(16)))
    nonce = bytes(range(12))
    ciphertext, tag = cipher.encrypt(nonce, b"sensitive", b"header")

    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce, ciphertext, tag[:-1] + bytes([tag[-1] ^ 1]), b"header")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce, ciphertext, tag, b"tampered")
    with pytest.raises(AuthenticationError):
        cipher.decrypt(nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), tag, b"header")


def test_sm4_gcm_rejects_invalid_nonce_length() -> None:
    with pytest.raises(SM4GCMError):
        SM4GCM(bytes(16)).encrypt(bytes(11), b"")

from __future__ import annotations

from crypto.sm3 import hkdf, hmac_sm3, sm3


def test_sm3_standard_vector() -> None:
    assert sm3(b"abc").hex() == (
        "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_hmac_sm3_is_stable() -> None:
    assert hmac_sm3(b"key", b"data").hex() == (
        "88a5a14b0fcf4a8a7b0c5084b8ee36e7"
        "0efca4e8467fa264c3231bf16463b425"
    )


def test_hkdf_sm3_known_vector() -> None:
    output = hkdf(
        salt=b"salt",
        input_key_material=b"ikm",
        info=b"info",
        length=42,
    )
    assert output.hex() == (
        "315a3171a989f11d4b10d39d48360982"
        "fc7f586ccbc688699af779c6e05a335"
        "58f3594a46e728a8bf6d4"
    )

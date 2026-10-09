from __future__ import annotations

import random
from fractions import Fraction

import pytest

from model.fixed_point import (
    FixedPointFormat,
    FixedPointOverflow,
    RoundingMode,
    add_fixed,
    decode_fixed,
    encode_fixed,
    multiply_fixed,
    secure_truncate,
    to_signed,
)


FORMAT = FixedPointFormat(fractional_bits=12, bits=32, signed=True)


def test_encode_decode_positive_and_negative_values() -> None:
    values = [Fraction(0), Fraction(1, 2), Fraction(-1, 2), Fraction(123, 8)]
    for value in values:
        encoded = encode_fixed(value, FORMAT)
        assert decode_fixed(encoded, FORMAT) == value
        assert 0 <= encoded < FORMAT.modulus


@pytest.mark.parametrize(
    ("value", "mode", "expected"),
    [
        ("1.25", RoundingMode.FLOOR, 1),
        ("-1.25", RoundingMode.FLOOR, -2),
        ("1.25", RoundingMode.CEIL, 2),
        ("-1.25", RoundingMode.CEIL, -1),
        ("-1.75", RoundingMode.TRUNC, -1),
        ("1.5", RoundingMode.NEAREST_HALF_AWAY, 2),
        ("-1.5", RoundingMode.NEAREST_HALF_AWAY, -2),
        ("2.5", RoundingMode.NEAREST_HALF_EVEN, 2),
    ],
)
def test_secure_truncate_round_modes(
    value: str, mode: RoundingMode, expected: int
) -> None:
    scaled = int(Fraction(value) * (1 << FORMAT.fractional_bits))
    assert to_signed(
        secure_truncate(
            scaled, FORMAT.fractional_bits, FORMAT, rounding=mode
        ),
        FORMAT,
    ) == expected


def test_checked_overflow_and_explicit_wrap() -> None:
    maximum = encode_fixed(FORMAT.maximum / FORMAT.scale, FORMAT)
    one = 1
    with pytest.raises(FixedPointOverflow):
        add_fixed(maximum, one, FORMAT)
    assert to_signed(add_fixed(maximum, one, FORMAT, wrap=True), FORMAT) == FORMAT.minimum


def test_canonical_fixed_point_vectors_are_deterministic() -> None:
    rng = random.Random(20261009)
    for _ in range(1000):
        left = Fraction(rng.randint(-128, 128), rng.randint(1, 16))
        right = Fraction(rng.randint(-128, 128), rng.randint(1, 16))
        left_encoded = encode_fixed(left, FORMAT)
        right_encoded = encode_fixed(right, FORMAT)
        left_decoded = decode_fixed(left_encoded, FORMAT)
        right_decoded = decode_fixed(right_encoded, FORMAT)
        assert decode_fixed(add_fixed(left_encoded, right_encoded, FORMAT), FORMAT) == (
            left_decoded + right_decoded
        )

        product = decode_fixed(
            multiply_fixed(
                left_encoded,
                right_encoded,
                FORMAT,
                rounding=RoundingMode.NEAREST_HALF_AWAY,
            ),
            FORMAT,
        )
        assert abs(product - left_decoded * right_decoded) <= Fraction(
            1, 2 * FORMAT.scale
        )

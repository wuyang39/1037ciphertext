"""Deterministic fixed-point arithmetic over unsigned ring storage.

Encoded values are stored as unsigned integers in ``Z_(2^bits)``. Signed
formats interpret the top bit as the sign bit. Products carry an explicit
shift so truncation and rounding remain visible to callers and tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from typing import Union


NumberLike = Union[int, float, str, Decimal, Fraction]


class RoundingMode(str, Enum):
    FLOOR = "floor"
    CEIL = "ceil"
    TRUNC = "trunc"
    NEAREST_HALF_AWAY = "nearest_half_away"
    NEAREST_HALF_EVEN = "nearest_half_even"


class FixedPointOverflow(ArithmeticError):
    """Raised when a checked fixed-point result is not representable."""

    def __init__(self, value: int, format: "FixedPointFormat") -> None:
        self.value = value
        self.format = format
        super().__init__(
            f"value {value} does not fit {format.bits}-bit "
            f"{'signed' if format.signed else 'unsigned'} format"
        )


@dataclass(frozen=True)
class FixedPointFormat:
    """Fixed-point format used by the plaintext reference arithmetic."""

    fractional_bits: int = 16
    bits: int = 64
    signed: bool = True

    def __post_init__(self) -> None:
        if self.bits <= 1:
            raise ValueError("bits must be greater than one")
        if self.fractional_bits < 0 or self.fractional_bits >= self.bits:
            raise ValueError("fractional_bits must be in [0, bits)")

    @property
    def modulus(self) -> int:
        return 1 << self.bits

    @property
    def mask(self) -> int:
        return self.modulus - 1

    @property
    def minimum(self) -> int:
        return -(1 << (self.bits - 1)) if self.signed else 0

    @property
    def maximum(self) -> int:
        return (1 << (self.bits - 1)) - 1 if self.signed else self.modulus - 1

    @property
    def scale(self) -> int:
        return 1 << self.fractional_bits


def _as_fraction(value: NumberLike) -> Fraction:
    if isinstance(value, bool):
        raise TypeError("bool is not a fixed-point numeric input")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, Decimal):
        return Fraction(value)
    if isinstance(value, float):
        return Fraction(str(value))
    if isinstance(value, str):
        return Fraction(value)
    raise TypeError(f"unsupported numeric type: {type(value).__name__}")


def _round_fraction(value: Fraction, mode: RoundingMode) -> int:
    numerator, denominator = value.numerator, value.denominator
    if mode is RoundingMode.FLOOR:
        return numerator // denominator
    if mode is RoundingMode.CEIL:
        return -((-numerator) // denominator)
    if mode is RoundingMode.TRUNC:
        quotient = abs(numerator) // denominator
        return quotient if numerator >= 0 else -quotient

    floor_value = numerator // denominator
    remainder = numerator - floor_value * denominator
    twice_remainder = remainder * 2
    if twice_remainder < denominator:
        return floor_value
    if twice_remainder > denominator:
        return floor_value + 1
    if mode is RoundingMode.NEAREST_HALF_AWAY:
        return floor_value + 1 if value > 0 else floor_value
    if mode is RoundingMode.NEAREST_HALF_EVEN:
        return floor_value if floor_value % 2 == 0 else floor_value + 1
    raise ValueError(f"unsupported rounding mode: {mode}")


def to_signed(raw_value: int, format: FixedPointFormat) -> int:
    """Interpret ring storage as a signed fixed-point integer."""
    if not format.signed:
        return raw_value & format.mask
    raw_value &= format.mask
    sign_bit = 1 << (format.bits - 1)
    return raw_value - format.modulus if raw_value & sign_bit else raw_value


def _encode_raw(raw_value: int, format: FixedPointFormat, wrap: bool) -> int:
    if not wrap and not format.minimum <= raw_value <= format.maximum:
        raise FixedPointOverflow(raw_value, format)
    return raw_value & format.mask


def encode_fixed(
    value: NumberLike,
    format: FixedPointFormat,
    *,
    rounding: RoundingMode = RoundingMode.NEAREST_HALF_AWAY,
    wrap: bool = False,
) -> int:
    """Encode a rational value into ring storage."""
    scaled = _as_fraction(value) * format.scale
    return _encode_raw(_round_fraction(scaled, rounding), format, wrap)


def decode_fixed(raw_value: int, format: FixedPointFormat) -> Fraction:
    """Decode ring storage into an exact rational value."""
    return Fraction(to_signed(raw_value, format), format.scale)


def add_fixed(
    left: int,
    right: int,
    format: FixedPointFormat,
    *,
    wrap: bool = False,
) -> int:
    """Add two encoded values with explicit overflow policy."""
    result = to_signed(left, format) + to_signed(right, format)
    return _encode_raw(result, format, wrap)


def subtract_fixed(
    left: int,
    right: int,
    format: FixedPointFormat,
    *,
    wrap: bool = False,
) -> int:
    """Subtract two encoded values with explicit overflow policy."""
    result = to_signed(left, format) - to_signed(right, format)
    return _encode_raw(result, format, wrap)


def secure_truncate(
    product: int,
    shift_bits: int,
    format: FixedPointFormat,
    *,
    rounding: RoundingMode = RoundingMode.NEAREST_HALF_AWAY,
    wrap: bool = False,
) -> int:
    """Round and truncate an encoded product by a fixed dyadic shift."""
    if shift_bits < 0:
        raise ValueError("shift_bits must be non-negative")
    truncated = _round_fraction(Fraction(product, 1 << shift_bits), rounding)
    return _encode_raw(truncated, format, wrap)


def multiply_fixed(
    left: int,
    right: int,
    format: FixedPointFormat,
    *,
    rounding: RoundingMode = RoundingMode.NEAREST_HALF_AWAY,
    wrap: bool = False,
) -> int:
    """Multiply encoded values, then use secure truncate semantics."""
    product = to_signed(left, format) * to_signed(right, format)
    return secure_truncate(
        product,
        format.fractional_bits,
        format,
        rounding=rounding,
        wrap=wrap,
    )

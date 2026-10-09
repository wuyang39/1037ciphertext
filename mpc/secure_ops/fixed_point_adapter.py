"""Fixed-point adapter shared by the plaintext and RSS references."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from model.fixed_point import (
    FixedPointFormat,
    RoundingMode,
    encode_fixed,
    to_signed,
)

from .rss import RSSContext, SharedTensor


class FixedPointAdapter:
    """Convert between rational fixed point and RSS ring shares."""

    def __init__(self, format: FixedPointFormat, context: RSSContext) -> None:
        if format.bits > context.ring_bits:
            raise ValueError("fixed-point format is wider than the RSS ring")
        self.format = format
        self.context = context

    def share(
        self,
        value: Any,
        *,
        rounding: RoundingMode = RoundingMode.NEAREST_HALF_AWAY,
    ) -> SharedTensor:
        if isinstance(value, list):
            return self.context.share(
                [
                    [self._encode_scalar(child, rounding) for child in row]
                    if isinstance(row, list)
                    else self._encode_scalar(row, rounding)
                    for row in value
                ]
            )
        return self.context.share(self._encode_scalar(value, rounding))

    def reconstruct(
        self,
        shared: SharedTensor,
        *,
        signed: bool = True,
    ) -> Any:
        raw = self.context.reconstruct(shared)

        def decode_scalar(value: int) -> Fraction:
            integer = (
                to_signed(value, self.format)
                if signed
                else value & self.format.mask
            )
            return Fraction(integer, self.format.scale)

        def walk(value: Any) -> Any:
            if isinstance(value, list):
                return [walk(child) for child in value]
            return decode_scalar(int(value))

        return walk(raw)

    def _encode_scalar(
        self,
        value: Any,
        rounding: RoundingMode,
    ) -> int:
        return encode_fixed(value, self.format, rounding=rounding)


__all__ = ["FixedPointAdapter"]

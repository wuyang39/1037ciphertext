"""Model references for A1-22.

The fixed-point arithmetic is plain Python and the enclave nodes reach it
through this package, so it is imported eagerly. ``TinyDecoder`` is a torch
module and the enclave deliberately carries no framework: a node that imports
``model`` for the arithmetic must not be forced to load one it never runs.
The decoder is therefore resolved on first use, which keeps
``from model import TinyDecoder`` working for the callers that do have torch.
"""

from .fixed_point import (
    FixedPointFormat,
    FixedPointOverflow,
    RoundingMode,
    add_fixed,
    decode_fixed,
    encode_fixed,
    multiply_fixed,
    secure_truncate,
)

__all__ = [
    "FixedPointFormat",
    "FixedPointOverflow",
    "RoundingMode",
    "TinyDecoder",
    "TinyDecoderConfig",
    "add_fixed",
    "decode_fixed",
    "encode_fixed",
    "multiply_fixed",
    "secure_truncate",
]


def __getattr__(name: str) -> object:
    if name in {"TinyDecoder", "TinyDecoderConfig"}:
        from . import tiny_decoder

        return getattr(tiny_decoder, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

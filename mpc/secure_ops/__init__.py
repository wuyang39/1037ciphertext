"""Secure-operator stubs backed by a deterministic 3-party RSS simulator."""

from .fixed_point_adapter import FixedPointAdapter
from .rss import (
    OperationTrace,
    RSSContext,
    RSSProtocolError,
    SharedTensor,
)

__all__ = [
    "FixedPointAdapter",
    "OperationTrace",
    "RSSContext",
    "RSSProtocolError",
    "SharedTensor",
]

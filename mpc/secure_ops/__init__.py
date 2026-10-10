"""Secure-operator stubs backed by a deterministic 3-party RSS simulator."""

from .fixed_point_adapter import FixedPointAdapter
from .provider import (
    FailClosedSecureNonlinearProvider,
    SecureNonlinearProvider,
    SecureOperatorUnavailable,
    SimulationRevealProvider,
)
from .rss import (
    OperationTrace,
    RSSContext,
    RSSProtocolError,
    SharedTensor,
)

__all__ = [
    "FixedPointAdapter",
    "FailClosedSecureNonlinearProvider",
    "OperationTrace",
    "RSSContext",
    "RSSProtocolError",
    "SecureNonlinearProvider",
    "SecureOperatorUnavailable",
    "SharedTensor",
    "SimulationRevealProvider",
]

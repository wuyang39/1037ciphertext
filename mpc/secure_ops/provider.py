"""Replaceable secure-nonlinear provider boundary.

Local development can explicitly choose the reveal-based simulator. Production
code must inject a provider backed by an audited secure protocol and keep the
simulator disabled.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol, Sequence

from .rss import RSSContext, RSSProtocolError, SharedTensor


class SecureOperatorUnavailable(RSSProtocolError):
    """No secure implementation is installed for the requested operator."""


class SecureNonlinearProvider(Protocol):
    """Narrow interface expected from YACL/SPU secure nonlinear operators."""

    def evaluate(
        self,
        *,
        name: str,
        input_shared: SharedTensor,
        context: RSSContext,
        decode: Callable[[SharedTensor], Any],
        encode: Callable[[Any], SharedTensor],
        transform: Callable[[Any], Any],
        parameters: dict[str, Any],
    ) -> SharedTensor:
        ...


@dataclass(frozen=True)
class FailClosedSecureNonlinearProvider:
    """Always reject calls until a real secure backend is configured."""

    provider_name: str = "unconfigured"

    def evaluate(
        self,
        *,
        name: str,
        input_shared: SharedTensor,
        context: RSSContext,
        decode: Callable[[SharedTensor], Any],
        encode: Callable[[Any], SharedTensor],
        transform: Callable[[Any], Any],
        parameters: dict[str, Any],
    ) -> SharedTensor:
        raise SecureOperatorUnavailable(
            f"secure nonlinear provider is not configured for {name}"
        )


@dataclass(frozen=True)
class SimulationRevealProvider:
    """Explicit local-only provider that reveals and resharing values."""

    allowed_operations: tuple[str, ...] = (
        "softmax",
        "layernorm",
        "gelu",
    )

    def evaluate(
        self,
        *,
        name: str,
        input_shared: SharedTensor,
        context: RSSContext,
        decode: Callable[[SharedTensor], Any],
        encode: Callable[[Any], SharedTensor],
        transform: Callable[[Any], Any],
        parameters: dict[str, Any],
    ) -> SharedTensor:
        if name not in self.allowed_operations:
            raise SecureOperatorUnavailable(
                f"simulation provider does not allow {name}"
            )
        if not context.reveal_allowed:
            raise SecureOperatorUnavailable(
                f"{name} requires a secure protocol; simulation reveal is disabled"
            )
        started = time.perf_counter()
        transformed = transform(decode(input_shared))
        result = encode(transformed)
        return context.record_external(
            operation=name,
            result=result,
            started=started,
            rounds=1,
            simulated_reveal=True,
            scale=int(parameters.get("scale", 1)),
            communication_bytes=int(parameters.get("communication_bytes", 0)) or None,
        )


__all__ = [
    "FailClosedSecureNonlinearProvider",
    "SecureNonlinearProvider",
    "SecureOperatorUnavailable",
    "SimulationRevealProvider",
]

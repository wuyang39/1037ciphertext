"""Deterministic network profiles for local performance comparisons."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkProfile:
    name: str
    bandwidth_mbps: float
    latency_ms: float

    def transfer_ms(self, byte_count: int) -> float:
        if byte_count < 0 or self.bandwidth_mbps <= 0 or self.latency_ms < 0:
            raise ValueError("network profile values are invalid")
        return self.latency_ms + (byte_count * 8) / (self.bandwidth_mbps * 1_000_000) * 1000.0


LAN = NetworkProfile("LAN", bandwidth_mbps=1000.0, latency_ms=1.0)
WAN_40MS = NetworkProfile("100Mbps-40ms", bandwidth_mbps=100.0, latency_ms=40.0)
WAN_80MS = NetworkProfile("100Mbps-80ms", bandwidth_mbps=100.0, latency_ms=80.0)


__all__ = ["LAN", "NetworkProfile", "WAN_40MS", "WAN_80MS"]

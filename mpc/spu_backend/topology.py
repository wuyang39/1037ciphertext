"""Three-party RSS topology and static release binding."""

from __future__ import annotations

from dataclasses import dataclass


class TopologyError(ValueError):
    """The configured SPU topology is not the supported 3PC layout."""


@dataclass(frozen=True)
class RSSTopology:
    """Static P0/P1/P2 topology consumed by the SPU compiler."""

    node_roles: tuple[str, str, str] = ("P0", "P1", "P2")
    threshold: int = 2
    security_model: str = "semi-honest"
    spu_build_hash: str = ""

    def __post_init__(self) -> None:
        if self.node_roles != ("P0", "P1", "P2"):
            raise TopologyError("D4 requires the ordered P0/P1/P2 topology")
        if self.threshold != 2:
            raise TopologyError("3PC RSS must use a two-of-three corruption threshold")
        if self.security_model != "semi-honest":
            raise TopologyError("the local D4 simulator is semi-honest only")
        if len(self.spu_build_hash) != 64:
            raise TopologyError("spu_build_hash must be a 32-byte hex digest")

    @property
    def party_count(self) -> int:
        return 3

    def to_dict(self) -> dict[str, object]:
        return {
            "node_roles": list(self.node_roles),
            "party_count": self.party_count,
            "threshold": self.threshold,
            "security_model": self.security_model,
            "spu_build_hash": self.spu_build_hash,
        }


__all__ = ["RSSTopology", "TopologyError"]

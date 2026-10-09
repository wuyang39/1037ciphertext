"""Redacted audit events permitted to leave the KAS/MPC trust boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from contracts import validate_contract


@dataclass(frozen=True)
class AuditEvent:
    """Audit records carry summaries only, never prompts, shares, or keys."""

    session_hash: str
    ticket_id: str
    release_id: str
    measurement: str
    result_code: str
    bytes: int
    elapsed_ms: float

    def __post_init__(self) -> None:
        validate_contract("audit_event", asdict(self))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuditEvent":
        validate_contract("audit_event", value)
        return cls(**value)

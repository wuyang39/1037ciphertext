"""Atomic one-use accounting for model and preprocessing material."""

from __future__ import annotations

import datetime as dt
import threading
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable


class MaterialLedgerError(ValueError):
    """A material registration, claim, or consumption was rejected."""


class MaterialStatus(str, Enum):
    AVAILABLE = "available"
    CLAIMED = "claimed"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True)
class MaterialRecord:
    material_id: str
    model_version: str
    share_epoch: int
    op_type: str
    count: int
    expiry: dt.datetime
    status: MaterialStatus = MaterialStatus.AVAILABLE

    def __post_init__(self) -> None:
        if not self.material_id or not self.model_version or not self.op_type:
            raise ValueError("material binding fields must not be empty")
        if self.share_epoch < 0 or self.count < 0:
            raise ValueError("share_epoch and count must be non-negative")
        if self.expiry.tzinfo is None:
            raise ValueError("expiry must be timezone-aware")


@dataclass(frozen=True)
class MaterialClaim:
    claim_id: str
    material_id: str
    model_version: str
    share_epoch: int
    op_type: str


class MaterialLedger:
    """Thread-safe ledger with explicit claim then consume transitions."""

    def __init__(self, *, clock: Callable[[], dt.datetime] | None = None) -> None:
        self._records: dict[str, MaterialRecord] = {}
        self._claims: dict[str, MaterialClaim] = {}
        self._audit: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def register(self, record: MaterialRecord) -> None:
        with self._lock:
            if record.material_id in self._records:
                raise MaterialLedgerError("material_id is already registered")
            self._records[record.material_id] = record
            self._audit.append(
                {
                    "event": "register",
                    "material_id": record.material_id,
                    "model_version": record.model_version,
                    "share_epoch": record.share_epoch,
                    "op_type": record.op_type,
                    "count": record.count,
                }
            )

    def claim(
        self,
        material_id: str,
        *,
        model_version: str,
        share_epoch: int,
        op_type: str,
    ) -> MaterialClaim:
        now = self._clock()
        with self._lock:
            record = self._records.get(material_id)
            if record is None:
                raise MaterialLedgerError("material is unknown")
            if now >= record.expiry:
                self._records[material_id] = replace(
                    record,
                    status=MaterialStatus.EXPIRED,
                )
                raise MaterialLedgerError("material has expired")
            if record.status != MaterialStatus.AVAILABLE:
                raise MaterialLedgerError(
                    f"material is not available: {record.status.value}"
                )
            if record.count <= 0:
                self._records[material_id] = replace(
                    record,
                    status=MaterialStatus.CONSUMED,
                )
                raise MaterialLedgerError("material count is exhausted")
            if (
                record.model_version != model_version
                or record.share_epoch != share_epoch
                or record.op_type != op_type
            ):
                raise MaterialLedgerError("material binding mismatch")
            claim = MaterialClaim(
                claim_id=str(uuid.uuid4()),
                material_id=material_id,
                model_version=model_version,
                share_epoch=share_epoch,
                op_type=op_type,
            )
            self._claims[claim.claim_id] = claim
            self._records[material_id] = replace(
                record,
                status=MaterialStatus.CLAIMED,
            )
            self._audit.append(
                {
                    "event": "claim",
                    "claim_id": claim.claim_id,
                    "material_id": material_id,
                    "op_type": op_type,
                }
            )
            return claim

    def consume(self, claim: MaterialClaim) -> MaterialRecord:
        now = self._clock()
        with self._lock:
            active = self._claims.pop(claim.claim_id, None)
            if active != claim:
                raise MaterialLedgerError("material claim is unknown or already used")
            record = self._records.get(claim.material_id)
            if record is None or record.status != MaterialStatus.CLAIMED:
                raise MaterialLedgerError("material claim state is inconsistent")
            if now >= record.expiry:
                expired = replace(record, status=MaterialStatus.EXPIRED)
                self._records[claim.material_id] = expired
                raise MaterialLedgerError("material expired before consumption")
            updated = replace(
                record,
                count=record.count - 1,
                status=(
                    MaterialStatus.AVAILABLE
                    if record.count - 1 > 0
                    else MaterialStatus.CONSUMED
                ),
            )
            self._records[claim.material_id] = updated
            self._audit.append(
                {
                    "event": "consume",
                    "claim_id": claim.claim_id,
                    "material_id": claim.material_id,
                    "remaining": updated.count,
                }
            )
            return updated

    def release(self, claim: MaterialClaim) -> None:
        """Return an unused claim after a failed operation."""
        with self._lock:
            active = self._claims.pop(claim.claim_id, None)
            if active != claim:
                raise MaterialLedgerError("material claim is unknown or already used")
            record = self._records.get(claim.material_id)
            if record is None or record.status != MaterialStatus.CLAIMED:
                raise MaterialLedgerError("material claim state is inconsistent")
            self._records[claim.material_id] = replace(
                record,
                status=MaterialStatus.AVAILABLE,
            )
            self._audit.append(
                {
                    "event": "release",
                    "claim_id": claim.claim_id,
                    "material_id": claim.material_id,
                }
            )

    def revoke(self, material_id: str) -> None:
        with self._lock:
            record = self._records.get(material_id)
            if record is None:
                raise MaterialLedgerError("material is unknown")
            self._records[material_id] = replace(
                record,
                status=MaterialStatus.REVOKED,
            )

    def record(self, material_id: str) -> MaterialRecord:
        with self._lock:
            record = self._records.get(material_id)
        if record is None:
            raise MaterialLedgerError("material is unknown")
        return record

    def audit_events(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(dict(event) for event in self._audit)


__all__ = [
    "MaterialClaim",
    "MaterialLedger",
    "MaterialLedgerError",
    "MaterialRecord",
    "MaterialStatus",
]

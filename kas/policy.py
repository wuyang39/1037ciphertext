"""Release measurement policy and quote result validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from contracts import validate_contract

from .errors import PolicyRejected


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise PolicyRejected("release expiry must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ReleaseManifest:
    release_id: str
    mrenclave: str
    mrsigner: str
    min_isvsvn: int
    debug_allowed: bool
    spu_build_hash: str
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    expires_at: datetime

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReleaseManifest":
        validate_contract("release_manifest", value)
        return cls(
            release_id=value["release_id"],
            mrenclave=value["mrenclave"],
            mrsigner=value["mrsigner"],
            min_isvsvn=value["min_isvsvn"],
            debug_allowed=value["debug_allowed"],
            spu_build_hash=value["spu_build_hash"],
            model_version=value["model_version"],
            model_manifest_hash=value["model_manifest_hash"],
            precision_plan_hash=value["precision_plan_hash"],
            expires_at=_parse_timestamp(value["expires_at"]),
        )


@dataclass(frozen=True)
class VerifiedQuote:
    mrenclave: str
    mrsigner: str
    isvsvn: int
    debug: bool
    report_data: bytes


class PolicyRegistry:
    """Registered releases that can issue node credentials."""

    def __init__(self, releases: list[ReleaseManifest]) -> None:
        self._releases: dict[str, ReleaseManifest] = {}
        for release in releases:
            if release.release_id in self._releases:
                raise ValueError(f"duplicate release_id: {release.release_id}")
            self._releases[release.release_id] = release

    @classmethod
    def from_json_file(cls, path: Path) -> "PolicyRegistry":
        with path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        if isinstance(document, dict):
            values = document.get("releases")
        else:
            values = document
        if not isinstance(values, list) or not values:
            raise ValueError("release policy file must contain a non-empty list")
        return cls([ReleaseManifest.from_dict(value) for value in values])

    def get(self, release_id: str, *, now: datetime) -> ReleaseManifest:
        release = self._releases.get(release_id)
        if release is None:
            raise PolicyRejected(f"release is not registered: {release_id}")
        if now.astimezone(timezone.utc) >= release.expires_at:
            raise PolicyRejected(f"release is expired: {release_id}")
        return release

    def validate_quote(
        self,
        release_id: str,
        quote: VerifiedQuote,
        *,
        now: datetime,
    ) -> ReleaseManifest:
        release = self.get(release_id, now=now)
        if quote.debug:
            raise PolicyRejected("debug Quote is forbidden")
        if quote.mrenclave.lower() != release.mrenclave:
            raise PolicyRejected("MRENCLAVE does not match the release")
        if quote.mrsigner.lower() != release.mrsigner:
            raise PolicyRejected("MRSIGNER does not match the release")
        if quote.isvsvn < release.min_isvsvn:
            raise PolicyRejected("ISVSVN is below the release minimum")
        return release

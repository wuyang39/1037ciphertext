"""Canonical JSON serialization used for hashes and signatures."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the one canonical UTF-8 representation of a JSON object."""
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical-JSON serializable") from exc
    return text.encode("utf-8")


def canonical_hash(value: Mapping[str, Any]) -> str:
    """Return a lower-case SHA-256 digest for a canonical JSON object."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

"""Model-share splitting and proof-bound import checks."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Iterable, Sequence

from crypto.sm3 import sm3


class ShareImportError(ValueError):
    """A model share is malformed, stale, or bound to another release."""


@dataclass(frozen=True)
class ModelShare:
    role: str
    model_hash: str
    share_epoch: int
    payload: bytes

    def __post_init__(self) -> None:
        if self.role not in {"P0", "P1", "P2"}:
            raise ShareImportError("model share role must be P0, P1, or P2")
        if len(self.model_hash) != 64 or self.share_epoch < 0:
            raise ShareImportError("model share metadata is invalid")

    def digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def split_model_payload(
    payload: bytes,
    *,
    model_hash: str,
    share_epoch: int,
    seed: int,
) -> tuple[ModelShare, ModelShare, ModelShare]:
    """Split an already-quantized model payload into three additive shares."""
    if not payload:
        raise ShareImportError("model payload must not be empty")
    rng = random.Random(seed)
    first = bytes(rng.randrange(256) for _ in payload)
    second = bytes(rng.randrange(256) for _ in payload)
    third = bytes(
        value ^ first[index] ^ second[index]
        for index, value in enumerate(payload)
    )
    return tuple(
        ModelShare(
            role=role,
            model_hash=model_hash,
            share_epoch=share_epoch,
            payload=share,
        )
        for role, share in zip(("P0", "P1", "P2"), (first, second, third))
    )


def reconstruct_model_payload(
    shares: Sequence[ModelShare],
) -> bytes:
    if len(shares) != 3 or {share.role for share in shares} != {"P0", "P1", "P2"}:
        raise ShareImportError("exactly three role-distinct shares are required")
    if len({share.model_hash for share in shares}) != 1:
        raise ShareImportError("model shares have different model hashes")
    if len({share.share_epoch for share in shares}) != 1:
        raise ShareImportError("model shares have different epochs")
    lengths = {len(share.payload) for share in shares}
    if len(lengths) != 1:
        raise ShareImportError("model shares have different lengths")
    return bytes(
        shares[0].payload[index]
        ^ shares[1].payload[index]
        ^ shares[2].payload[index]
        for index in range(len(shares[0].payload))
    )


def import_model_share(
    share: ModelShare,
    *,
    expected_model_hash: str,
    expected_share_epoch: int,
    expected_role: str,
    attestation_release_id: str,
    allowed_release_ids: Iterable[str],
) -> ModelShare:
    """Reject a share before it is written into protected storage."""
    if share.model_hash != expected_model_hash:
        raise ShareImportError("model share hash mismatch")
    if share.share_epoch != expected_share_epoch:
        raise ShareImportError("model share epoch mismatch")
    if share.role != expected_role:
        raise ShareImportError("model share role mismatch")
    if attestation_release_id not in set(allowed_release_ids):
        raise ShareImportError("attestation release is not allowed for this share")
    return share


__all__ = [
    "ModelShare",
    "ShareImportError",
    "import_model_share",
    "reconstruct_model_payload",
    "split_model_payload",
]

"""Hand a plaintext tensor to three parties as encoded additive shares.

The dealer (the workspace builder) uses this once per model tensor, and the
client uses it once per decoding step, so both take the same path into the SPU
and neither has to reimplement the share encoding.

Nothing here is secret-bearing by itself: a share is uniform on its own. The
point of routing the split through one helper is that the *encode* step, which
the share channel and the request payload both depend on, cannot drift between
the two callers.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Callable, Sequence

from mpc.spu_backend.spu_link import decode_share, encode_share


PARTIES = 3
# How much of a share's payload the acceptance records as a search probe. The
# probe only ever has to be long enough not to collide; it is a slice of a
# uniformly random share, so publishing it reveals nothing about the value the
# shares add up to.
PROBE_CHARACTERS = 32


class SharingError(ValueError):
    """A tensor could not be split, or a share set could not be joined."""


def split_secret(libspu: Any, io: Any, value: Any) -> Sequence[Any]:
    """Split one tensor into the three parties' SPU shares."""
    import numpy

    try:
        shares = io.MakeShares(
            numpy.asarray(value, dtype=numpy.float64), int(libspu.VIS_SECRET)
        )
    except Exception as exc:  # pragma: no cover - reported by the caller
        raise SharingError(f"the tensor could not be shared: {exc}") from exc
    if len(shares) != PARTIES:
        raise SharingError("SPU returned an unexpected number of shares")
    return shares


def share_probe(encoded: str) -> str:
    """A stable, non-secret search token for one encoded share."""
    try:
        document = json.loads(encoded)
        chunk = base64.b64decode(document["chunks"][0], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise SharingError("the encoded share is malformed") from exc
    text = base64.b64encode(chunk).decode("ascii")
    return text[:PROBE_CHARACTERS]


def make_splitter(libspu: Any, io: Any) -> Callable[[Any], list[str]]:
    """Return ``value -> three encoded shares`` for the client and the dealer."""

    def split(value: Any) -> list[str]:
        return [encode_share(share) for share in split_secret(libspu, io, value)]

    return split


def make_joiner(libspu: Any, io: Any) -> Callable[[Sequence[str]], Any]:
    """Return ``three encoded shares -> plaintext tensor``."""

    def join(encoded_shares: Sequence[str]) -> Any:
        if len(encoded_shares) != PARTIES:
            raise SharingError("three shares are required to reconstruct")
        shares = [decode_share(libspu, value) for value in encoded_shares]
        try:
            return io.Reconstruct(shares)
        except Exception as exc:  # pragma: no cover - reported by the caller
            raise SharingError(f"the shares could not be joined: {exc}") from exc

    return join


__all__ = [
    "PARTIES",
    "PROBE_CHARACTERS",
    "SharingError",
    "make_joiner",
    "make_splitter",
    "share_probe",
    "split_secret",
]

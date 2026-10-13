"""Session-scoped KV cache with explicit secure-wipe semantics.

Two kinds of entry live here. ``KVCacheEntry`` holds logical three-party
``SharedTensor`` pairs and is what the local RSS tests exercise.
``KVBuffer`` holds one party's serialized session state in a mutable buffer, so
an enclave node can keep its own share of each decoding step and then prove it
was overwritten: :meth:`SecureKVCache.wipe` zeroes every byte in place and
``assert_scrubbed`` re-checks that the buffers really are all zeros.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rss import RSSProtocolError, SharedTensor


@dataclass
class KVCacheEntry:
    key: SharedTensor
    value: SharedTensor


@dataclass
class KVBuffer:
    """One party's serialized step state, stored so it can be scrubbed."""

    label: str
    shape: tuple[int, ...]
    data: bytearray = field(repr=False)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def scrubbed(self) -> bool:
        return not any(self.data)


class SecureKVCache:
    """KV state that exists only for one enclave session."""

    def __init__(self, *, max_layers: int, max_tokens: int) -> None:
        if max_layers <= 0 or max_tokens <= 0:
            raise ValueError("KV cache limits must be positive")
        self.max_layers = max_layers
        self.max_tokens = max_tokens
        self._entries: dict[int, list[KVCacheEntry]] = {}
        self._buffers: dict[int, list[KVBuffer]] = {}
        self._closed = False
        self._wipe_count = 0
        self._wipe_record: dict[str, Any] | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def wipe_count(self) -> int:
        return self._wipe_count

    def append(
        self,
        *,
        layer: int,
        key: SharedTensor,
        value: SharedTensor,
    ) -> None:
        if self._closed:
            raise RSSProtocolError("KV cache is closed")
        if not 0 <= layer < self.max_layers:
            raise RSSProtocolError("KV layer is outside the session cache")
        if key.shape != value.shape:
            raise RSSProtocolError("KV key and value shapes differ")
        entries = self._entries.setdefault(layer, [])
        if len(entries) >= self.max_tokens:
            raise RSSProtocolError("KV token cache limit reached")
        entries.append(KVCacheEntry(key=key, value=value))

    def append_buffer(
        self,
        *,
        layer: int,
        label: str,
        shape: tuple[int, ...],
        data: bytes,
    ) -> KVBuffer:
        """Keep one party's serialized step state until the session ends."""
        if self._closed:
            raise RSSProtocolError("KV cache is closed")
        if not 0 <= layer < self.max_layers:
            raise RSSProtocolError("KV layer is outside the session cache")
        if not isinstance(data, bytes):
            raise TypeError("buffered session state must be bytes")
        buffers = self._buffers.setdefault(layer, [])
        if len(buffers) >= self.max_tokens:
            raise RSSProtocolError("KV token cache limit reached")
        buffer = KVBuffer(label=label, shape=tuple(shape), data=bytearray(data))
        buffers.append(buffer)
        return buffer

    def layer(self, layer: int) -> tuple[KVCacheEntry, ...]:
        if self._closed:
            raise RSSProtocolError("KV cache is closed")
        return tuple(self._entries.get(layer, ()))

    def buffers(self, layer: int) -> tuple[KVBuffer, ...]:
        if self._closed:
            raise RSSProtocolError("KV cache is closed")
        return tuple(self._buffers.get(layer, ()))

    def buffer_bytes(self) -> int:
        return sum(
            buffer.size for buffers in self._buffers.values() for buffer in buffers
        )

    def wipe(self) -> None:
        """Overwrite logical share storage and drop all session references."""
        for entries in self._entries.values():
            for entry in entries:
                _zero_shared_tensor(entry.key)
                _zero_shared_tensor(entry.value)
        for buffers in self._buffers.values():
            for buffer in buffers:
                for index in range(len(buffer.data)):
                    buffer.data[index] = 0
        survived = [
            buffer.label
            for buffers in self._buffers.values()
            for buffer in buffers
            if not buffer.scrubbed
        ]
        self._wipe_record = {
            "buffers": sum(len(buffers) for buffers in self._buffers.values()),
            "buffer_bytes": sum(
                buffer.size
                for buffers in self._buffers.values()
                for buffer in buffers
            ),
            "entries": sum(len(entries) for entries in self._entries.values()),
            "unscrubbed": survived,
            "all_zero": not survived,
        }
        self._entries.clear()
        self._buffers.clear()
        self._wipe_count += 1
        self._closed = True

    def assert_empty(self) -> None:
        if self._entries or self._buffers:
            raise RSSProtocolError("KV cache still contains session state")

    def assert_scrubbed(self) -> None:
        """Refuse to claim a wipe that left recoverable step state behind."""
        record = self._wipe_record
        if record is None:
            raise RSSProtocolError("the session state has not been wiped yet")
        if not record["all_zero"]:
            raise RSSProtocolError(
                "session state survived the wipe: "
                + ", ".join(sorted(record["unscrubbed"]))
            )

    @property
    def wipe_record(self) -> dict[str, Any]:
        return dict(self._wipe_record or {})


def _zero_shared_tensor(tensor: SharedTensor) -> None:
    """Best-effort in-place scrub of the mutable logical share representation."""
    zeroed = tuple(tuple(0 for _ in share) for share in tensor.shares)
    object.__setattr__(tensor, "shares", zeroed)


__all__ = ["KVBuffer", "KVCacheEntry", "SecureKVCache"]

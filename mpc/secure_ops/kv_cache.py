"""Session-scoped KV cache with explicit secure-wipe semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rss import RSSProtocolError, SharedTensor


@dataclass
class KVCacheEntry:
    key: SharedTensor
    value: SharedTensor


class SecureKVCache:
    """KV state that exists only for one enclave session."""

    def __init__(self, *, max_layers: int, max_tokens: int) -> None:
        if max_layers <= 0 or max_tokens <= 0:
            raise ValueError("KV cache limits must be positive")
        self.max_layers = max_layers
        self.max_tokens = max_tokens
        self._entries: dict[int, list[KVCacheEntry]] = {}
        self._closed = False
        self._wipe_count = 0

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

    def layer(self, layer: int) -> tuple[KVCacheEntry, ...]:
        if self._closed:
            raise RSSProtocolError("KV cache is closed")
        return tuple(self._entries.get(layer, ()))

    def wipe(self) -> None:
        """Overwrite logical share storage and drop all session references."""
        for entries in self._entries.values():
            for entry in entries:
                _zero_shared_tensor(entry.key)
                _zero_shared_tensor(entry.value)
        self._entries.clear()
        self._wipe_count += 1
        self._closed = True

    def assert_empty(self) -> None:
        if self._entries:
            raise RSSProtocolError("KV cache still contains session state")


def _zero_shared_tensor(tensor: SharedTensor) -> None:
    """Best-effort in-place scrub of the mutable logical share representation."""
    zeroed = tuple(tuple(0 for _ in share) for share in tensor.shares)
    object.__setattr__(tensor, "shares", zeroed)


__all__ = ["KVCacheEntry", "SecureKVCache"]

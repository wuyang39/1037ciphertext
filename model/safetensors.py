"""A dependency-free reader for the safetensors container.

The frozen GPT-2 weights arrive as one ``model.safetensors`` file. The enclave
runtime deliberately carries no deep-learning framework, so the importer reads
the container itself rather than going through one: an eight-byte little-endian
header length, a JSON header that describes every tensor, and one contiguous
data section that follows it. A tensor is returned as the exact bytes that were
frozen, reshaped by the header and nothing else.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np


# The header is JSON that describes the whole file; a bound keeps a corrupt
# length field from asking for an absurd read before the JSON is even parsed.
MAX_HEADER_BYTES = 64 << 20

_DTYPES: dict[str, np.dtype[Any]] = {
    "F64": np.dtype("<f8"),
    "F32": np.dtype("<f4"),
    "F16": np.dtype("<f2"),
    "I64": np.dtype("<i8"),
    "I32": np.dtype("<i4"),
    "I16": np.dtype("<i2"),
    "I8": np.dtype("i1"),
    "U8": np.dtype("u1"),
    "BOOL": np.dtype("?"),
}


class SafetensorsError(ValueError):
    """A safetensors container is malformed or does not match its header."""


@dataclass(frozen=True)
class TensorEntry:
    """One tensor's place in the container."""

    name: str
    dtype: str
    shape: tuple[int, ...]
    offset: int
    length: int

    @property
    def numpy_dtype(self) -> np.dtype[Any]:
        try:
            return _DTYPES[self.dtype]
        except KeyError as exc:
            raise SafetensorsError(f"unsupported safetensors dtype {self.dtype!r}") from exc


@dataclass(frozen=True)
class SafetensorsFile:
    """A validated container header plus the path its data section lives in."""

    path: Path
    entries: tuple[TensorEntry, ...]
    metadata: Mapping[str, str]
    header_bytes: int
    file_bytes: int

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(entry.name for entry in self.entries)

    def entry(self, name: str) -> TensorEntry:
        for entry in self.entries:
            if entry.name == name:
                return entry
        raise SafetensorsError(f"tensor is not present: {name}")

    def shapes(self) -> dict[str, list[int]]:
        return {entry.name: list(entry.shape) for entry in self.entries}

    def read(self, name: str) -> np.ndarray:
        """Read one tensor, verifying that its slice has the promised length."""
        entry = self.entry(name)
        with self.path.open("rb") as handle:
            handle.seek(entry.offset)
            raw = handle.read(entry.length)
        if len(raw) != entry.length:
            raise SafetensorsError(f"tensor payload is truncated: {name}")
        array = np.frombuffer(raw, dtype=entry.numpy_dtype)
        return array.reshape(entry.shape)


def open_safetensors(path: Path | str) -> SafetensorsFile:
    """Validate a container header and return a reader for its tensors."""
    container = Path(path)
    try:
        size = container.stat().st_size
    except OSError as exc:
        raise SafetensorsError("the safetensors file is not readable") from exc
    if size < 8:
        raise SafetensorsError("the safetensors file is too short to hold a header")
    with container.open("rb") as handle:
        length = struct.unpack("<Q", handle.read(8))[0]
        if length <= 0 or length > MAX_HEADER_BYTES or 8 + length > size:
            raise SafetensorsError("the safetensors header length is out of range")
        raw_header = handle.read(length)
    try:
        document = json.loads(raw_header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetensorsError("the safetensors header is not JSON") from exc
    if not isinstance(document, dict):
        raise SafetensorsError("the safetensors header must be an object")
    metadata = document.pop("__metadata__", {})
    if not isinstance(metadata, dict):
        raise SafetensorsError("the safetensors metadata must be an object")
    data_start = 8 + length
    entries: list[TensorEntry] = []
    for name, value in document.items():
        if not isinstance(value, dict) or set(value) != {"dtype", "shape", "data_offsets"}:
            raise SafetensorsError(f"tensor descriptor is malformed: {name}")
        if not isinstance(value["dtype"], str) or not isinstance(value["shape"], list):
            raise SafetensorsError(f"tensor descriptor is malformed: {name}")
        offsets = value["data_offsets"]
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(isinstance(item, int) for item in offsets)
        ):
            raise SafetensorsError(f"tensor offsets are malformed: {name}")
        begin, end = offsets
        if begin < 0 or end < begin:
            raise SafetensorsError(f"tensor offsets are out of order: {name}")
        shape = tuple(int(item) for item in value["shape"])
        if any(item < 0 for item in shape):
            raise SafetensorsError(f"tensor shape is negative: {name}")
        entry = TensorEntry(
            name=name,
            dtype=value["dtype"],
            shape=shape,
            offset=data_start + begin,
            length=end - begin,
        )
        expected = int(np.prod(entry.shape, dtype=np.int64)) * entry.numpy_dtype.itemsize
        if expected != entry.length:
            raise SafetensorsError(f"tensor byte length does not match its shape: {name}")
        if entry.offset + entry.length > size:
            raise SafetensorsError(f"tensor runs past the end of the file: {name}")
        entries.append(entry)
    if not entries:
        raise SafetensorsError("the safetensors file carries no tensors")
    entries.sort(key=lambda item: item.offset)
    for previous, following in zip(entries, entries[1:]):
        if previous.offset + previous.length > following.offset:
            raise SafetensorsError(
                f"tensor payloads overlap: {previous.name} and {following.name}"
            )
    return SafetensorsFile(
        path=container,
        entries=tuple(sorted(entries, key=lambda item: item.name)),
        metadata={str(key): str(value) for key, value in metadata.items()},
        header_bytes=length,
        file_bytes=size,
    )


__all__ = [
    "MAX_HEADER_BYTES",
    "SafetensorsError",
    "SafetensorsFile",
    "TensorEntry",
    "open_safetensors",
]

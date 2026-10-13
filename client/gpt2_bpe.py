"""The frozen GPT-2 byte-pair encoder, in plain Python.

The client is the only party that ever sees the prompt, and it runs where a
deep-learning stack is not guaranteed, so the released GPT-2 encoder is
reimplemented here rather than imported: the byte-to-unicode table, the
pre-tokenisation pattern, the merge ranks read from the frozen ``merges.txt``
and the vocabulary from the frozen ``vocab.json``.

The one place this file could quietly diverge from the released tokenizer is the
pre-tokenisation pattern, because the released one is written against
``\\p{L}``/``\\p{N}`` and Python's :mod:`re` has no property escapes. The classes
below are the documented substitution, and ``tests/unit/test_d7_gpt2_tools.py``
holds this encoder to the released one over a fixed corpus instead of trusting
the substitution.

The ids this returns are real GPT-2 vocabulary ids. They are not the candidate
indices the enclave program ranks; ``infra.d7_vectors`` owns that mapping.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping, Sequence


MERGES_FILE = "merges.txt"
VOCAB_FILE = "vocab.json"


class Gpt2BpeError(ValueError):
    """The frozen vocabulary or merges file is missing or malformed."""


# The pre-tokenisation pattern of the released encoder with the property
# escapes replaced by their Python classes: letters are ``[^\W\d_]``, numbers
# are ``\d``, and everything that is neither space, letter nor number is
# ``[^\s\w]|_`` (the underscore is a word character here but not a letter).
PRE_TOKEN_PATTERN = re.compile(
    r"""'s|'t|'re|'ve|'m|'ll|'d| ?[^\W\d_]+| ?\d+| ?(?:[^\s\w]|_)+|\s+(?!\S)|\s+""",
    re.UNICODE,
)


@lru_cache(maxsize=1)
def bytes_to_unicode() -> dict[int, str]:
    """GPT-2's reversible map from the 256 byte values to printable characters."""
    printable = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("\xa1"), ord("\xac") + 1))
        + list(range(ord("\xae"), ord("\xff") + 1))
    )
    mapped = list(printable)
    extra = 0
    for value in range(256):
        if value not in printable:
            mapped.append(value)
    table: dict[int, str] = {}
    for index, value in enumerate(mapped):
        if index < len(printable):
            table[value] = chr(value)
        else:
            table[value] = chr(256 + extra)
            extra += 1
    return table


@lru_cache(maxsize=1)
def _unicode_to_bytes() -> dict[str, int]:
    return {character: value for value, character in bytes_to_unicode().items()}


def _merge_ranks(lines: Iterable[str]) -> dict[tuple[str, str], int]:
    ranks: dict[tuple[str, str], int] = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#version"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise Gpt2BpeError(f"a merge rule is malformed: {line!r}")
        ranks[(parts[0], parts[1])] = len(ranks)
    return ranks


def _pairs(word: Sequence[str]) -> set[tuple[str, str]]:
    return {(word[index], word[index + 1]) for index in range(len(word) - 1)}


@dataclass(frozen=True)
class Gpt2Bpe:
    """A frozen byte-pair encoder and decoder."""

    vocabulary: Mapping[str, int]
    ranks: Mapping[tuple[str, str], int]
    unk_token: str = "<|endoftext|>"

    @property
    def vocab_size(self) -> int:
        return len(self.vocabulary)

    @property
    def unk_id(self) -> int:
        try:
            return int(self.vocabulary[self.unk_token])
        except KeyError as exc:
            raise Gpt2BpeError("the vocabulary has no end-of-text token") from exc

    def _bpe(self, token: str) -> tuple[str, ...]:
        word = tuple(token)
        if len(word) < 2:
            return word
        pairs = _pairs(word)
        while pairs:
            best = min(pairs, key=lambda pair: self.ranks.get(pair, 1 << 30))
            if best not in self.ranks:
                break
            first, second = best
            merged: list[str] = []
            index = 0
            while index < len(word):
                if (
                    index < len(word) - 1
                    and word[index] == first
                    and word[index + 1] == second
                ):
                    merged.append(first + second)
                    index += 2
                else:
                    merged.append(word[index])
                    index += 1
            word = tuple(merged)
            if len(word) < 2:
                break
            pairs = _pairs(word)
        return word

    def encode(self, text: str) -> list[int]:
        """Encode text into real GPT-2 vocabulary ids."""
        if not isinstance(text, str):
            raise Gpt2BpeError("the prompt must be text")
        table = bytes_to_unicode()
        ids: list[int] = []
        for chunk in PRE_TOKEN_PATTERN.findall(text):
            mapped = "".join(table[value] for value in chunk.encode("utf-8"))
            for piece in self._bpe(mapped):
                if piece in self.vocabulary:
                    ids.append(int(self.vocabulary[piece]))
                else:
                    ids.append(self.unk_id)
        if not ids:
            raise Gpt2BpeError("the prompt has no tokenizable bytes")
        return ids

    def decode(self, ids: Sequence[int]) -> str:
        """Decode ids back to text, replacing bytes that are not valid UTF-8."""
        reverse = _unicode_to_bytes()
        payload = bytearray()
        for value in ids:
            if not isinstance(value, int):
                raise Gpt2BpeError("token ids must be integers")
            piece = None
            for token, index in self.vocabulary.items():
                if int(index) == value:
                    piece = token
                    break
            if piece is None:
                raise Gpt2BpeError(f"token id {value} is outside the vocabulary")
            for character in piece:
                try:
                    payload.append(reverse[character])
                except KeyError as exc:
                    raise Gpt2BpeError(
                        f"token {piece!r} is not byte-encodable"
                    ) from exc
        return payload.decode("utf-8", errors="replace")

    def token(self, value: int) -> str:
        return self.decode([value])


def load_bpe(directory: Path | str) -> Gpt2Bpe:
    """Read the frozen vocabulary and merge rules from a source directory."""
    root = Path(directory)
    try:
        vocabulary = json.loads((root / VOCAB_FILE).read_text(encoding="utf-8"))
        merges = (root / MERGES_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, json.JSONDecodeError) as exc:
        raise Gpt2BpeError("the frozen tokenizer files are unreadable") from exc
    if not isinstance(vocabulary, dict) or not vocabulary:
        raise Gpt2BpeError("the frozen vocabulary is malformed")
    return Gpt2Bpe(
        vocabulary={str(key): int(value) for key, value in vocabulary.items()},
        ranks=_merge_ranks(merges),
    )


def inverse_vocabulary(encoder: Gpt2Bpe) -> dict[int, str]:
    """id -> token, built once for callers that decode many ids."""
    lookup: dict[int, str] = {}
    for token, index in encoder.vocabulary.items():
        lookup.setdefault(int(index), str(token))
    return lookup


__all__ = [
    "MERGES_FILE",
    "PRE_TOKEN_PATTERN",
    "VOCAB_FILE",
    "Gpt2Bpe",
    "Gpt2BpeError",
    "bytes_to_unicode",
    "inverse_vocabulary",
    "load_bpe",
]

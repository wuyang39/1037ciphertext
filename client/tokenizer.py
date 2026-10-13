"""The frozen word-level tokenizer D6 ships with the toy decoder.

D7 replaces this with the real GPT-2 byte-pair encoder. D6 needs a tokenizer
that is deterministic, versioned and small enough that both the client and the
acceptance record can reproduce a token string from ids offline, so it is a
lower-cased whitespace tokenizer over a pinned vocabulary. The vocabulary has
its own digest, and that digest is part of the model manifest the session
binds to, so swapping the vocabulary changes the session bindings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from contracts import canonical_hash


class TokenizerError(ValueError):
    """The text or the id sequence cannot be tokenized."""


PAD_TOKEN = "<pad>"
BOS_TOKEN = "<bos>"
UNK_TOKEN = "<unk>"

# A pinned English vocabulary. It is deliberately small: the point of D6 is a
# real private autoregressive loop, and D7 brings the real model whose output
# carries meaning. Every word here is in the frozen manifest.
DEFAULT_VOCABULARY: tuple[str, ...] = (
    PAD_TOKEN,
    BOS_TOKEN,
    UNK_TOKEN,
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "are", "was",
    "be", "it", "this", "that", "these", "those", "for", "on", "with", "as",
    "at", "by", "from", "but", "not", "no", "yes", "if", "then", "than",
    "so", "we", "you", "they", "he", "she", "i", "my", "your", "our",
    "their", "his", "her", "its", "one", "two", "three", "first", "second",
    "next", "last", "new", "old", "good", "bad", "big", "small", "long",
    "short", "high", "low", "fast", "slow", "true", "false", "null",
    "cipher", "key", "model", "token", "text", "word", "test", "code",
    "data", "share", "secret", "private", "public", "secure", "proof",
    "enclave", "session", "server", "client", "cloud", "network", "system",
    "machine", "learning", "language", "answer", "question", "result",
    "value", "number", "time", "work", "make", "made", "use", "used", "see",
    "saw", "know", "think", "say", "said", "get", "got", "give", "go",
    "run", "runs", "stop", "start", "end", "open", "close", "read",
    "write", "send", "receive", "check", "verify", "sign", "encrypt",
    "decrypt", "compute", "protect", "keep", "hold", "release",
    "wipe", "clean", "safe", "strong", "weak", "part", "whole",
    "left", "right", "up", "down", "over", "under", "here", "there",
)

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class WordTokenizer:
    """A deterministic id <-> text mapping over a pinned vocabulary."""

    tokens: tuple[str, ...] = DEFAULT_VOCABULARY

    def __post_init__(self) -> None:
        if len(self.tokens) < 4:
            raise TokenizerError("the vocabulary is too small")
        if len(set(self.tokens)) != len(self.tokens):
            raise TokenizerError("the vocabulary has duplicate entries")
        for special in (PAD_TOKEN, BOS_TOKEN, UNK_TOKEN):
            if special not in self.tokens:
                raise TokenizerError(f"the vocabulary needs {special!r}")
        if self.tokens[0] != PAD_TOKEN:
            raise TokenizerError(f"{PAD_TOKEN!r} must be id 0")

    @property
    def vocab_size(self) -> int:
        return len(self.tokens)

    @property
    def pad_id(self) -> int:
        return self.tokens.index(PAD_TOKEN)

    @property
    def bos_id(self) -> int:
        return self.tokens.index(BOS_TOKEN)

    @property
    def unk_id(self) -> int:
        return self.tokens.index(UNK_TOKEN)

    @property
    def vocabulary_digest(self) -> str:
        return canonical_hash({"tokens": list(self.tokens)})

    def encode(self, text: str) -> list[int]:
        if not isinstance(text, str):
            raise TokenizerError("the prompt must be text")
        words = _TOKEN_PATTERN.findall(text.lower())
        if not words:
            raise TokenizerError("the prompt has no tokenizable words")
        index = {token: position for position, token in enumerate(self.tokens)}
        return [index.get(word, self.unk_id) for word in words]

    def decode(self, ids: Sequence[int]) -> str:
        rendered: list[str] = []
        for value in ids:
            if not isinstance(value, int) or not 0 <= value < self.vocab_size:
                raise TokenizerError(f"token id {value!r} is outside the vocabulary")
            token = self.tokens[value]
            if token in (PAD_TOKEN, BOS_TOKEN):
                continue
            rendered.append(token)
        return " ".join(rendered)

    def token(self, value: int) -> str:
        if not isinstance(value, int) or not 0 <= value < self.vocab_size:
            raise TokenizerError(f"token id {value!r} is outside the vocabulary")
        return self.tokens[value]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokenizer": "a122-word-v1",
            "vocab_size": self.vocab_size,
            "vocabulary_digest": self.vocabulary_digest,
            "tokens": list(self.tokens),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "WordTokenizer":
        if not isinstance(document, Mapping):
            raise TokenizerError("the tokenizer document must be a mapping")
        if document.get("tokenizer") != "a122-word-v1":
            raise TokenizerError("unknown tokenizer")
        tokens = document.get("tokens")
        if not isinstance(tokens, list) or not all(
            isinstance(token, str) for token in tokens
        ):
            raise TokenizerError("the tokenizer vocabulary is malformed")
        tokenizer = cls(tokens=tuple(tokens))
        if document.get("vocabulary_digest") != tokenizer.vocabulary_digest:
            raise TokenizerError("the tokenizer vocabulary digest does not match")
        if int(document.get("vocab_size", -1)) != tokenizer.vocab_size:
            raise TokenizerError("the tokenizer vocabulary size does not match")
        return tokenizer


__all__ = [
    "BOS_TOKEN",
    "DEFAULT_VOCABULARY",
    "PAD_TOKEN",
    "TokenizerError",
    "UNK_TOKEN",
    "WordTokenizer",
]

"""The frozen English GPT-2 source: files, hashes, geometry and tensor layout.

D7 replaces the synthetic Tiny decoder with the official ``gpt2`` checkpoint.
"Official" only means something if the bytes are pinned, so this module carries
the identity of the frozen revision: the repository, the commit, the sha256 of
every file that was downloaded, and the license the checkpoint is released
under. :func:`verify_gpt2_source` re-reads a directory and reports the same
record, which is what the acceptance evidence stores.

The checkpoint keeps its attention projection fused as ``c_attn`` with the
HuggingFace ``Conv1D`` convention (the stored matrix is already ``in x out``).
The enclave program wants the three projections apart, so this module owns the
one place that splits them: :func:`load_gpt2_weights` returns the flat, ordered
tensor set the MPC program consumes, sliced from the real weights and nothing
else. No value is drawn, scaled or replaced.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from contracts import canonical_hash
from model.safetensors import SafetensorsFile, open_safetensors


GPT2_REPOSITORY = "gpt2"
GPT2_REVISION = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
GPT2_LICENSE = "Modified MIT License (OpenAI, 2019)"
GPT2_UPSTREAM = "https://github.com/openai/gpt-2"
GPT2_PARAMETERS = 124_439_808
"""Parameter count with the twelve constant causal-mask buffers excluded."""


class Gpt2Error(ValueError):
    """The frozen GPT-2 source is missing, altered, or not the pinned revision."""


@dataclass(frozen=True)
class SourceFile:
    """One frozen file with the digest that pins it."""

    name: str
    size: int
    sha256: str


# Every file was downloaded from the revision above through the mirror named in
# the freeze record; the digests below are what verifies a local copy.
SOURCE_FILES: tuple[SourceFile, ...] = (
    SourceFile(
        "config.json",
        665,
        "0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4",
    ),
    SourceFile(
        "merges.txt",
        456318,
        "1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5",
    ),
    SourceFile(
        "model.safetensors",
        548105171,
        "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707",
    ),
    SourceFile(
        "README.md",
        8092,
        "0fcd631078093c2aa1d93438b898320b8a1167784e2a1ab37b8016e9de8b3c2e",
    ),
    SourceFile(
        "tokenizer.json",
        1355256,
        "8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6",
    ),
    SourceFile(
        "vocab.json",
        1042301,
        "196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783",
    ),
)

WEIGHTS_FILE = "model.safetensors"
CONFIG_FILE = "config.json"
TOKENIZER_FILE = "tokenizer.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class Gpt2Config:
    """The geometry the frozen ``config.json`` declares."""

    vocab_size: int
    n_positions: int
    n_ctx: int
    n_embd: int
    n_head: int
    n_layer: int
    layer_norm_epsilon: float
    activation_function: str
    bos_token_id: int
    eos_token_id: int

    def __post_init__(self) -> None:
        for name in (
            "vocab_size",
            "n_positions",
            "n_ctx",
            "n_embd",
            "n_head",
            "n_layer",
        ):
            if int(getattr(self, name)) <= 0:
                raise Gpt2Error(f"{name} must be positive")
        if self.n_embd % self.n_head:
            raise Gpt2Error("n_embd must be divisible by n_head")
        if self.activation_function not in {"gelu_new", "gelu"}:
            raise Gpt2Error(
                f"the frozen activation {self.activation_function!r} is not supported"
            )

    @property
    def head_size(self) -> int:
        return self.n_embd // self.n_head

    @property
    def intermediate_size(self) -> int:
        """GPT-2's MLP width is four times the embedding width."""
        return 4 * self.n_embd

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Gpt2Config":
        if value.get("model_type") != "gpt2":
            raise Gpt2Error("the frozen configuration is not a GPT-2 model")
        try:
            return cls(
                vocab_size=int(value["vocab_size"]),
                n_positions=int(value["n_positions"]),
                n_ctx=int(value["n_ctx"]),
                n_embd=int(value["n_embd"]),
                n_head=int(value["n_head"]),
                n_layer=int(value["n_layer"]),
                layer_norm_epsilon=float(value["layer_norm_epsilon"]),
                activation_function=str(value["activation_function"]),
                bos_token_id=int(value["bos_token_id"]),
                eos_token_id=int(value["eos_token_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise Gpt2Error(f"the frozen configuration is malformed: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "vocab_size": self.vocab_size,
            "n_positions": self.n_positions,
            "n_ctx": self.n_ctx,
            "n_embd": self.n_embd,
            "n_head": self.n_head,
            "n_layer": self.n_layer,
            "layer_norm_epsilon": self.layer_norm_epsilon,
            "activation_function": self.activation_function,
            "bos_token_id": self.bos_token_id,
            "eos_token_id": self.eos_token_id,
        }


def load_config(directory: Path | str) -> Gpt2Config:
    path = Path(directory) / CONFIG_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Gpt2Error("the frozen configuration is not readable JSON") from exc
    if not isinstance(document, dict):
        raise Gpt2Error("the frozen configuration must be an object")
    return Gpt2Config.from_dict(document)


def verify_gpt2_source(directory: Path | str) -> dict[str, Any]:
    """Re-hash a frozen source directory and report every file's verdict."""
    root = Path(directory)
    records: list[dict[str, Any]] = []
    for expected in SOURCE_FILES:
        path = root / expected.name
        if not path.is_file():
            records.append(
                {
                    "name": expected.name,
                    "expected_size": expected.size,
                    "expected_sha256": expected.sha256,
                    "present": False,
                    "verified": False,
                }
            )
            continue
        size = path.stat().st_size
        digest = _sha256_file(path)
        records.append(
            {
                "name": expected.name,
                "expected_size": expected.size,
                "expected_sha256": expected.sha256,
                "size": size,
                "sha256": digest,
                "present": True,
                "verified": size == expected.size and digest == expected.sha256,
            }
        )
    verified = all(record["verified"] for record in records)
    return {
        "repository": GPT2_REPOSITORY,
        "revision": GPT2_REVISION,
        "upstream": GPT2_UPSTREAM,
        "license": GPT2_LICENSE,
        "parameters": GPT2_PARAMETERS,
        "files": records,
        "verified": verified,
    }


def require_gpt2_source(directory: Path | str) -> dict[str, Any]:
    """Refuse a source directory that is not byte-for-byte the frozen one."""
    record = verify_gpt2_source(directory)
    if not record["verified"]:
        missing = [
            entry["name"] for entry in record["files"] if not entry.get("verified")
        ]
        raise Gpt2Error("the frozen GPT-2 source does not verify: " + ", ".join(missing))
    return record


def tokenizer_sha256(directory: Path | str) -> str:
    """The digest the model manifest binds for the byte-pair encoder."""
    path = Path(directory) / TOKENIZER_FILE
    if not path.is_file():
        raise Gpt2Error("the frozen tokenizer is missing")
    return _sha256_file(path)


def candidate_token_ids(
    size: int,
    *,
    required: Iterable[int] = (),
    vocab_size: int = 50257,
) -> tuple[int, ...]:
    """The candidate set the secure Argmax ranks.

    GPT-2 numbers its byte pairs in merge order, so the lowest ids are the
    most-merged (most frequent) units in the training corpus. The rule is
    therefore public and prompt-independent: take the ``size`` lowest ids and
    add whatever ids the run's own prompt encodes to, since a prompt token that
    cannot be embedded could not be run at all. The resulting tuple is
    ascending and is part of the model manifest, so a client that disagrees
    about the candidate set is refused rather than silently scored differently.
    """
    if size < 1 or size > vocab_size:
        raise Gpt2Error("the candidate set size is outside the vocabulary")
    ids = set(range(size))
    for value in required:
        token = int(value)
        if not 0 <= token < vocab_size:
            raise Gpt2Error(f"candidate token id {token} is outside the vocabulary")
        ids.add(token)
    return tuple(sorted(ids))


def candidate_vocabulary_digest(token_ids: Sequence[int]) -> str:
    """The digest a session binds for one candidate vocabulary."""
    ordered = list(token_ids)
    if not ordered or list(sorted(set(ordered))) != ordered:
        raise Gpt2Error("the candidate vocabulary must be non-empty and ascending")
    return canonical_hash({"candidate_tokens": ordered})


LAYER_TENSOR_SUFFIXES: tuple[str, ...] = (
    "ln_1.weight",
    "ln_1.bias",
    "attn.q.weight",
    "attn.q.bias",
    "attn.k.weight",
    "attn.k.bias",
    "attn.v.weight",
    "attn.v.bias",
    "attn.proj.weight",
    "attn.proj.bias",
    "ln_2.weight",
    "ln_2.bias",
    "mlp.fc.weight",
    "mlp.fc.bias",
    "mlp.proj.weight",
    "mlp.proj.bias",
)


def weight_tensor_names(layers: int) -> tuple[str, ...]:
    """The flat, ordered tensor set the enclave program consumes."""
    if layers < 1:
        raise Gpt2Error("a model needs at least one layer")
    names = ["token_embedding.weight", "position_embedding.weight"]
    for index in range(layers):
        names.extend(f"layer_{index}.{suffix}" for suffix in LAYER_TENSOR_SUFFIXES)
    names.extend(("ln_f.weight", "ln_f.bias", "lm_head.weight", "lm_head.bias"))
    return tuple(names)


def _tensor(store: SafetensorsFile, name: str) -> np.ndarray:
    return np.asarray(store.read(name), dtype=np.float64)


def load_gpt2_weights(
    store: SafetensorsFile,
    config: Gpt2Config,
    *,
    layers: int,
    token_ids: Sequence[int],
    sequence: int,
) -> dict[str, np.ndarray]:
    """Slice the real checkpoint into the flat tensor set the program runs.

    Three slices are taken and nothing else: the layers are the leading
    ``layers`` blocks, the embedding and output tables keep the rows of
    ``token_ids``, and the position table keeps its leading ``sequence`` rows.
    """
    if layers < 1 or layers > config.n_layer:
        raise Gpt2Error("the requested layer range leaves the frozen model")
    if not 1 <= sequence <= config.n_positions:
        raise Gpt2Error("the requested sequence leaves the position table")
    if len(token_ids) < 1:
        raise Gpt2Error("the candidate vocabulary must not be empty")
    rows = np.asarray(list(token_ids), dtype=np.int64)
    if int(rows.max()) >= config.vocab_size or int(rows.min()) < 0:
        raise Gpt2Error("a candidate token id leaves the vocabulary")
    matrix = config.n_embd
    word_embedding = _tensor(store, "wte.weight")
    weights: dict[str, np.ndarray] = {
        "token_embedding.weight": word_embedding[rows].copy(),
        "position_embedding.weight": _tensor(store, "wpe.weight")[:sequence].copy(),
    }
    for index in range(layers):
        prefix = f"h.{index}."
        fused_weight = _tensor(store, prefix + "attn.c_attn.weight")
        fused_bias = _tensor(store, prefix + "attn.c_attn.bias")
        if fused_weight.shape != (matrix, 3 * matrix):
            raise Gpt2Error(f"layer {index} has an unexpected fused projection shape")
        q, k, v = np.array_split(fused_weight, 3, axis=1)
        q_bias, k_bias, v_bias = np.array_split(fused_bias, 3, axis=0)
        layer = f"layer_{index}."
        weights.update(
            {
                layer + "ln_1.weight": _tensor(store, prefix + "ln_1.weight"),
                layer + "ln_1.bias": _tensor(store, prefix + "ln_1.bias"),
                layer + "attn.q.weight": np.ascontiguousarray(q),
                layer + "attn.q.bias": np.ascontiguousarray(q_bias),
                layer + "attn.k.weight": np.ascontiguousarray(k),
                layer + "attn.k.bias": np.ascontiguousarray(k_bias),
                layer + "attn.v.weight": np.ascontiguousarray(v),
                layer + "attn.v.bias": np.ascontiguousarray(v_bias),
                layer + "attn.proj.weight": _tensor(store, prefix + "attn.c_proj.weight"),
                layer + "attn.proj.bias": _tensor(store, prefix + "attn.c_proj.bias"),
                layer + "ln_2.weight": _tensor(store, prefix + "ln_2.weight"),
                layer + "ln_2.bias": _tensor(store, prefix + "ln_2.bias"),
                layer + "mlp.fc.weight": _tensor(store, prefix + "mlp.c_fc.weight"),
                layer + "mlp.fc.bias": _tensor(store, prefix + "mlp.c_fc.bias"),
                layer + "mlp.proj.weight": _tensor(store, prefix + "mlp.c_proj.weight"),
                layer + "mlp.proj.bias": _tensor(store, prefix + "mlp.c_proj.bias"),
            }
        )
    weights["ln_f.weight"] = _tensor(store, "ln_f.weight")
    weights["ln_f.bias"] = _tensor(store, "ln_f.bias")
    # GPT-2 ties the output projection to the input embedding, so the head is
    # the same rows transposed rather than a second table the checkpoint omits.
    weights["lm_head.weight"] = np.ascontiguousarray(
        word_embedding[rows].transpose(1, 0)
    )
    weights["lm_head.bias"] = np.zeros(len(token_ids), dtype=np.float64)
    return weights


def open_frozen_store(directory: Path | str) -> SafetensorsFile:
    return open_safetensors(Path(directory) / WEIGHTS_FILE)


__all__ = [
    "CONFIG_FILE",
    "GPT2_LICENSE",
    "GPT2_PARAMETERS",
    "GPT2_REPOSITORY",
    "GPT2_REVISION",
    "GPT2_UPSTREAM",
    "Gpt2Config",
    "Gpt2Error",
    "LAYER_TENSOR_SUFFIXES",
    "SOURCE_FILES",
    "SourceFile",
    "TOKENIZER_FILE",
    "WEIGHTS_FILE",
    "candidate_token_ids",
    "candidate_vocabulary_digest",
    "load_config",
    "load_gpt2_weights",
    "open_frozen_store",
    "require_gpt2_source",
    "tokenizer_sha256",
    "verify_gpt2_source",
    "weight_tensor_names",
]

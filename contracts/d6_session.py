"""Frozen D6 session descriptors shared by the client and the enclave nodes.

D5 drove one fixed case grid from P0. D6 lets an outside client open a session,
so the things both sides must agree on move into one versioned document: the
geometry the MHLO programs are built for, the model and precision manifests the
session binds to, and the two payload shapes that travel inside the encrypted
frames.

``SessionPlan`` is the wire form of that agreement. Its digests are the values
the KAS signs into the JobTicket and the values every ``ResultFrame`` is bound
to, so a session cannot silently drift from the model it claims to run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from contracts import canonical_hash


SESSION_PROTOCOL = "a122-d6-session-v1"
STEP_PAYLOAD_PROTOCOL = "a122-d6-step-v1"
RESULT_PAYLOAD_PROTOCOL = "a122-d6-result-v1"
NODE_CONFIG_VERSION = "a122-d6-node-v1"

STEP_MESSAGES = ("ping", "hello", "finished", "step", "close", "status", "shutdown")

# The precision plan D6 pins: the same SEMI2K/FM64 fixed-point setup D4 and D5
# measured, with no configured plaintext reveal anywhere in the path.
PRECISION_PLAN: dict[str, Any] = {
    "plan_version": "a122-precision-v1",
    "protocol": "SEMI2K",
    "field": "FM64",
    "fractional_bits": 18,
    "reveal_policy": "none",
    "postprocess": "dyadic-18",
}


class PlanError(ValueError):
    """A model manifest, a session plan or a step payload is malformed."""


def precision_plan_hash(plan: Mapping[str, Any] | None = None) -> str:
    """Digest the frozen precision plan, or a variant of it."""
    return canonical_hash(dict(plan or PRECISION_PLAN))


@dataclass(frozen=True)
class ModelManifest:
    """The tiny decoder D6 runs, pinned so every instance builds one model."""

    model_version: str
    weight_seed: int
    sequence: int
    hidden_size: int
    num_heads: int
    intermediate_size: int
    vocab_size: int
    tokenizer_digest: str
    fractional_bits: int = 18

    def __post_init__(self) -> None:
        if not self.model_version:
            raise PlanError("the model version must not be empty")
        if self.hidden_size % self.num_heads:
            raise PlanError("hidden_size must be divisible by num_heads")
        for name in (
            "sequence",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "vocab_size",
        ):
            if int(getattr(self, name)) <= 0:
                raise PlanError(f"{name} must be positive")
        if not 0 < self.fractional_bits < 63:
            raise PlanError("fractional_bits is outside the fixed-point range")
        if not isinstance(self.tokenizer_digest, str) or len(self.tokenizer_digest) != 64:
            raise PlanError("the tokenizer digest must be a 32-byte digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "weight_seed": int(self.weight_seed),
            "sequence": int(self.sequence),
            "hidden_size": int(self.hidden_size),
            "num_heads": int(self.num_heads),
            "intermediate_size": int(self.intermediate_size),
            "vocab_size": int(self.vocab_size),
            "tokenizer_digest": self.tokenizer_digest,
            "fractional_bits": int(self.fractional_bits),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelManifest":
        try:
            return cls(
                model_version=str(value["model_version"]),
                weight_seed=int(value["weight_seed"]),
                sequence=int(value["sequence"]),
                hidden_size=int(value["hidden_size"]),
                num_heads=int(value["num_heads"]),
                intermediate_size=int(value["intermediate_size"]),
                vocab_size=int(value["vocab_size"]),
                tokenizer_digest=str(value["tokenizer_digest"]),
                fractional_bits=int(value.get("fractional_bits", 18)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"the model manifest is malformed: {exc}") from exc

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


@dataclass(frozen=True)
class SessionPlan:
    """Everything one D6 session binds to, in the form the nodes check."""

    release_id: str
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    sequence: int
    vocab_size: int
    hidden_size: int
    num_heads: int
    intermediate_size: int
    fractional_bits: int
    max_new_tokens: int
    length_bound: int

    def __post_init__(self) -> None:
        if not self.release_id or not self.model_version:
            raise PlanError("the release and model version must not be empty")
        for name in ("model_manifest_hash", "precision_plan_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise PlanError(f"{name} must be a 32-byte digest")
        if not isinstance(self.share_epoch, int) or self.share_epoch < 0:
            raise PlanError("share_epoch must be a non-negative integer")
        if self.hidden_size % self.num_heads:
            raise PlanError("hidden_size must be divisible by num_heads")
        for name in (
            "sequence",
            "vocab_size",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "max_new_tokens",
            "length_bound",
        ):
            if int(getattr(self, name)) <= 0:
                raise PlanError(f"{name} must be positive")
        if self.max_new_tokens >= self.sequence:
            raise PlanError(
                "the context window must be able to hold the prompt and the "
                "generated tokens"
            )

    @classmethod
    def for_manifest(
        cls,
        manifest: ModelManifest,
        *,
        release_id: str,
        share_epoch: int,
        max_new_tokens: int,
        length_bound: int,
    ) -> "SessionPlan":
        return cls(
            release_id=release_id,
            model_version=manifest.model_version,
            model_manifest_hash=manifest.digest(),
            precision_plan_hash=precision_plan_hash(),
            share_epoch=share_epoch,
            sequence=manifest.sequence,
            vocab_size=manifest.vocab_size,
            hidden_size=manifest.hidden_size,
            num_heads=manifest.num_heads,
            intermediate_size=manifest.intermediate_size,
            fractional_bits=manifest.fractional_bits,
            max_new_tokens=max_new_tokens,
            length_bound=length_bound,
        )

    @property
    def prompt_budget(self) -> int:
        """How many prompt tokens fit next to every generated token."""
        return self.sequence - self.max_new_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_version": SESSION_PROTOCOL,
            "release_id": self.release_id,
            "model_version": self.model_version,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": int(self.share_epoch),
            "sequence": int(self.sequence),
            "vocab_size": int(self.vocab_size),
            "hidden_size": int(self.hidden_size),
            "num_heads": int(self.num_heads),
            "intermediate_size": int(self.intermediate_size),
            "fractional_bits": int(self.fractional_bits),
            "max_new_tokens": int(self.max_new_tokens),
            "length_bound": int(self.length_bound),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SessionPlan":
        if not isinstance(value, Mapping):
            raise PlanError("the session plan must be a mapping")
        if value.get("plan_version") != SESSION_PROTOCOL:
            raise PlanError("unknown session plan version")
        try:
            return cls(
                release_id=str(value["release_id"]),
                model_version=str(value["model_version"]),
                model_manifest_hash=str(value["model_manifest_hash"]),
                precision_plan_hash=str(value["precision_plan_hash"]),
                share_epoch=int(value["share_epoch"]),
                sequence=int(value["sequence"]),
                vocab_size=int(value["vocab_size"]),
                hidden_size=int(value["hidden_size"]),
                num_heads=int(value["num_heads"]),
                intermediate_size=int(value["intermediate_size"]),
                fractional_bits=int(value["fractional_bits"]),
                max_new_tokens=int(value["max_new_tokens"]),
                length_bound=int(value["length_bound"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"the session plan is malformed: {exc}") from exc


def step_payload(*, decode_step: int, history_share: str) -> bytes:
    """The client's per-step payload: its share of the history one-hot rows.

    Only the share travels. The digest both sides keep is taken over the share
    string itself rather than over the one-hot matrix: a digest of the plaintext
    history would be a brute-forceable fingerprint of the prompt.
    """
    from contracts import canonical_bytes

    if decode_step < 1:
        raise PlanError("decode_step must be positive")
    return canonical_bytes(
        {
            "protocol": STEP_PAYLOAD_PROTOCOL,
            "decode_step": int(decode_step),
            "history": history_share,
        }
    )


def parse_step_payload(payload: bytes) -> dict[str, Any]:
    """Parse and validate one step payload, or refuse it."""
    import json

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError("the step payload is not canonical JSON") from exc
    if not isinstance(document, dict):
        raise PlanError("the step payload must be an object")
    if document.get("protocol") != STEP_PAYLOAD_PROTOCOL:
        raise PlanError("unknown step payload version")
    if set(document) != {"protocol", "decode_step", "history"}:
        raise PlanError("the step payload has unexpected fields")
    if not isinstance(document["decode_step"], int) or document["decode_step"] < 1:
        raise PlanError("the step payload carries an invalid decode_step")
    if not isinstance(document["history"], str):
        raise PlanError("the step payload carries no history share")
    return document


def result_payload(*, decode_step: int, token_share: str, logits_share: str) -> bytes:
    """One node's per-step output: its share of the next token and the logits.

    The logits travel so the client can check the secure Argmax against the
    logits it reconstructs itself; the step's hidden state stays inside the
    node and never crosses the protocol boundary.
    """
    from contracts import canonical_bytes

    if decode_step < 1:
        raise PlanError("decode_step must be positive")
    return canonical_bytes(
        {
            "protocol": RESULT_PAYLOAD_PROTOCOL,
            "decode_step": int(decode_step),
            "token": token_share,
            "logits": logits_share,
        }
    )


def parse_result_payload(payload: bytes) -> dict[str, Any]:
    import json

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError("the result payload is not canonical JSON") from exc
    if not isinstance(document, dict):
        raise PlanError("the result payload must be an object")
    if document.get("protocol") != RESULT_PAYLOAD_PROTOCOL:
        raise PlanError("unknown result payload version")
    if set(document) != {"protocol", "decode_step", "token", "logits"}:
        raise PlanError("the result payload has unexpected fields")
    if not isinstance(document["decode_step"], int) or document["decode_step"] < 1:
        raise PlanError("the result payload carries an invalid decode_step")
    for name in ("token", "logits"):
        if not isinstance(document[name], str):
            raise PlanError(f"the result payload carries no {name} share")
    return document


__all__ = [
    "NODE_CONFIG_VERSION",
    "PRECISION_PLAN",
    "RESULT_PAYLOAD_PROTOCOL",
    "SESSION_PROTOCOL",
    "STEP_MESSAGES",
    "STEP_PAYLOAD_PROTOCOL",
    "ModelManifest",
    "PlanError",
    "SessionPlan",
    "parse_result_payload",
    "parse_step_payload",
    "precision_plan_hash",
    "result_payload",
    "step_payload",
]

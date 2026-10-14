"""Frozen D7 session descriptors shared by the GPT-2 client and the enclave nodes.

D7 runs the real GPT-2 decoding step, so the things both sides must agree on
are the ones the exported run pinned: the model bundle digest, the byte-pair
tokenizer digest, the candidate vocabulary the secure Argmax ranks, and the
calibrated precision plan. ``D7SessionPlan`` is the wire form of that
agreement; its digests are the values the KAS signs into the JobTicket and the
values every ``ResultFrame`` is bound to, so a session cannot silently drift
from the model it claims to run.

The D6 plan binds a ``weight_seed`` because its model is drawn from one. D7's
model is a frozen checkpoint, so this module binds a content hash instead, and
carries the number of blocks the run actually stacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from contracts import canonical_hash
from contracts.d6_session import PRECISION_PLAN, PlanError, precision_plan_hash


D7_SESSION_PROTOCOL = "a122-d7-session-v1"
D7_STEP_PAYLOAD_PROTOCOL = "a122-d7-step-v1"
D7_RESULT_PAYLOAD_PROTOCOL = "a122-d7-result-v1"
D7_NODE_CONFIG_VERSION = "a122-d7-node-v1"


def _require_digest(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise PlanError(f"{name} must be a 32-byte digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise PlanError(f"{name} must be hexadecimal") from exc
    return value


@dataclass(frozen=True)
class D7ModelManifest:
    """One exported GPT-2 run, pinned by content rather than by seed."""

    model_version: str
    model_hash: str
    tokenizer_hash: str
    candidate_vocabulary_hash: str
    # The calibration plan the export recorded: the per-tensor dyadic widths.
    # ``D7SessionPlan.precision_plan_hash`` is a different document -- the
    # runtime descriptor (SEMI2K over FM64 at a pinned fractional width) that
    # every result frame is bound to -- so the two are carried separately.
    export_precision_plan_hash: str
    sequence: int
    layers: int
    hidden_size: int
    num_heads: int
    intermediate_size: int
    vocab_size: int
    fractional_bits: int = 18

    def __post_init__(self) -> None:
        if not self.model_version:
            raise PlanError("the model version must not be empty")
        for name in (
            "model_hash",
            "tokenizer_hash",
            "candidate_vocabulary_hash",
            "export_precision_plan_hash",
        ):
            _require_digest(getattr(self, name), name=name)
        if self.hidden_size % self.num_heads:
            raise PlanError("hidden_size must be divisible by num_heads")
        for name in (
            "sequence",
            "layers",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "vocab_size",
        ):
            if int(getattr(self, name)) <= 0:
                raise PlanError(f"{name} must be positive")
        if not 0 < self.fractional_bits < 63:
            raise PlanError("fractional_bits is outside the fixed-point range")

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "model_hash": self.model_hash,
            "tokenizer_hash": self.tokenizer_hash,
            "candidate_vocabulary_hash": self.candidate_vocabulary_hash,
            "export_precision_plan_hash": self.export_precision_plan_hash,
            "sequence": int(self.sequence),
            "layers": int(self.layers),
            "hidden_size": int(self.hidden_size),
            "num_heads": int(self.num_heads),
            "intermediate_size": int(self.intermediate_size),
            "vocab_size": int(self.vocab_size),
            "fractional_bits": int(self.fractional_bits),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "D7ModelManifest":
        try:
            return cls(
                model_version=str(value["model_version"]),
                model_hash=str(value["model_hash"]),
                tokenizer_hash=str(value["tokenizer_hash"]),
                candidate_vocabulary_hash=str(value["candidate_vocabulary_hash"]),
                export_precision_plan_hash=str(value["export_precision_plan_hash"]),
                sequence=int(value["sequence"]),
                layers=int(value["layers"]),
                hidden_size=int(value["hidden_size"]),
                num_heads=int(value["num_heads"]),
                intermediate_size=int(value["intermediate_size"]),
                vocab_size=int(value["vocab_size"]),
                fractional_bits=int(value.get("fractional_bits", 18)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"the model manifest is malformed: {exc}") from exc

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


@dataclass(frozen=True)
class D7SessionPlan:
    """Everything one D7 session binds to, in the form the nodes check."""

    release_id: str
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    sequence: int
    layers: int
    vocab_size: int
    hidden_size: int
    num_heads: int
    intermediate_size: int
    fractional_bits: int
    prompt_tokens: int
    max_new_tokens: int
    length_bound: int

    def __post_init__(self) -> None:
        if not self.release_id or not self.model_version:
            raise PlanError("the release and model version must not be empty")
        for name in ("model_manifest_hash", "precision_plan_hash"):
            _require_digest(getattr(self, name), name=name)
        if not isinstance(self.share_epoch, int) or self.share_epoch < 0:
            raise PlanError("share_epoch must be a non-negative integer")
        if self.hidden_size % self.num_heads:
            raise PlanError("hidden_size must be divisible by num_heads")
        for name in (
            "sequence",
            "layers",
            "vocab_size",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "prompt_tokens",
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
        if self.prompt_tokens > self.prompt_budget:
            raise PlanError(
                "the pinned prompt does not fit next to the generated tokens"
            )

    @classmethod
    def for_manifest(
        cls,
        manifest: D7ModelManifest,
        *,
        release_id: str,
        share_epoch: int,
        max_new_tokens: int,
        length_bound: int,
        prompt_tokens: int,
    ) -> "D7SessionPlan":
        return cls(
            release_id=release_id,
            model_version=manifest.model_version,
            model_manifest_hash=manifest.digest(),
            precision_plan_hash=precision_plan_hash(),
            share_epoch=share_epoch,
            sequence=manifest.sequence,
            layers=manifest.layers,
            vocab_size=manifest.vocab_size,
            hidden_size=manifest.hidden_size,
            num_heads=manifest.num_heads,
            intermediate_size=manifest.intermediate_size,
            fractional_bits=manifest.fractional_bits,
            prompt_tokens=prompt_tokens,
            max_new_tokens=max_new_tokens,
            length_bound=length_bound,
        )

    @property
    def prompt_budget(self) -> int:
        """How many prompt tokens fit next to every generated token."""
        return self.sequence - self.max_new_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_version": D7_SESSION_PROTOCOL,
            "release_id": self.release_id,
            "model_version": self.model_version,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": int(self.share_epoch),
            "sequence": int(self.sequence),
            "layers": int(self.layers),
            "vocab_size": int(self.vocab_size),
            "hidden_size": int(self.hidden_size),
            "num_heads": int(self.num_heads),
            "intermediate_size": int(self.intermediate_size),
            "fractional_bits": int(self.fractional_bits),
            "prompt_tokens": int(self.prompt_tokens),
            "max_new_tokens": int(self.max_new_tokens),
            "length_bound": int(self.length_bound),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "D7SessionPlan":
        if not isinstance(value, Mapping):
            raise PlanError("the session plan must be a mapping")
        if value.get("plan_version") != D7_SESSION_PROTOCOL:
            raise PlanError("unknown session plan version")
        try:
            return cls(
                release_id=str(value["release_id"]),
                model_version=str(value["model_version"]),
                model_manifest_hash=str(value["model_manifest_hash"]),
                precision_plan_hash=str(value["precision_plan_hash"]),
                share_epoch=int(value["share_epoch"]),
                sequence=int(value["sequence"]),
                layers=int(value["layers"]),
                vocab_size=int(value["vocab_size"]),
                hidden_size=int(value["hidden_size"]),
                num_heads=int(value["num_heads"]),
                intermediate_size=int(value["intermediate_size"]),
                fractional_bits=int(value["fractional_bits"]),
                prompt_tokens=int(value["prompt_tokens"]),
                max_new_tokens=int(value["max_new_tokens"]),
                length_bound=int(value["length_bound"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"the session plan is malformed: {exc}") from exc

    def decode_row(self, decode_step: int) -> int:
        """The context row step ``decode_step`` predicts from.

        The prompt is left-aligned in the window, so step 1 reads row
        ``prompt_tokens - 1`` and every later step moves one column right. Both
        sides derive it from the plan rather than from the payload, so a client
        cannot ask a node for a row the session never agreed to run.
        """
        row = int(self.prompt_tokens) + int(decode_step) - 2
        if not 0 <= row < self.sequence:
            raise PlanError(f"decoding step {decode_step} leaves the context window")
        return row


def step_payload(*, decode_step: int, history_share: str) -> bytes:
    """The client's per-step payload: its share of the left-aligned history."""
    from contracts import canonical_bytes

    if decode_step < 1:
        raise PlanError("decode_step must be positive")
    return canonical_bytes(
        {
            "protocol": D7_STEP_PAYLOAD_PROTOCOL,
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
    if document.get("protocol") != D7_STEP_PAYLOAD_PROTOCOL:
        raise PlanError("unknown step payload version")
    if set(document) != {"protocol", "decode_step", "history"}:
        raise PlanError("the step payload has unexpected fields")
    if not isinstance(document["decode_step"], int) or document["decode_step"] < 1:
        raise PlanError("the step payload carries an invalid decode_step")
    if not isinstance(document["history"], str):
        raise PlanError("the step payload carries no history share")
    return document


def result_payload(*, decode_step: int, token_share: str, logits_share: str) -> bytes:
    """One node's per-step output: its share of the chosen index and the logits."""
    from contracts import canonical_bytes

    if decode_step < 1:
        raise PlanError("decode_step must be positive")
    return canonical_bytes(
        {
            "protocol": D7_RESULT_PAYLOAD_PROTOCOL,
            "decode_step": int(decode_step),
            "token": token_share,
            "logits": logits_share,
        }
    )


def parse_result_payload(payload: bytes) -> dict[str, Any]:
    """Parse and validate one result payload, or refuse it."""
    import json

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError("the result payload is not canonical JSON") from exc
    if not isinstance(document, dict):
        raise PlanError("the result payload must be an object")
    if document.get("protocol") != D7_RESULT_PAYLOAD_PROTOCOL:
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
    "D7_NODE_CONFIG_VERSION",
    "D7_RESULT_PAYLOAD_PROTOCOL",
    "D7_SESSION_PROTOCOL",
    "D7_STEP_PAYLOAD_PROTOCOL",
    "PRECISION_PLAN",
    "D7ModelManifest",
    "D7SessionPlan",
    "PlanError",
    "parse_result_payload",
    "parse_step_payload",
    "precision_plan_hash",
    "result_payload",
    "step_payload",
]

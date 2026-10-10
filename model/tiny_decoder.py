"""Deterministic Tiny Decoder used to isolate numerical and cache issues."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Optional, Sequence

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class TinyDecoderConfig:
    vocab_size: int = 256
    hidden_size: int = 32
    num_layers: int = 2
    num_heads: int = 4
    intermediate_size: int = 64
    max_seq_len: int = 32
    layernorm_eps: float = 1e-5

    def __post_init__(self) -> None:
        if self.hidden_size % self.num_heads != 0:
            raise ValueError("hidden_size must be divisible by num_heads")
        for field_name in (
            "vocab_size",
            "hidden_size",
            "num_layers",
            "num_heads",
            "intermediate_size",
            "max_seq_len",
        ):
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} must be positive")


@dataclass
class TinyDecoderOutput:
    logits: Tensor
    past_key_values: Optional[tuple[tuple[Tensor, Tensor], ...]] = None


def _fill_portable_normal(
    tensor: Tensor, *, generator: torch.Generator, std: float
) -> None:
    """Fill ``tensor`` with a standard-normal sample that is bit-identical on
    every platform.

    ``torch.nn.init.normal_`` routes through the platform C library's
    ``log``/``cos``, so Windows (MSVC) and Linux (glibc) disagree in the
    low-order bits of the sampled floats.  ``parameter_hash`` is written into
    frozen fixtures, model packages, and release manifests, so those bits must
    not depend on the host.  Summing twelve uniforms (Irwin-Hall) keeps the
    variance at 1 while using only IEEE-754 additions, which are identical on
    every conforming platform.
    """
    with torch.no_grad():
        accumulator = torch.zeros_like(tensor)
        for _ in range(12):
            accumulator = accumulator + torch.rand(
                tensor.shape,
                generator=generator,
                dtype=tensor.dtype,
                device=tensor.device,
            )
        tensor.copy_((accumulator - 6.0) * std)


class _DecoderBlock(nn.Module):
    def __init__(self, config: TinyDecoderConfig) -> None:
        super().__init__()
        hidden_size = config.hidden_size
        self.num_heads = config.num_heads
        self.head_size = hidden_size // config.num_heads
        self.ln_1 = nn.LayerNorm(hidden_size, eps=config.layernorm_eps)
        self.qkv = nn.Linear(hidden_size, hidden_size * 3, bias=True)
        self.attention_out = nn.Linear(hidden_size, hidden_size, bias=True)
        self.ln_2 = nn.LayerNorm(hidden_size, eps=config.layernorm_eps)
        self.ffn_in = nn.Linear(hidden_size, config.intermediate_size, bias=True)
        self.activation = nn.GELU(approximate="none")
        self.ffn_out = nn.Linear(config.intermediate_size, hidden_size, bias=True)

    def forward(
        self,
        hidden_states: Tensor,
        past_key_value: Optional[tuple[Tensor, Tensor]],
    ) -> tuple[Tensor, tuple[Tensor, Tensor]]:
        batch_size, query_length, hidden_size = hidden_states.shape
        normalized = self.ln_1(hidden_states)
        qkv = self.qkv(normalized)
        query, key, value = qkv.chunk(3, dim=-1)

        query = query.view(
            batch_size, query_length, self.num_heads, self.head_size
        ).transpose(1, 2)
        key = key.view(
            batch_size, query_length, self.num_heads, self.head_size
        ).transpose(1, 2)
        value = value.view(
            batch_size, query_length, self.num_heads, self.head_size
        ).transpose(1, 2)

        past_length = 0
        if past_key_value is not None:
            past_key, past_value = past_key_value
            past_length = past_key.shape[-2]
            key = torch.cat((past_key, key), dim=-2)
            value = torch.cat((past_value, value), dim=-2)

        scores = query @ key.transpose(-2, -1)
        scores = scores / math.sqrt(self.head_size)

        key_positions = torch.arange(
            key.shape[-2], device=hidden_states.device
        )
        query_positions = torch.arange(
            past_length, past_length + query_length, device=hidden_states.device
        )
        causal_mask = key_positions.unsqueeze(0) <= query_positions.unsqueeze(1)
        scores = scores.masked_fill(~causal_mask, torch.finfo(scores.dtype).min)

        attention = torch.softmax(scores, dim=-1)
        attended = (attention @ value).transpose(1, 2).reshape(
            batch_size, query_length, hidden_size
        )
        hidden_states = hidden_states + self.attention_out(attended)

        normalized = self.ln_2(hidden_states)
        hidden_states = hidden_states + self.ffn_out(
            self.activation(self.ffn_in(normalized))
        )
        return hidden_states, (key, value)


class TinyDecoder(nn.Module):
    """A deterministic GPT-style decoder for D0/D5 interface tests."""

    def __init__(self, config: TinyDecoderConfig, *, seed: int = 0) -> None:
        super().__init__()
        self.config = config
        self.token_embedding = nn.Embedding(config.vocab_size, config.hidden_size)
        self.position_embedding = nn.Embedding(
            config.max_seq_len, config.hidden_size
        )
        self.blocks = nn.ModuleList(
            [_DecoderBlock(config) for _ in range(config.num_layers)]
        )
        self.final_norm = nn.LayerNorm(
            config.hidden_size, eps=config.layernorm_eps
        )
        self.lm_head = nn.Linear(config.hidden_size, config.vocab_size, bias=False)
        self._initialize_parameters(seed)

    def _initialize_parameters(self, seed: int) -> None:
        generator = torch.Generator(device="cpu")
        generator.manual_seed(seed)
        for name, parameter in self.named_parameters():
            if parameter.dim() >= 2:
                _fill_portable_normal(parameter, generator=generator, std=0.02)
            elif name.endswith("bias"):
                nn.init.zeros_(parameter)
            else:
                nn.init.ones_(parameter)

    def forward(
        self,
        input_ids: Tensor,
        past_key_values: Optional[tuple[tuple[Tensor, Tensor], ...]] = None,
        *,
        use_cache: bool = False,
    ) -> TinyDecoderOutput:
        if input_ids.ndim != 2:
            raise ValueError("input_ids must have shape [batch, sequence]")
        if input_ids.dtype not in (torch.int32, torch.int64):
            raise ValueError("input_ids must use an integer dtype")
        if past_key_values is not None and len(past_key_values) != len(self.blocks):
            raise ValueError("past_key_values must contain one entry per block")

        batch_size, query_length = input_ids.shape
        if query_length == 0:
            raise ValueError("input_ids must contain at least one token")
        past_length = 0 if past_key_values is None else past_key_values[0][0].shape[-2]
        total_length = past_length + query_length
        if total_length > self.config.max_seq_len:
            raise ValueError("sequence exceeds configured context window")
        if input_ids.min().item() < 0 or input_ids.max().item() >= self.config.vocab_size:
            raise ValueError("input token id is outside the vocabulary")

        positions = torch.arange(
            past_length, total_length, device=input_ids.device, dtype=torch.long
        )
        hidden_states = self.token_embedding(input_ids) + self.position_embedding(
            positions
        ).unsqueeze(0)

        present_key_values: list[tuple[Tensor, Tensor]] = []
        for index, block in enumerate(self.blocks):
            past = None if past_key_values is None else past_key_values[index]
            hidden_states, present = block(hidden_states, past)
            present_key_values.append(present)

        logits = self.lm_head(self.final_norm(hidden_states))
        return TinyDecoderOutput(
            logits=logits,
            past_key_values=tuple(present_key_values) if use_cache else None,
        )

    @torch.inference_mode()
    def greedy_generate(
        self,
        input_ids: Tensor,
        max_new_tokens: int,
        *,
        context_window: Optional[int] = None,
    ) -> Tensor:
        """Greedy decode with the same fixed context window as the TEE runtime."""
        if max_new_tokens < 0:
            raise ValueError("max_new_tokens must be non-negative")
        window = context_window or self.config.max_seq_len
        if window > self.config.max_seq_len:
            raise ValueError("context_window exceeds max_seq_len")
        if input_ids.shape[1] > window:
            raise ValueError("prompt exceeds context_window")

        generated = input_ids
        for _ in range(max_new_tokens):
            model_input = generated[:, -window:]
            output = self(model_input)
            next_token = output.logits[:, -1, :].argmax(dim=-1, keepdim=True)
            generated = torch.cat((generated, next_token), dim=1)
        return generated

    def parameter_hash(self) -> str:
        """Hash parameters in stable name order for fixtures and manifests."""
        digest = hashlib.sha256()
        for name, parameter in sorted(self.state_dict().items()):
            tensor = parameter.detach().cpu().contiguous()
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(tuple(tensor.shape)).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(tensor.dtype).encode("ascii"))
            digest.update(b"\0")
            digest.update(tensor.numpy().tobytes())
        return digest.hexdigest()

    def logits_for_ids(
        self, input_ids: Sequence[int], *, window: Optional[int] = None
    ) -> Tensor:
        """Return logits for a one-dimensional prompt, optionally fixed-windowed."""
        ids = torch.tensor([list(input_ids)], dtype=torch.long)
        if window is not None:
            ids = ids[:, -window:]
        return self(ids).logits

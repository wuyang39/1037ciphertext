"""Local-only fidelity checks: what the slice costs against the released model.

Two questions have to be answered before three enclaves are asked to run
anything, and both are cheap to answer on the operator's machine:

1. does the *float reference of the program* reproduce the released GPT-2's own
   logits on the candidate positions? If it does not, the MHLO program encodes
   something other than GPT-2 and no enclave run can fix that;
2. is the released model's own next token inside the candidate set? A restricted
   head can only return the true token when it is.

Answering both needs the released implementation, so this module is deliberately
outside the enclave path: it imports a framework lazily and is never imported by
a node. What it produces is a record of the boundary, not a claim that the
boundary is invisible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from model.gpt2 import Gpt2Config
from mpc.spu_backend.d7_program import D7Config


class D7FidelityError(ValueError):
    """The released model could not be loaded or compared."""


_MODEL_CACHE: dict[str, Any] = {}


def released_model(source_directory: Path | str) -> Any:
    """Load the released model once per process.

    A step-by-step comparison asks the same question several times, and
    reloading 548 MB of weights between steps would dominate the run.
    """
    key = str(Path(source_directory).resolve())
    if key in _MODEL_CACHE:
        return _MODEL_CACHE[key]
    try:
        from transformers import GPT2LMHeadModel
    except ImportError as exc:  # pragma: no cover - only on a bare machine
        raise D7FidelityError("the fidelity check needs torch and transformers") from exc
    try:
        model = GPT2LMHeadModel.from_pretrained(
            key,
            local_files_only=True,
            attn_implementation="eager",
        )
    except Exception as exc:  # noqa: BLE001 - reported with the loader's reason
        raise D7FidelityError(f"the frozen model did not load: {exc}") from exc
    model.eval()
    _MODEL_CACHE[key] = model
    return model


def torch_logits(
    source_directory: Path | str,
    token_ids: Sequence[int],
) -> np.ndarray:
    """The released GPT-2's logits for one context, position by position."""
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - only on a bare machine
        raise D7FidelityError("the fidelity check needs torch and transformers") from exc
    model = released_model(source_directory)
    with torch.no_grad():
        tensor = torch.tensor([list(token_ids)], dtype=torch.long)
        logits = model(input_ids=tensor).logits[0]
    values = logits.to(torch.float64).numpy()
    if values.shape != (len(token_ids), model.config.vocab_size):
        raise D7FidelityError("the released model returned an unexpected logit shape")
    return values


def compare_to_reference(
    *,
    released_row: np.ndarray,
    reference_row: np.ndarray,
    candidate_tokens: Sequence[int],
) -> dict[str, Any]:
    """Compare the released next-token logits with the reference on the candidates.

    ``released_row`` is the released model's logit row over its full vocabulary
    and ``reference_row`` is the program reference's logit row over the
    candidate vocabulary, both for the same position.
    """
    last_released = np.asarray(released_row, dtype=np.float64)
    last_reference = np.asarray(reference_row, dtype=np.float64)
    if last_released.ndim != 1 or last_reference.ndim != 1:
        raise D7FidelityError("both logit rows must be one-dimensional")
    rows = np.asarray(list(candidate_tokens), dtype=np.int64)
    if int(rows.max()) >= last_released.shape[0]:
        raise D7FidelityError("a candidate token id leaves the released vocabulary")
    released_candidates = last_released[rows]
    reference_candidates = last_reference
    if reference_candidates.shape != released_candidates.shape:
        raise D7FidelityError("the reference and the candidate set disagree in width")
    delta = np.abs(released_candidates - reference_candidates)
    order = np.argsort(-released_candidates, kind="stable")
    true_index = int(np.argmax(last_released))
    return {
        "candidate_width": int(rows.size),
        "max_abs_error": float(delta.max()),
        "mean_abs_error": float(delta.mean()),
        "released_argmax_token": true_index,
        "released_argmax_inside_candidates": bool(np.isin(true_index, rows)),
        "candidate_argmax_token": int(rows[int(order[0])]),
        "released_top5_tokens": [
            int(value)
            for value in np.argsort(-last_released, kind="stable")[:5]
        ],
        "released_top5_inside_candidates": bool(
            all(
                np.isin(int(value), rows)
                for value in np.argsort(-last_released, kind="stable")[:5]
            )
        ),
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    Path(path).write_text(
        json.dumps(dict(report), ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


__all__ = [
    "D7Config",
    "D7FidelityError",
    "Gpt2Config",
    "compare_to_reference",
    "released_model",
    "torch_logits",
    "write_report",
]

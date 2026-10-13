"""Produce the D7 local evidence bundle: freeze, fidelity, calibration.

Everything D7 can prove without an enclave is proved here, on the operator's
machine, against the released model:

* the frozen checkpoint verifies file by file, and the license that covers it
  is recorded with its own digest;
* the float reference of the *program* reproduces the released GPT-2's logits
  on the candidate positions;
* the released model's own next token lies inside the candidate set, so a
  restricted head returns the token the full head would have;
* a three-step greedy loop driven by the program's own arithmetic agrees token
  for token with the released model restricted to the same candidates.

The enclave run that follows only has to add the fixed-point protocol error to
this. If this bundle is wrong, no enclosure can fix it, so it is the first thing
to check before spending three instances on a decode.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from client.gpt2_bpe import load_bpe
from infra.d7_vectors import (
    build_run,
    decode_index,
    encode_prompt,
    load_run_weights,
    program_geometry,
    reference_step,
)
from infra.evidence import seal_directory, sha256_file, write_json
from model.calibration import calibrate_tensors
from model.gpt2 import load_config, require_gpt2_source, tokenizer_sha256


class D7LocalEvidenceError(RuntimeError):
    """The local evidence run could not be completed."""


def _released_step(
    released_logits: np.ndarray,
    candidate_tokens: Sequence[int],
) -> tuple[int, int, np.ndarray]:
    """The released model's token over the candidates, and its logit row."""
    row = np.asarray(released_logits, dtype=np.float64)[-1]
    rows = np.asarray(list(candidate_tokens), dtype=np.int64)
    restricted = row[rows]
    index = int(np.argmax(restricted))
    return int(rows[index]), index, restricted


def run(
    *,
    source_directory: Path,
    output_directory: Path,
    model_version: str,
    layers: int,
    sequence: int,
    candidate_size: int,
    prompt: str,
    steps: int,
    license_path: Path | None,
    error_bound: float,
) -> dict[str, Any]:
    from infra.d7_fidelity import compare_to_reference, torch_logits

    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    freeze = require_gpt2_source(source_directory)
    config = load_config(source_directory)
    encoder = load_bpe(source_directory)
    prompt_ids = encoder.encode(prompt)
    run_record = build_run(
        config,
        model_version=model_version,
        sequence=sequence,
        layers=layers,
        candidate_size=candidate_size,
        required_tokens=prompt_ids,
    )
    weights = load_run_weights(source_directory, config, run_record)
    geometry = program_geometry(run_record, config)
    history = encode_prompt(run_record, prompt_ids)

    plan, calibration = calibrate_tensors(
        weights,
        plan_id=f"{model_version}-dyadic-plan",
        error_bound=error_bound,
    )

    fidelity: list[dict[str, Any]] = []
    generated_reference: list[dict[str, Any]] = []
    released_ids = list(prompt_ids)
    program_ids = list(prompt_ids)
    agree = True
    for step in range(1, steps + 1):
        reference = reference_step(history, weights, geometry)
        released = torch_logits(source_directory, released_ids)
        report = compare_to_reference(
            released_row=released[-1],
            reference_row=reference["logits"][reference["decode_row"]],
            candidate_tokens=run_record.candidate_tokens,
        )
        report["step"] = step
        report["history_length"] = len(history)
        fidelity.append(report)
        released_token, _index, restricted = _released_step(
            released, run_record.candidate_tokens
        )
        program_token = decode_index(run_record, int(reference["token"][0]))
        step_agrees = released_token == program_token
        agree = agree and step_agrees
        generated_reference.append(
            {
                "step": step,
                "program_token": program_token,
                "program_text": encoder.decode([program_token]),
                "released_token_over_candidates": released_token,
                "released_text": encoder.decode([released_token]),
                "token_agreement": step_agrees,
                "logit_max_abs_error": float(
                    np.abs(restricted - reference["logits"][reference["decode_row"]]).max()
                ),
            }
        )
        if not step_agrees:
            break
        history.append(int(reference["token"][0]))
        released_ids.append(released_token)
        program_ids.append(program_token)

    memory = {
        "tensor_count": len(weights),
        "elements": int(sum(int(value.size) for value in weights.values())),
        "float64_bytes_per_party": int(
            sum(int(value.size) for value in weights.values()) * 8
        ),
        "quantized_bytes_per_party": int(
            sum(int(value.size) for value in weights.values()) * 8
        ),
        "candidate_width": run_record.vocab_size,
    }
    summary = {
        "run": run_record.to_dict(),
        "prompt": prompt,
        "prompt_tokens": list(prompt_ids),
        "model_version": model_version,
        "layers": layers,
        "geometry": {
            "sequence": geometry.sequence,
            "hidden_size": geometry.hidden_size,
            "num_heads": geometry.num_heads,
            "intermediate_size": geometry.intermediate_size,
            "fractional_bits": geometry.fractional_bits,
        },
        "metrics": memory,
        "steps_requested": steps,
        "steps_compared": len(generated_reference),
        "token_agreement": agree,
        "fidelity_verdict": "passed" if agree else "failed",
        "max_logit_error_vs_released": max(
            (entry["max_abs_error"] for entry in fidelity), default=None
        ),
        "released_argmax_inside_candidates": all(
            entry["released_argmax_inside_candidates"] for entry in fidelity
        ),
        "candidate_rule": (
            f"the {candidate_size} lowest GPT-2 token ids plus every id the "
            "prompt encodes to; ascending, digest bound in the model manifest"
        ),
        "generated_program_text": "".join(
            entry["program_text"] for entry in generated_reference
        ),
        "generated_released_text": "".join(
            entry["released_text"] for entry in generated_reference
        ),
    }

    freeze_document = {
        **freeze,
        "tokenizer_sha256": tokenizer_sha256(source_directory),
        "tokenizer_encoder": "client/gpt2_bpe.py (pure Python, checked against the "
        "released tokenizer over a pinned corpus)",
        "license_file": str(license_path) if license_path else None,
        "license_sha256": sha256_file(license_path) if license_path else None,
        "prompt": prompt,
        "prompt_tokens": list(prompt_ids),
    }
    write_json(output / "d7-freeze.json", freeze_document)
    write_json(output / "d7-run.json", run_record.to_dict())
    write_json(output / "d7-precision-plan.json", plan)
    write_json(
        output / "d7-calibration.json",
        {
            "error_bound": error_bound,
            "tensors": [record.to_dict() for record in calibration],
            "worst_max_abs_error": max(
                record.max_abs_error for record in calibration
            ),
            "narrowest_fractional_bits": min(
                record.fractional_bits for record in calibration
            ),
        },
    )
    write_json(output / "d7-fidelity.json", {"steps": fidelity})
    write_json(
        output / "d7-generation.json",
        {
            "prompt": prompt,
            "prompt_tokens": list(prompt_ids),
            "steps": generated_reference,
            "verdict": "passed" if agree else "failed",
        },
    )
    write_json(output / "d7-summary.json", summary)
    (output / "README.md").write_text(
        "\n".join(
            [
                "# D7 local model evidence",
                "",
                f"- frozen source: `{freeze['repository']}` @ `{freeze['revision']}`",
                f"- license: {freeze['license']}",
                f"- prompt: {prompt!r} -> {prompt_ids}",
                f"- layers: {layers}, sequence: {sequence}, candidates: "
                f"{run_record.vocab_size}",
                f"- fidelity verdict: {summary['fidelity_verdict']}",
                f"- program text: {summary['generated_program_text']!r}",
                f"- released text: {summary['generated_released_text']!r}",
                "",
                "This bundle is produced by `python -m infra.d7_local_evidence`. It",
                "records what the D7 program's own arithmetic reproduces of the",
                "released GPT-2 before any enclave is involved.",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
    index = seal_directory(output)
    summary["sealed"] = {
        "file_count": index["file_count"],
        "index": "evidence-index.json",
        "seal": "evidence.sha256",
    }
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 local evidence")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--model-version", default="gpt2-small-d7-v1")
    parser.add_argument("--layers", type=int, default=12)
    parser.add_argument("--sequence", type=int, default=8)
    parser.add_argument("--candidates", type=int, default=1024)
    parser.add_argument("--prompt", default="the cipher key is secret")
    parser.add_argument("--steps", type=int, default=3)
    parser.add_argument("--license", type=Path, default=None)
    parser.add_argument("--error-bound", type=float, default=2.0 ** -19)
    args = parser.parse_args(argv)
    try:
        summary = run(
            source_directory=args.source,
            output_directory=args.out,
            model_version=args.model_version,
            layers=args.layers,
            sequence=args.sequence,
            candidate_size=args.candidates,
            prompt=args.prompt,
            steps=args.steps,
            license_path=args.license,
            error_bound=args.error_bound,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"D7 local evidence failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


__all__ = ["D7LocalEvidenceError", "main", "run"]


if __name__ == "__main__":
    raise SystemExit(main())

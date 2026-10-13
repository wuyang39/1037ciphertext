from __future__ import annotations

import re

import numpy as np
import pytest

from infra.d5_vectors import (
    argmax_cases,
    block_cases,
    build_grid,
    case_inputs,
    digest_grid,
    gelu_cases,
    layernorm_cases,
    reference_argmax,
    reference_block,
    reference_gelu,
    reference_gelu_erf,
    reference_layernorm,
    reference_softmax,
    softmax_cases,
)
from mpc.spu_backend.d5_program import (
    D5Config,
    D5ProgramError,
    build_argmax_program,
    build_block_program,
    build_gelu_program,
    build_layernorm_program,
    build_softmax_program,
)


CONFIG = D5Config()


def test_each_program_declares_its_typed_interface() -> None:
    softmax = build_softmax_program(CONFIG.sequence, CONFIG.sequence)
    assert softmax.input_names == ("scores",)
    assert softmax.outputs[0].shape == (CONFIG.sequence, CONFIG.sequence)

    layernorm = build_layernorm_program(CONFIG.sequence, CONFIG.hidden_size)
    assert layernorm.input_names == ("h", "gamma", "beta")

    gelu = build_gelu_program(CONFIG.sequence, CONFIG.hidden_size)
    assert gelu.output_names == ("y",)

    argmax = build_argmax_program(CONFIG.vocab_size)
    assert argmax.outputs[0].shape == (1,)

    block = build_block_program(CONFIG)
    assert block.output_names == ("hidden", "logits", "token")
    assert len(block.inputs) == 21


def test_programs_carry_no_reveal_and_no_scientific_constants() -> None:
    programs = [
        build_softmax_program(4, 5),
        build_layernorm_program(4, 6),
        build_gelu_program(3, 4),
        build_argmax_program(8),
        build_block_program(CONFIG),
    ]
    for program in programs:
        assert "reveal" not in program.text
        # The front end rejects scientific notation in a dense literal.
        assert not re.search(r"dense<[^>]*[0-9]e[-+]?[0-9]", program.text)
        assert program.text.startswith("func.func @main(")
        assert program.text.count("func.func") == 1


def test_block_uses_only_supported_structural_ops() -> None:
    text = build_block_program(CONFIG).text
    for op in (
        "mhlo.dot_general",
        "mhlo.reshape",
        "mhlo.exponential",
        "mhlo.rsqrt",
        "mhlo.tanh",
        "mhlo.reduce",
    ):
        assert op in text
    # These need the generic assembly form or the parser rejects them.
    assert '"mhlo.transpose"' in text
    assert '"mhlo.broadcast_in_dim"' in text
    assert '"mhlo.slice"' in text
    assert '"mhlo.select"' in text


def test_shape_validation_rejects_nonsense() -> None:
    with pytest.raises(D5ProgramError):
        build_softmax_program(0, 4)
    with pytest.raises(D5ProgramError):
        build_argmax_program(0)
    with pytest.raises(D5ProgramError):
        D5Config(hidden_size=7, num_heads=2)


def test_references_match_the_functions_the_ir_asks_spu_for() -> None:
    scores = np.array([[1.0, 2.0, 3.0], [-1.0, 0.0, 1.0]])
    probabilities = reference_softmax(scores)
    assert np.allclose(probabilities.sum(axis=1), 1.0)
    assert np.all(probabilities >= 0.0)

    h = np.array([[0.5, -1.5, 2.0]])
    normalized = reference_layernorm(h, np.ones(3), np.zeros(3))
    assert abs(float(normalized.mean())) < 1e-12

    # The tanh GELU stays within a few 1e-3 of the exact erf form on [-6, 6].
    grid = np.linspace(-6.0, 6.0, 401)
    assert np.abs(reference_gelu(grid) - reference_gelu_erf(grid)).max() < 5e-3

    assert reference_argmax(np.array([0.0, 3.0, 3.0, 1.0])) == 1.0


def test_block_reference_is_deterministic_and_matches_its_own_gelu() -> None:
    cases = block_cases(CONFIG)
    assert len(cases) >= 9
    first = reference_block(case_inputs(cases[0]), CONFIG)
    again = reference_block(case_inputs(cases[0]), CONFIG)
    assert np.array_equal(first["hidden"], again["hidden"])
    assert first["logits"].shape == (CONFIG.sequence, CONFIG.vocab_size)
    assert 0.0 <= float(first["token"][0]) < CONFIG.vocab_size
    # A hidden state that is exactly zero still normalizes without a NaN.
    zero = {name: value * 0.0 for name, value in case_inputs(cases[0]).items()}
    zero["lm_bias"] = case_inputs(cases[0])["lm_bias"]
    assert np.isfinite(reference_block(zero, CONFIG)["hidden"]).all()


def test_grid_is_reproducible_and_digest_is_stable() -> None:
    grid = build_grid(CONFIG)
    assert set(grid) == {"softmax", "layernorm", "gelu", "argmax", "block"}
    digest = digest_grid(grid)
    assert digest == digest_grid(build_grid(CONFIG))
    assert len(digest) == 64
    assert len(softmax_cases(CONFIG)) == 8
    assert len(layernorm_cases(CONFIG)) == 7
    assert len(gelu_cases(CONFIG)) == 6
    assert len(argmax_cases(CONFIG)) == 8

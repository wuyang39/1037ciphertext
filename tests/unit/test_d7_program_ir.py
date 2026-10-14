"""The MHLO text a program hands the SPU compiler has to be well formed.

The compiler runs inside the enclave, several minutes into a sign-and-run
cycle, and its complaint about a malformed program is a C++ stack trace from
``spu::compiler::compile``. The one rule that can be checked here without the
runtime is the one that broke first: inside a function body, an SSA value may
only be used after the signature or an assignment introduced it.
"""

from __future__ import annotations

import re
from typing import Mapping

from mpc.spu_backend.d5_program import (
    D5Config,
    SpuProgram,
    build_argmax_program,
    build_layernorm_program,
    build_softmax_program,
)
from mpc.spu_backend.d6_program import build_step_program
from mpc.spu_backend.d7_program import D7Config, build_gpt2_program


VALUE = re.compile(r"%[A-Za-z_][A-Za-z0-9_.$-]*")
BLOCK_ARGUMENTS = re.compile(r"\^bb\d+\(([^)]*)\)")
# An SSA value name is a bare identifier. Dots, dashes and a second percent
# sign all survive Python string building and then die in the MLIR parser, so
# the rule is stated with nothing left loose.
STRICT_VALUE = re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*$")
ANY_VALUE = re.compile(r"%[^\s,:()\"]+")


def undefined_values(text: str) -> list[tuple[int, str]]:
    """Every ``%%name`` a body line uses before anything defines it."""
    defined: set[str] = set()
    problems: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        introduces: set[str] = set()
        stripped = line.lstrip()
        if stripped.startswith("func.func"):
            introduces |= set(VALUE.findall(line))
        elif stripped.startswith("%") and "=" in line:
            found = VALUE.findall(line)
            if found:
                introduces.add(found[0])
        block = BLOCK_ARGUMENTS.search(line)
        if block:
            introduces |= set(VALUE.findall(block.group(1)))
        body = line
        for name in introduces:
            if name in body:
                body = body.replace(name, "\0", 1)
        for name in VALUE.findall(body):
            if name not in defined:
                problems.append((number, name))
        defined |= introduces
    return problems


def _programs() -> Mapping[str, SpuProgram]:
    geometry = D7Config(
        sequence=8,
        layers=1,
        hidden_size=768,
        num_heads=12,
        intermediate_size=3072,
        vocab_size=1028,
    )
    tiny = D7Config(
        sequence=4,
        layers=2,
        hidden_size=8,
        num_heads=2,
        intermediate_size=16,
        vocab_size=32,
    )
    return {
        "d7-gpt2-real-row4": build_gpt2_program(
            geometry, decode_row=4, name="step-4"
        ),
        "d7-gpt2-tiny": build_gpt2_program(tiny, decode_row=1),
        "d6-step": build_step_program(
            D5Config(sequence=4, hidden_size=8, intermediate_size=16, vocab_size=32)
        ),
        "d5-softmax": build_softmax_program(4, 6),
        "d5-layernorm": build_layernorm_program(4, 6),
        "d5-argmax": build_argmax_program(32),
    }


def test_every_program_body_resolves_its_ssa_values() -> None:
    for label, program in _programs().items():
        problems = undefined_values(program.text)
        assert not problems, f"{label}: {problems[:4]}"


def test_every_ssa_name_is_a_bare_identifier() -> None:
    for label, program in _programs().items():
        odd = sorted(
            {token for token in ANY_VALUE.findall(program.text) if not STRICT_VALUE.match(token)}
        )
        assert not odd, f"{label}: {odd[:4]}"
        assert "%%" not in program.text, label


def test_the_manifest_names_are_not_the_ssa_names() -> None:
    """The GPT-2 tensors are named with dots, which the body cannot carry.

    The binding name stays ``layer_0.attn.q.weight`` so the dealer's share
    bundle keeps its manifest keys, while the parameter list has to spell the
    same tensor the way the body references it.
    """
    program = _programs()["d7-gpt2-real-row4"]
    assert "layer_0.attn.q.weight" in program.input_names
    signature = program.text.splitlines()[0]
    assert "%layer_0.attn.q.weight:" not in signature
    assert "%layer_0_attn_q_weight:" in signature

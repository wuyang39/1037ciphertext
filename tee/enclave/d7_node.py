"""D7 enclave node: the real GPT-2 decoding step on one SPU party.

The D6 node serves a session whose step program has one fixed shape, because a
fixed-shape block can read whatever context the client shares in front of it.
D7 cannot: the row the step predicts from is a constant baked into the
program's slice, so one program serves exactly one context length. This module
therefore builds one GPT-2 program per decoding step of the pinned plan and
hands the D6 node's state machine a table that maps a step to its program.

Everything else is the D6 node: the same handshake, the same JobTicket checks,
the same per-step spill and the same wipe. The weights are the exported model's
own tensors, sliced by the dealer, so the node holds one additive share of the
program the reference implementation describes and never a plaintext weight.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from contracts.d7_session import (
    D7_NODE_CONFIG_VERSION,
    D7ModelManifest,
    D7SessionPlan,
    parse_step_payload,
    result_payload,
)
from mpc.spu_backend.d7_program import D7Config, build_gpt2_program
from tee.enclave.d6_node import (
    D6NodeConfig,
    SessionPayloads,
    SessionPrograms,
    run_node,
)
from tee.enclave.node_common import NodeError, log


READY_MARKER = "A122-D7-NODE-READY"
DONE_MARKER = "A122-D7-NODE-DONE"
REFUSED_MARKER = "A122-D7-NODE-REFUSED"


class D7NodeConfig(D6NodeConfig):
    """A node configuration that speaks the D7 plan instead of the D6 one."""

    CONFIG_VERSION = D7_NODE_CONFIG_VERSION
    plan_from_dict = staticmethod(D7SessionPlan.from_dict)
    model_from_dict = staticmethod(D7ModelManifest.from_dict)


def program_geometry(plan: D7SessionPlan) -> D7Config:
    """The program geometry the plan pins, on the exported model's numbers."""
    return D7Config(
        sequence=plan.sequence,
        layers=plan.layers,
        hidden_size=plan.hidden_size,
        num_heads=plan.num_heads,
        intermediate_size=plan.intermediate_size,
        vocab_size=plan.vocab_size,
        fractional_bits=plan.fractional_bits,
    )


def decode_rows(plan: D7SessionPlan) -> tuple[int, ...]:
    """The context rows this plan will ever read, in step order."""
    return tuple(plan.decode_row(step) for step in range(1, plan.max_new_tokens + 1))


def build_d7_programs(config: D6NodeConfig) -> SessionPrograms:
    """One GPT-2 program per decoding step, plus the step-to-program table."""
    plan = config.plan
    geometry = program_geometry(plan)
    programs = tuple(
        build_gpt2_program(geometry, decode_row=row, name=f"step-{row}")
        for row in decode_rows(plan)
    )
    return SessionPrograms(
        programs=programs,
        program_for_step=lambda step: f"step-{plan.decode_row(int(step))}",
        # The program returns the last block's hidden state, so the session
        # keeps one buffered state per decoding step rather than one per block.
        kv_max_layers=1,
    )


def run_d7_node(config: D6NodeConfig, *, session_timeout: float = 1800.0) -> int:
    return run_node(
        config,
        programs=build_d7_programs(config),
        payloads=SessionPayloads(
            parse_step=parse_step_payload,
            result=result_payload,
        ),
        session_timeout=session_timeout,
        # The driver waits for the D7 markers, and the node has to say which
        # phase it is announcing rather than inherit the D6 node's lines.
        ready_marker=READY_MARKER,
        done_marker=DONE_MARKER,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 D7 GPT-2 enclave SPU node")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--session-timeout", type=float, default=1800.0)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"the node configuration could not be read: {exc}")
        return 2
    try:
        config = D7NodeConfig.from_document(document)
        return run_d7_node(config, session_timeout=args.session_timeout)
    except (NodeError, ValueError) as exc:
        log(f"{REFUSED_MARKER} {type(exc).__name__}: {exc}")
        return 3


__all__ = [
    "DONE_MARKER",
    "READY_MARKER",
    "REFUSED_MARKER",
    "D7NodeConfig",
    "build_d7_programs",
    "decode_rows",
    "main",
    "program_geometry",
    "run_d7_node",
]


if __name__ == "__main__":
    raise SystemExit(main())

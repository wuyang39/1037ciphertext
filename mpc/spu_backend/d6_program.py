"""The one program D6 adds to the D5 set: a private token-embedding lookup.

The D5 decoder block in :mod:`mpc.spu_backend.d5_program` consumes hidden
states, and D5 always handed it random hidden states. Autoregressive
generation needs the step's token history to *become* those hidden states
without either side learning the other's secret, so the client contributes a
one-hot history matrix as its own secret input while the embedding table stays
the model's secret weight::

    hidden = onehot(history) @ embedding

Both operands are secret, so this is one ordinary ``mhlo.dot_general``. No
plaintext index, token id or gather ever reaches a party, and the one-hot rows
themselves are only ever seen as additive shares.
"""

from __future__ import annotations

from mpc.spu_backend.d5_program import (
    D5Config,
    D5ProgramError,
    SpuProgram,
    TensorSpec,
    build_block_program,
    _type_of,
)


def build_step_program(config: D5Config) -> SpuProgram:
    """One decoding step: embedding lookup and the whole decoder block.

    The lookup is fused into the block instead of being a second program, so a
    step is a single collective run whose only secret inputs are the client's
    history one-hot matrix and the model's embedding table. Nothing in between
    leaves the MPC runtime, so no hidden state is ever an input or an output of
    the protocol boundary.
    """
    seq, d, vocab = config.sequence, config.hidden_size, config.vocab_size
    one_hot = _type_of((seq, vocab))
    table = _type_of((vocab, d))
    looked_up = _type_of((seq, d))
    if config.hidden_size != d:  # pragma: no cover - kept explicit for readers
        raise D5ProgramError("the embedding width must equal the hidden size")
    prelude = (
        f"  %embedded = \"mhlo.dot_general\"(%history, %embedding) "
        f"{{dot_dimension_numbers = #mhlo.dot<lhs_contracting_dimensions = [1], "
        f"rhs_contracting_dimensions = [0]>}} : ({one_hot}, {table}) -> {looked_up}",
    )
    program = build_block_program(
        config,
        extra_inputs=(
            TensorSpec("history", (seq, vocab)),
            TensorSpec("embedding", (vocab, d)),
        ),
        prelude=prelude,
        h_operand="%embedded",
    )
    return SpuProgram(
        name="step",
        text=program.text,
        inputs=program.inputs,
        outputs=program.outputs,
    )


__all__ = ["build_step_program"]

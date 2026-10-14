"""Drive a set of named MHLO programs over one already-validated SPU link.

``SpuNodeRuntime`` owns the D4 lifecycle: verify the identity, build the
runtime config, compile a program and tear the link down collectively. D5 runs
several differently-shaped programs over a single link, so this subclass
reuses that lifecycle and only replaces what differs: it compiles every
program up front and runs the one the driver names.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from mpc.spu_backend.d5_program import SpuProgram
from mpc.spu_backend.spu_link import (
    FXP_FRACTION_BITS,
    NodeIdentity,
    SpuLinkPolicy,
    SpuNodeRuntime,
    apply_runtime_options,
    make_io,
    runtime_config,
    verify_local_identity,
)


class SpuProgramRuntime(SpuNodeRuntime):
    """One enclave-side runtime slice hosting a D5 program set."""

    def __init__(
        self,
        *,
        libspu: Any,
        policy: SpuLinkPolicy,
        identity: NodeIdentity,
        programs: Sequence[SpuProgram],
        fraction_bits: int = FXP_FRACTION_BITS,
        runtime_options: Mapping[str, Any] | None = None,
        executor: Any | None = None,
        present_client_certificate: bool = True,
    ) -> None:
        if not programs:
            raise RuntimeError("the runtime needs at least one program")
        self.policy = policy
        self.identity = identity
        self.libspu = libspu
        self.programs = {program.name: program for program in programs}
        if len(self.programs) != len(programs):
            raise RuntimeError("program names must be unique")
        self.present_client_certificate = present_client_certificate
        self.identity_fingerprint = verify_local_identity(policy, identity)
        self.config = runtime_config(libspu, fraction_bits=fraction_bits)
        # D8's ablation arms differ only here: an arm that turns a runtime
        # approximation down says so in its configuration, and the value it
        # actually landed on is reported back so the run can be checked
        # against the arm it claims to be.
        self.runtime_options = apply_runtime_options(
            libspu, self.config, runtime_options
        )
        self.fraction_bits = int(fraction_bits)
        self.io = make_io(libspu, self.config)
        self.executables = {
            program.name: program.executable(libspu) for program in programs
        }
        self._executor = executor
        self._runtime: Any | None = None

    def run(self, *, program: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
        if self._runtime is None:
            raise RuntimeError("the SPU runtime has not been started")
        try:
            spec = self.programs[program]
        except KeyError as exc:
            raise RuntimeError(f"unknown program {program!r}") from exc
        executable = self.executables[program]
        missing = set(spec.input_names) - set(inputs)
        if missing:
            raise ValueError(
                f"program {program} is missing inputs: " + ", ".join(sorted(missing))
            )
        for name in spec.input_names:
            self._runtime.SetVar(name, inputs[name])
        self._runtime.Run(executable)
        return {name: self._runtime.GetVar(name) for name in spec.output_names}


__all__ = ["SpuProgramRuntime"]

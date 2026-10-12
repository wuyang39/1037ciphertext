"""The D4 operator program executed by the real SPU runtime.

The D4 acceptance runs six operators inside the three enclaves through
SecretFlow-SPU 0.9.5 (YACL + BRPC). The program is written as MHLO text so the
compiler front end can be driven from the enclave without importing JAX: the
LibOS mounts the ``libspu`` extension directly.

Two details of the SPU 0.9.5 front end are easy to get wrong and were confirmed
against the shipped ``libspu.so``:

* ``mhlo.dot_general`` must use the ``#mhlo.dot<...>`` alias form; the plain
  custom assembly (``contracting_dims = [1] x [0]``) is rejected by the parser.
* ``func.return`` needs an explicit type list when the function returns more
  than one value.
"""

from __future__ import annotations

from typing import Any


SPU_OPERATORS: tuple[str, ...] = (
    "add",
    "mul",
    "matmul",
    "truncate",
    "compare",
    "reciprocal",
)

FXP_FRACTION_BITS = 18
"""Fractional bits used by every D4 run; mirrored into the runtime config."""

DEFAULT_TOLERANCE = 1e-3
"""Absolute tolerance of the FM64 fixed-point reference comparison."""


class SpuProgramError(ValueError):
    """The requested operator program is not a supported D4 shape."""


def build_program(batch: int, rows: int, cols: int) -> str:
    """Return the batched MHLO program for the six D4 operators.

    The leading dimension batches independent vectors so one protocol round
    covers ``batch`` vectors instead of one; the acceptance grid uses it to run
    a thousand vectors with a handful of link round trips.
    """
    if batch < 1 or rows < 1 or cols < 1:
        raise SpuProgramError("batch and matrix dimensions must be positive")
    tensor = f"tensor<{batch}x{rows}x{cols}xf64>"
    mask_tensor = f"tensor<{batch}x{rows}x{cols}xi1>"
    dot_dims = (
        "#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        # The tensor is rank 3 (batch, rows, cols), so the contracting axes are
        # the lhs column axis (2) and the rhs row axis (1).
        "lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>"
    )
    return f"""
func.func @main(%x: {tensor}, %y: {tensor}) -> ({", ".join([tensor] * 6)}) {{
  %add = mhlo.add %x, %y : {tensor}
  %mul = mhlo.multiply %x, %y : {tensor}
  %matmul = "mhlo.dot_general"(%x, %y) {{dot_dimension_numbers = {dot_dims}}} : ({tensor}, {tensor}) -> {tensor}
  %truncate = mhlo.floor %x : {tensor}
  %cmp0 = mhlo.compare LT, %x, %y : ({tensor}, {tensor}) -> {mask_tensor}
  %compare = mhlo.convert %cmp0 : ({mask_tensor}) -> {tensor}
  %one = mhlo.constant dense<1.0> : {tensor}
  %reciprocal = mhlo.divide %one, %x : {tensor}
  return %add, %mul, %matmul, %truncate, %compare, %reciprocal : {", ".join([tensor] * 6)}
}}
"""


def _require_numpy() -> Any:
    try:
        import numpy  # type: ignore
    except ImportError as exc:  # pragma: no cover - numpy is a hard dependency
        raise SpuProgramError("numpy is required for reference outputs") from exc
    return numpy


def reference_outputs(x: Any, y: Any) -> dict[str, Any]:
    """Compute the plaintext reference for the same six operators."""
    numpy = _require_numpy()
    left = numpy.asarray(x, dtype=numpy.float64)
    right = numpy.asarray(y, dtype=numpy.float64)
    if left.shape != right.shape or left.ndim != 3:
        raise SpuProgramError(
            "reference inputs must be equally shaped (batch, rows, cols) tensors"
        )
    if left.shape[1] != left.shape[2]:
        raise SpuProgramError("the D4 program requires square matrices")
    return {
        "add": left + right,
        "mul": left * right,
        "matmul": left @ right,
        "truncate": numpy.floor(left),
        "compare": (left < right).astype(numpy.float64),
        "reciprocal": 1.0 / left,
    }


def compare_with_reference(
    actual: dict[str, Any],
    x: Any,
    y: Any,
    *,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Return the operator names that disagree with the reference."""
    numpy = _require_numpy()
    expected = reference_outputs(x, y)
    mismatches: list[str] = []
    for name in SPU_OPERATORS:
        if name not in actual:
            mismatches.append(name)
            continue
        got = numpy.asarray(actual[name], dtype=numpy.float64)
        want = expected[name]
        if got.shape != want.shape:
            mismatches.append(name)
            continue
        if name == "compare":
            if not numpy.array_equal(got.astype(bool), want.astype(bool)):
                mismatches.append(name)
            continue
        if not numpy.allclose(got, want, rtol=tolerance, atol=tolerance):
            mismatches.append(name)
    return mismatches


__all__ = [
    "DEFAULT_TOLERANCE",
    "FXP_FRACTION_BITS",
    "SPU_OPERATORS",
    "SpuProgramError",
    "build_program",
    "compare_with_reference",
    "reference_outputs",
]

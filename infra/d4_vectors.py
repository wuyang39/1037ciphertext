"""Deterministic and boundary vector grids for the D4 acceptance.

Every value is a dyadic rational with at most 18 fractional bits, which is the
fixed-point scale of the SPU runs. Keeping the grid dyadic removes float
rounding as an explanation for a mismatch while still exercising the reference
implementation.

The grid mixes two families:

* ``deterministic`` - reproducible pseudo-random matrices from a fixed seed.
* ``boundary`` - magnitudes on the fixed-point edges (the smallest step, powers
  of two, the largest magnitude the field carries comfortably) plus structural
  matrices (identity, signed permutations, rank-one) that stress matmul.

``x`` never contains an exact zero, because one of the six operators is a
reciprocal.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any, Iterable, Sequence


FXP_BITS = 18
FXP_STEP = 2.0 ** -FXP_BITS
DEFAULT_ROWS = 4
DEFAULT_COLS = 4
DEFAULT_COUNT = 1024
DEFAULT_SEED = 20261012
BOUNDARY_MAGNITUDES: tuple[float, ...] = (
    FXP_STEP,
    2 * FXP_STEP,
    2.0**-9,
    0.5,
    1.0,
    2.0,
    8.0,
    32.0,
    1024.0,
)
"""Magnitudes spanning the fixed-point grid from one step to 2^10."""


class VectorGridError(ValueError):
    """The vector grid is malformed or cannot be reproduced."""


def quantize(value: float) -> float:
    """Round a value onto the 18-bit fixed-point grid."""
    scaled = round(value * (1 << FXP_BITS))
    return scaled / float(1 << FXP_BITS)


def _sign(random_source: random.Random) -> float:
    return -1.0 if random_source.getrandbits(1) else 1.0


def _nonzero(value: float, random_source: random.Random) -> float:
    if value != 0.0:
        return value
    return FXP_STEP * _sign(random_source)


def _random_matrix(
    random_source: random.Random,
    rows: int,
    cols: int,
    *,
    maximum: float,
) -> list[list[float]]:
    return [
        [
            quantize(random_source.uniform(-maximum, maximum))
            for _ in range(cols)
        ]
        for _ in range(rows)
    ]


def _boundary_matrix(
    random_source: random.Random,
    rows: int,
    cols: int,
    *,
    nonzero: bool,
) -> list[list[float]]:
    matrix: list[list[float]] = []
    for _ in range(rows):
        row: list[float] = []
        for _ in range(cols):
            value = _sign(random_source) * random_source.choice(
                list(BOUNDARY_MAGNITUDES) + [0.0]
            )
            if nonzero:
                value = _nonzero(quantize(value), random_source)
            row.append(quantize(value))
        matrix.append(row)
    return matrix


def _structural_matrix(
    random_source: random.Random,
    rows: int,
    cols: int,
    *,
    nonzero: bool,
) -> list[list[float]]:
    kind = random_source.randrange(3)
    matrix = [[0.0] * cols for _ in range(rows)]
    if kind == 0:
        for index in range(min(rows, cols)):
            matrix[index][index] = 1.0
    elif kind == 1:
        columns = list(range(cols))
        random_source.shuffle(columns)
        for row in range(rows):
            matrix[row][columns[row % cols]] = _sign(random_source)
    else:
        row_vector = [
            quantize(random_source.uniform(-4.0, 4.0)) for _ in range(rows)
        ]
        column_vector = [
            quantize(random_source.uniform(-4.0, 4.0)) for _ in range(cols)
        ]
        matrix = [
            [quantize(row_vector[row] * column_vector[col]) for col in range(cols)]
            for row in range(rows)
        ]
    if nonzero:
        for row in range(rows):
            for col in range(cols):
                if matrix[row][col] == 0.0 and (row + col) % 2 == 0:
                    matrix[row][col] = FXP_STEP * _sign(random_source)
        if all(value == 0.0 for row in matrix for value in row):
            matrix[0][0] = FXP_STEP
    return matrix


def generate_vectors(
    *,
    count: int = DEFAULT_COUNT,
    rows: int = DEFAULT_ROWS,
    cols: int = DEFAULT_COLS,
    seed: int = DEFAULT_SEED,
    boundary_every: int = 4,
) -> list[dict[str, Any]]:
    """Return ``count`` reproducible ``(x, y)`` matrix pairs."""
    if count < 1:
        raise VectorGridError("the grid needs at least one vector")
    if rows < 1 or cols < 1:
        raise VectorGridError("matrix dimensions must be positive")
    if boundary_every < 1:
        raise VectorGridError("boundary_every must be at least one")
    random_source = random.Random(seed)
    vectors: list[dict[str, Any]] = []
    for index in range(count):
        if index % boundary_every == 0:
            kind = "boundary"
            x = _boundary_matrix(random_source, rows, cols, nonzero=True)
            y = _boundary_matrix(random_source, rows, cols, nonzero=False)
        elif index % boundary_every == 1:
            kind = "structural"
            x = _structural_matrix(random_source, rows, cols, nonzero=True)
            y = _structural_matrix(random_source, rows, cols, nonzero=False)
        else:
            kind = "deterministic"
            x = _random_matrix(random_source, rows, cols, maximum=4.0)
            y = _random_matrix(random_source, rows, cols, maximum=4.0)
        x = [[_nonzero(value, random_source) for value in row] for row in x]
        vectors.append(
            {
                "index": index,
                "kind": kind,
                "rows": rows,
                "cols": cols,
                "x": x,
                "y": y,
            }
        )
    return vectors


def batches(
    vectors: Sequence[dict[str, Any]],
    batch_size: int,
) -> Iterable[list[dict[str, Any]]]:
    """Yield the grid in fixed-size batches, padding is not required."""
    if batch_size < 1:
        raise VectorGridError("batch size must be positive")
    for start in range(0, len(vectors), batch_size):
        yield list(vectors[start : start + batch_size])


def digest_vectors(vectors: Sequence[dict[str, Any]]) -> str:
    """Return the canonical SHA-256 digest of a vector grid."""
    payload = json.dumps(
        list(vectors),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_vectors(path: Path, vectors: Sequence[dict[str, Any]]) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            {
                "fraction_bits": FXP_BITS,
                "count": len(vectors),
                "digest": digest_vectors(vectors),
                "vectors": list(vectors),
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    path.write_text(payload, encoding="utf-8")
    return digest_vectors(vectors)


def load_vectors(path: Path) -> list[dict[str, Any]]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    vectors = document.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise VectorGridError("the vector file has no vectors")
    if document.get("digest") != digest_vectors(vectors):
        raise VectorGridError("the vector grid digest does not match its content")
    return vectors


__all__ = [
    "BOUNDARY_MAGNITUDES",
    "DEFAULT_COLS",
    "DEFAULT_COUNT",
    "DEFAULT_ROWS",
    "DEFAULT_SEED",
    "FXP_BITS",
    "FXP_STEP",
    "VectorGridError",
    "batches",
    "digest_vectors",
    "generate_vectors",
    "load_vectors",
    "quantize",
    "write_vectors",
]

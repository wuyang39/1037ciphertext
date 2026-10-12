from __future__ import annotations

import json

import pytest

from infra.d4_vectors import (
    FXP_STEP,
    VectorGridError,
    batches,
    digest_vectors,
    generate_vectors,
    load_vectors,
    quantize,
    write_vectors,
)


def test_vector_grid_is_reproducible_and_fixed_point() -> None:
    first = generate_vectors(count=64, rows=3, cols=3, seed=7)
    second = generate_vectors(count=64, rows=3, cols=3, seed=7)
    assert digest_vectors(first) == digest_vectors(second)
    assert [entry["kind"] for entry in first[:5]] == [
        "boundary",
        "structural",
        "deterministic",
        "deterministic",
        "boundary",
    ]
    for entry in first:
        assert entry["rows"] == 3 and entry["cols"] == 3
        for matrix in (entry["x"], entry["y"]):
            assert len(matrix) == 3
            for row in matrix:
                assert len(row) == 3
                for value in row:
                    assert value == pytest.approx(quantize(value))
        # x never holds an exact zero: the grid exercises a reciprocal.
        assert all(value != 0.0 for row in entry["x"] for value in row)


def test_vector_grid_seed_changes_the_grid() -> None:
    assert digest_vectors(generate_vectors(count=16, seed=1)) != digest_vectors(
        generate_vectors(count=16, seed=2)
    )


def test_quantize_snaps_to_the_fixed_point_step() -> None:
    assert quantize(0.1) == pytest.approx(round(0.1 / FXP_STEP) * FXP_STEP)
    assert quantize(FXP_STEP / 3) == 0.0
    assert quantize(-FXP_STEP) == -FXP_STEP


def test_vector_grid_round_trips_through_disk(tmp_path) -> None:
    vectors = generate_vectors(count=32, rows=2, cols=2, seed=11)
    path = tmp_path / "vectors.json"
    digest = write_vectors(path, vectors)
    assert digest == digest_vectors(vectors)
    assert load_vectors(path) == vectors
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["count"] == 32
    assert document["fraction_bits"] == 18


def test_vector_file_digest_mismatch_is_rejected(tmp_path) -> None:
    path = tmp_path / "vectors.json"
    write_vectors(path, generate_vectors(count=4, rows=2, cols=2, seed=3))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["vectors"][0]["x"][0][0] = 123.0
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(VectorGridError, match="digest"):
        load_vectors(path)


def test_batches_cover_every_vector_once() -> None:
    vectors = generate_vectors(count=100, rows=2, cols=2, seed=5)
    seen = [entry["index"] for batch in batches(vectors, 30) for entry in batch]
    assert seen == list(range(100))
    assert len(list(batches(vectors, 30))) == 4


def test_vector_grid_rejects_bad_parameters() -> None:
    with pytest.raises(VectorGridError):
        generate_vectors(count=0)
    with pytest.raises(VectorGridError):
        generate_vectors(count=4, rows=0)
    with pytest.raises(VectorGridError):
        list(batches(generate_vectors(count=4), 0))

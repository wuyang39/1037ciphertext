from __future__ import annotations

import random

import pytest

from mpc.material_ledger import MaterialLedger, MaterialLedgerError, MaterialRecord
from mpc.secure_ops.fixed_point_adapter import FixedPointAdapter
from mpc.secure_ops.rss import RSSContext, RSSProtocolError
from model.fixed_point import FixedPointFormat


def test_rss_add_mul_matmul_and_fixed_adapter_vectors() -> None:
    context = RSSContext(ring_bits=64, seed=20261009)
    rng = random.Random(20261009)
    for _ in range(1000):
        left = rng.randint(-2**20, 2**20)
        right = rng.randint(-2**20, 2**20)
        left_shared = context.share(left)
        right_shared = context.share(right)
        assert context.reconstruct_signed(context.add(left_shared, right_shared)) == (
            left + right
        )
        assert context.reconstruct_signed(context.mul(left_shared, right_shared)) == (
            left * right
        )

    left_matrix = [[1, -2, 3], [4, 5, -6]]
    right_matrix = [[7, 8], [-9, 10], [11, -12]]
    product = context.matmul(
        context.share(left_matrix),
        context.share(right_matrix),
    )
    assert context.reconstruct_signed(product) == [
        [7 + 18 + 33, 8 - 20 - 36],
        [28 - 45 - 66, 32 + 50 + 72],
    ]

    format = FixedPointFormat(fractional_bits=12, bits=32, signed=True)
    adapter = FixedPointAdapter(format, context)
    shared = adapter.share([[1.25, -2.5], [0.0, 3.5]])
    assert adapter.reconstruct(shared) == [
        [1.25, -2.5],
        [0.0, 3.5],
    ]


def test_rss_truncate_compare_and_reciprocal_are_explicit_simulations() -> None:
    context = RSSContext(ring_bits=64, seed=7)
    product = context.share(3 << 12)
    truncated = context.truncate(product, shift_bits=12)
    assert context.reconstruct_signed(truncated) == 3
    comparison = context.compare(context.share(5), context.share(5))
    assert context.reconstruct(comparison) == 1
    reciprocal = context.reciprocal(context.share(4), scale=1 << 12)
    assert context.reconstruct_signed(reciprocal) == (1 << 12) // 4
    assert any(trace.simulated_reveal for trace in context.traces)
    with pytest.raises(RSSProtocolError, match="reveal"):
        RSSContext(ring_bits=64, reveal_allowed=False).compare(
            context.share(1),
            context.share(2),
        )


def test_material_ledger_is_atomic_and_single_use() -> None:
    now = __import__("datetime").datetime(
        2026, 10, 9, tzinfo=__import__("datetime").timezone.utc
    )
    ledger = MaterialLedger(clock=lambda: now)
    ledger.register(
        MaterialRecord(
            material_id="triple-1",
            model_version="tiny-v1",
            share_epoch=7,
            op_type="rss_mul",
            count=1,
            expiry=now + __import__("datetime").timedelta(hours=1),
        )
    )
    claim = ledger.claim(
        "triple-1",
        model_version="tiny-v1",
        share_epoch=7,
        op_type="rss_mul",
    )
    record = ledger.consume(claim)
    assert record.count == 0
    with pytest.raises(MaterialLedgerError):
        ledger.consume(claim)
    with pytest.raises(MaterialLedgerError):
        ledger.claim(
            "triple-1",
            model_version="tiny-v1",
            share_epoch=7,
            op_type="rss_mul",
        )

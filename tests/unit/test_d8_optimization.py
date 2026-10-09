from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from benchmark.collector import (
    BenchmarkCollector,
    BenchmarkSample,
    summarize_samples,
    write_markdown_report,
)
from benchmark.network import LAN, WAN_40MS
from model.graph import convert_tiny_decoder_graph
from mpc.secure_ops.approximations import (
    ApproximationError,
    gelu_piecewise,
    rsqrt_goldschmidt,
    softmax_piecewise,
)
from mpc.stage_planner import StagePlanner


def test_stage_planner_produces_reproducible_before_after_diff() -> None:
    graph = convert_tiny_decoder_graph(
        num_layers=2,
        hidden_size=8,
        num_heads=2,
        intermediate_size=16,
    )
    scales = {
        node.node_id: 16
        for node in graph.nodes
        if node.op in {"rss_matmul", "rss_add", "layernorm"}
    }
    plan = StagePlanner(precision_scales=scales).plan(graph)
    assert plan.before_hash == graph.digest()
    assert plan.after_hash != plan.before_hash
    assert any(stage.fused for stage in plan.stages)
    assert plan.removed_nodes
    assert plan.digest() == StagePlanner(precision_scales=scales).plan(graph).digest()


def test_approximations_record_ranges_errors_and_iterations() -> None:
    probabilities = softmax_piecewise([1.0, 2.0, 3.0])
    assert sum(probabilities) == pytest.approx(1.0)
    assert sum(
        abs(actual - expected)
        for actual, expected in zip(probabilities, [0.09003057, 0.24472847, 0.66524096])
    ) < 1e-6
    assert gelu_piecewise(1.0) == pytest.approx(0.841191, abs=3e-3)
    estimate = rsqrt_goldschmidt(4.0, initial=0.4)
    assert estimate == pytest.approx(0.5, abs=2e-5)
    with pytest.raises(ApproximationError):
        softmax_piecewise([1e6])


def test_benchmark_collector_is_redacted_and_reproducible() -> None:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "trace.jsonl"
        collector = BenchmarkCollector(output)
        with collector.time_block(stage="attention", operation="rss_matmul", bytes=128):
            pass
        collector.record(
            BenchmarkSample(
                stage="attention",
                operation="softmax",
                elapsed_ms=2.0,
                bytes=64,
                material_count=1,
            )
        )
        lines = output.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert "prompt" not in lines[0]
        summary = summarize_samples(collector.samples)
        assert summary["count"] == 2
        assert summary["bytes"] == 192
        report = Path(directory) / "report.md"
        write_markdown_report(collector.samples, report)
        assert "Local Benchmark Summary" in report.read_text(encoding="utf-8")
    assert WAN_40MS.transfer_ms(1_000_000) > LAN.transfer_ms(1_000_000)

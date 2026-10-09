"""Collect only redacted latency, memory, network, and material counters."""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class BenchmarkSample:
    stage: str
    operation: str
    elapsed_ms: float
    bytes: int
    cpu_percent: float = 0.0
    ram_bytes: int = 0
    epc_bytes: int = 0
    material_count: int = 0
    token_consistent: bool = True
    error: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BenchmarkCollector:
    """Append-only JSONL evidence collector for reproducible reports."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._samples: list[BenchmarkSample] = []

    @property
    def samples(self) -> tuple[BenchmarkSample, ...]:
        return tuple(self._samples)

    def record(self, sample: BenchmarkSample) -> None:
        if sample.elapsed_ms < 0 or sample.bytes < 0:
            raise ValueError("benchmark values must be non-negative")
        self._samples.append(sample)
        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    sample.to_dict(),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )

    def time_block(
        self,
        *,
        stage: str,
        operation: str,
        bytes: int = 0,
        material_count: int = 0,
    ):
        started = time.perf_counter()
        collector = self

        class _Timer:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, exc_type, exc, traceback):
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                collector.record(
                    BenchmarkSample(
                        stage=stage,
                        operation=operation,
                        elapsed_ms=elapsed_ms,
                        bytes=bytes,
                        material_count=material_count,
                    )
                )
                return False

        return _Timer()


def summarize_samples(samples: Iterable[BenchmarkSample]) -> dict[str, Any]:
    values = list(samples)
    if not values:
        return {
            "count": 0,
            "elapsed_ms": {"p50": 0.0, "p95": 0.0, "mean": 0.0},
            "bytes": 0,
            "materials": 0,
            "token_consistency": 0.0,
            "max_error": 0.0,
        }
    latencies = sorted(sample.elapsed_ms for sample in values)
    p95_index = min(len(latencies) - 1, int(0.95 * (len(latencies) - 1)))
    return {
        "count": len(values),
        "elapsed_ms": {
            "p50": statistics.median(latencies),
            "p95": latencies[p95_index],
            "mean": statistics.fmean(latencies),
        },
        "bytes": sum(sample.bytes for sample in values),
        "materials": sum(sample.material_count for sample in values),
        "token_consistency": sum(
            1 for sample in values if sample.token_consistent
        )
        / len(values),
        "max_error": max(sample.error for sample in values),
    }


def write_markdown_report(
    samples: Iterable[BenchmarkSample],
    output_path: Path,
) -> None:
    summary = summarize_samples(samples)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# A1-22 Local Benchmark Summary",
        "",
        "> This report is generated from redacted local-simulator samples.",
        "",
        f"- Sample count: {summary['count']}",
        f"- Latency mean: {summary['elapsed_ms']['mean']:.3f} ms",
        f"- Latency p50: {summary['elapsed_ms']['p50']:.3f} ms",
        f"- Latency p95: {summary['elapsed_ms']['p95']:.3f} ms",
        f"- Network bytes: {summary['bytes']}",
        f"- Material count: {summary['materials']}",
        f"- Token consistency: {summary['token_consistency']:.3f}",
        f"- Max error: {summary['max_error']:.6f}",
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


__all__ = [
    "BenchmarkCollector",
    "BenchmarkSample",
    "summarize_samples",
    "write_markdown_report",
]

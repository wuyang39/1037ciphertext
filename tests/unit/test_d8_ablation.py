"""The D8 ablation surface: named runtime arms, printed from their traces.

The arms themselves only run on the three SGX instances. What is testable
here is everything that decides whether an arm is real: the option names the
runtime accepts, the refusal of a name it does not, the check that the nodes
opened with the settings the arm asked for, and a report that is a function of
the arm traces rather than a transcription of them.
"""

from __future__ import annotations

import json
from enum import IntEnum
from pathlib import Path

import pytest

from infra.d8_ablation import (
    DEFAULT_ARMS,
    arm_checks,
    build_summary,
    node_runtime,
    rebuild_summary,
    report_markdown,
)
from infra.d8_three_hosts import ThreeHostError
from mpc.spu_backend.spu_link import (
    SpuBackendError,
    resolve_runtime_options,
    runtime_config,
)


class _FakeRuntimeConfig:
    """A stand-in for libspu's RuntimeConfig: named enums and plain fields."""

    class ExpMode(IntEnum):
        EXP_DEFAULT = 0
        EXP_PADE = 1
        EXP_TAYLOR = 2
        EXP_PRIME = 3

    class LogMode(IntEnum):
        LOG_DEFAULT = 0
        LOG_PADE = 1
        LOG_NEWTON = 2
        LOG_MINMAX = 3

    class SigmoidMode(IntEnum):
        SIGMOID_DEFAULT = 0
        SIGMOID_MM1 = 1
        SIGMOID_SEG3 = 2
        SIGMOID_REAL = 3

    class SortMethod(IntEnum):
        SORT_DEFAULT = 0

    def __init__(self, **kwargs: object) -> None:
        self.fxp_exp_mode = 0
        self.fxp_exp_iters = 8
        self.fxp_div_goldschmidt_iters = 2
        self.enable_lower_accuracy_rsqrt = False
        self.__dict__.update(kwargs)


class _FakeLibSpu:
    class ProtocolKind(IntEnum):
        SEMI2K = 2

    class FieldType(IntEnum):
        FM64 = 2

    RuntimeConfig = _FakeRuntimeConfig


def test_the_shipping_configuration_is_untouched_without_an_arm() -> None:
    config = runtime_config(_FakeLibSpu, fraction_bits=18)
    assert config.fxp_exp_iters == 8
    assert config.fxp_div_goldschmidt_iters == 2
    assert config.enable_lower_accuracy_rsqrt is False


def test_an_arm_moves_named_switches_and_resolves_symbolic_enum_names() -> None:
    resolved = resolve_runtime_options(
        _FakeLibSpu,
        {
            "fxp_exp_iters": 2,
            "fxp_div_goldschmidt_iters": 1,
            "enable_lower_accuracy_rsqrt": True,
            "fxp_exp_mode": "EXP_PADE",
        },
    )
    assert resolved == {
        "enable_lower_accuracy_rsqrt": True,
        "fxp_div_goldschmidt_iters": 1,
        "fxp_exp_iters": 2,
        "fxp_exp_mode": 1,
    }
    config = runtime_config(_FakeLibSpu, fraction_bits=18, options=resolved)
    assert config.fxp_exp_iters == 2
    assert config.fxp_exp_mode == 1
    assert config.enable_lower_accuracy_rsqrt is True


def test_an_option_that_is_not_a_switch_is_refused_not_ignored() -> None:
    """A typo that silently did nothing would make the table a fiction."""
    with pytest.raises(SpuBackendError, match="unknown SPU runtime option"):
        resolve_runtime_options(_FakeLibSpu, {"fxp_exp_iter": 2})
    with pytest.raises(SpuBackendError, match="not one of"):
        resolve_runtime_options(_FakeLibSpu, {"fxp_exp_mode": "EXP_NOPE"})
    with pytest.raises(SpuBackendError, match="must not be negative"):
        resolve_runtime_options(_FakeLibSpu, {"fxp_exp_iters": -1})


READY = (
    'A122-D7-NODE-READY {"role": "P0", "runtime": '
    '{"fraction_bits": 12, "options": {"fxp_exp_iters": 2}}}'
)


def test_a_node_runtime_is_read_back_out_of_its_own_ready_line() -> None:
    assert node_runtime("noise\n" + READY + "\n") == {
        "fraction_bits": 12,
        "options": {"fxp_exp_iters": 2},
    }
    assert node_runtime("nothing here") == {}


def _arm_record(
    *,
    bits: int,
    options: dict[str, object],
    wall: float,
    error: float,
    tokens: list[int],
    agreement: str = "passed",
    node_bits: int | None = None,
    node_options: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "client_runtime": {"fractional_bits": bits, "options": dict(options)},
        "node_runtime": {
            role: {
                "fraction_bits": bits if node_bits is None else node_bits,
                "options": dict(options if node_options is None else node_options),
            }
            for role in ("P0", "P1", "P2")
        },
        "client_wall_seconds": wall,
        "worst_max_abs_error": error,
        "step_client_ms": [1.0, 2.0, 3.0],
        "step_node_ms": {"P0": [1.0, 2.0, 3.0]},
        "step_max_abs_error": [error, error, error],
        "mean_abs_error_worst": error / 10.0,
        "tokens": tokens,
        "generated_text": " secret secret secret",
        "token_agreement": agreement,
        "argmax_agreement": agreement,
        "hygiene": "clean",
        "staged_shares_scrubbed": "clean",
        "verdicts": {"passed": agreement == "passed"},
        "wire": {
            role: {
                "wire_bytes": 1_250_000_000,
                "retransmits": 3,
                "capture_gaps": 0,
                "verdict": "tls13_only",
            }
            for role in ("P0", "P1", "P2")
        },
    }


def test_an_arm_that_did_not_reach_the_nodes_is_caught() -> None:
    arm = {"name": "fxp-12", "fractional_bits": 12, "options": {}}
    landed = arm_checks(
        arm, _arm_record(bits=12, options={}, wall=1, error=1, tokens=[1])
    )
    assert landed["arm_landed"] is True
    stale = arm_checks(
        arm,
        _arm_record(bits=12, options={}, wall=1, error=1, tokens=[1], node_bits=18),
    )
    assert stale["arm_landed"] is False
    assert any("opened at 18 bits" in problem for problem in stale["problems"])


def test_an_approximation_arm_that_did_not_reach_the_client_is_caught() -> None:
    arm = {
        "name": "approx-low",
        "fractional_bits": None,
        "options": {"fxp_exp_iters": 2},
    }
    missing = arm_checks(
        arm,
        _arm_record(
            bits=18,
            options={},
            wall=1,
            error=1,
            tokens=[1],
            node_bits=18,
            node_options={"fxp_exp_iters": 2},
        ),
    )
    assert missing["arm_landed"] is False
    assert any("client did not carry" in problem for problem in missing["problems"])


def _four_arms() -> dict[str, dict[str, object]]:
    return {
        "baseline": _arm_record(bits=18, options={}, wall=16.0, error=0.065, tokens=[3200]),
        "baseline-repeat": _arm_record(
            bits=18, options={}, wall=16.4, error=0.066, tokens=[3200]
        ),
        "approx-low": _arm_record(
            bits=18,
            options={
                "fxp_exp_iters": 2,
                "fxp_div_goldschmidt_iters": 1,
                "enable_lower_accuracy_rsqrt": True,
            },
            wall=15.0,
            error=0.21,
            tokens=[3200],
        ),
        "fxp-12": _arm_record(
            bits=12, options={}, wall=16.2, error=1.4, tokens=[3200]
        ),
    }


def test_the_comparison_is_relative_to_the_control_arm() -> None:
    summary = build_summary(
        run_id="d8-abl-demo",
        commit="abc1234",
        arms=DEFAULT_ARMS,
        records=_four_arms(),
    )
    rows = {row["arm"]: row for row in summary["comparison"]}
    assert rows["baseline"]["slowdown_vs_control"] == 1.0
    assert rows["approx-low"]["slowdown_vs_control"] == 0.9375
    assert rows["fxp-12"]["error_ratio_vs_control"] == 21.5385
    assert rows["fxp-12"]["fractional_bits"] == 12
    assert rows["baseline-repeat"]["tokens"] == [3200]
    assert all(row["arm_landed"] for row in summary["comparison"])
    assert summary["gaps"], "the summary has to name what it did not measure"


def test_the_report_names_every_arm_and_its_gaps() -> None:
    summary = build_summary(
        run_id="d8-abl-demo",
        commit="abc1234",
        arms=DEFAULT_ARMS,
        records=_four_arms(),
    )
    markdown = report_markdown(summary)
    for arm in DEFAULT_ARMS:
        assert f"`{arm['name']}`" in markdown
    assert "EPC" in markdown
    assert "TODO" not in markdown and "TBD" not in markdown


def _arm_dir(root: Path, name: str, *, stamp: str) -> None:
    target = root / name
    target.mkdir(parents=True)
    document = {
        "run_id": f"d8-abl-demo-{name}",
        "commit": "abc1234",
        "timestamp_utc": stamp,
        "generated_tokens": [3200, 3200, 3200],
        "generated_text": " secret secret secret",
        "client_wall_seconds": 16.0,
        "steps": [{"step_wall_ms": 5000.0}],
        "reference_check": {"worst_max_abs_error": 0.065},
        "verdicts": {"passed": True},
        "hygiene": {"verdict": "clean"},
        "staging_scrub": {"verdict": "clean"},
    }
    (target / "d7-summary.json").write_text(json.dumps(document), encoding="utf-8")
    (target / "d7-client-result.json").write_text(
        json.dumps(
            {
                "runtime": {"fractional_bits": 18, "options": {}},
                "reference_check": {
                    "worst_max_abs_error": 0.065,
                    "token_agreement": "passed",
                    "argmax_agreement": "passed",
                    "steps": [{"max_abs_error": 0.065, "mean_abs_error": 0.0065}],
                },
            }
        ),
        encoding="utf-8",
    )
    for role in ("p0", "p1", "p2"):
        (target / f"d7-three-{role}-node-status.json").write_text(
            json.dumps({"steps": [{"elapsed_ms": 5000.0}]}), encoding="utf-8"
        )
        (target / f"d7-three-{role}-node.log").write_text(READY + "\n", encoding="utf-8")
    for role in ("P0", "P1", "P2"):
        (target / f"d7-three-{role}-tls-summary.txt").write_text(
            "\n".join(
                [
                    "packets on expected ports: 10",
                    "TLS 1.3 flows: 1",
                    "application-data records: 5",
                    "non-TLS payload bytes: 0",
                    "TCP retransmissions: 2 (300 bytes, deduplicated)",
                    "capture gaps: 0 (unreassembled bytes: 0)",
                    "verdict: tls13_only",
                    "a -> b packets=4 bytes=1000 records={} non_tls=0 retransmits=0",
                ]
            ),
            encoding="utf-8",
        )


TWO_ARMS = (
    {
        "name": "baseline",
        "fractional_bits": None,
        "options": {},
        "description": "control",
    },
    {
        "name": "fxp-12",
        "fractional_bits": 12,
        "options": {},
        "description": "narrow",
    },
)


def test_rebuild_reproduces_its_own_bytes(tmp_path: Path) -> None:
    _arm_dir(tmp_path, "baseline", stamp="2026-10-14T12:00:00Z")
    _arm_dir(tmp_path, "fxp-12", stamp="2026-10-14T12:31:00Z")
    names = ("d8-abl-demo-summary.json", "d8-ablation-report.md", "README.md")

    def rendered() -> dict[str, bytes]:
        return {name: (tmp_path / name).read_bytes() for name in names}

    rebuild_summary(tmp_path, run_id="d8-abl-demo", arms=TWO_ARMS)
    first = rendered()
    rebuild_summary(tmp_path, run_id="d8-abl-demo", arms=TWO_ARMS)
    assert first == rendered()
    summary = json.loads(first["d8-abl-demo-summary.json"])
    assert summary["timestamp_utc"] == "2026-10-14T12:31:00Z"
    rows = {row["arm"]: row for row in summary["comparison"]}
    # The stand-in client trace was left at width 18 while the arm asked for
    # 12, so the arm has to be reported as not having landed rather than as a
    # measurement.
    assert rows["fxp-12"]["arm_landed"] is False
    assert any(
        "the client ran at 18 bits" in p for p in rows["fxp-12"]["arm_problems"]
    )


def test_rebuild_refuses_a_commit_the_traces_do_not_show(tmp_path: Path) -> None:
    _arm_dir(tmp_path, "baseline", stamp="2026-10-14T12:00:00Z")
    arms = ({"name": "baseline", "fractional_bits": None, "options": {}},)
    with pytest.raises(ThreeHostError, match="the traces record commit"):
        rebuild_summary(tmp_path, run_id="d8-abl-demo", arms=arms, commit="deadbeef")

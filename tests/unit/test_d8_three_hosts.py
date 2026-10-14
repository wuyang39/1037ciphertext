from __future__ import annotations

import json

from infra.d8_three_hosts import (
    build_summary,
    report_markdown,
    summarise_capture,
    summarise_samples,
)


CAPTURE = "\n".join(
    [
        "# A1-22 D4 TLS capture summary",
        "capture: d8-P0.pcap",
        "expected ports: [47100, 47101, 47102, 47200, 47201, 47202, 47890]",
        "packets on expected ports: 134109",
        "TLS 1.3 flows: 11",
        "TLS 1.2-or-lower flows: 0",
        "handshake messages: 34",
        "application-data records: 228852",
        "non-TLS payload bytes: 0",
        "TCP retransmissions: 231 (94771 bytes, deduplicated)",
        "capture gaps: 0 (unreassembled bytes: 0)",
        "verdict: tls13_only",
        "",
        "# A1-22 D7 cross-host capture",
        "role: P0",
        "instance: iZuf6bjvfplpwleemaipwmZ",
        "private address: 172.27.172.201",
        "capture: /tmp/d8-P0.pcap (1265072028 bytes, sha256 f019ebf9)",
        "",
        "# A1-22 D4 TLS capture summary",
        "capture: d8-P0.pcap",
        "expected ports: [47100, 47101, 47102, 47200, 47201, 47202, 47890]",
        "packets on expected ports: 134109",
        "TLS 1.3 flows: 11",
        "TLS 1.2-or-lower flows: 0",
        "handshake messages: 34",
        "application-data records: 228852",
        "non-TLS payload bytes: 0",
        "TCP retransmissions: 231 (94771 bytes, deduplicated)",
        "capture gaps: 0 (unreassembled bytes: 0)",
        "verdict: tls13_only",
        "",
        "172.27.172.201:42384 -> 172.27.172.202:47101 packets=18165 "
        "bytes=312575843 records={} handshakes={} alerts=[] non_tls=0 "
        "retransmits=38 non_tls_prefix=",
        "172.27.172.202:47101 -> 172.27.172.201:42384 packets=16681 "
        "bytes=348698 records={} handshakes={} alerts=[] non_tls=0 "
        "retransmits=22 non_tls_prefix=",
    ]
)


def _sample(t: float, total: float, busy: float, rss: float, ticks: float) -> str:
    return json.dumps(
        {
            "t": t,
            "cpu_total": total,
            "cpu_busy": busy,
            "mem_available_kb": 7000000 - int(t) * 1000,
            "gramine_rss_kb": rss,
            "gramine_cpu_ticks": ticks,
        }
    )


def test_capture_summary_counts_wire_bytes_and_not_the_headline_totals() -> None:
    summary = summarise_capture(CAPTURE)
    assert summary["verdict"] == "tls13_only"
    assert summary["capture_gaps"] == 0
    assert summary["retransmits"] == 231
    assert summary["non_tls_payload_bytes"] == 0
    # 1265072028 appears as the capture size in the header and must not be
    # mistaken for traffic on the wire.
    assert summary["wire_bytes"] == 312575843 + 348698
    assert summary["wire_packets"] == 18165 + 16681


def test_samples_become_utilisation_the_report_can_recompute() -> None:
    text = "\n".join(
        [
            _sample(0.0, 1000, 200, 50000, 0),
            _sample(0.5, 1400, 380, 60000, 150),
            _sample(1.0, 1800, 560, 55000, 300),
            "not a sample",
        ]
    )
    summary = summarise_samples(text)
    assert summary["samples"] == 3
    assert summary["cpu_util_percent_mean"] == 45.0
    assert summary["cpu_util_percent_peak"] == 45.0
    assert summary["gramine_rss_kb_peak"] == 60000
    assert summary["gramine_cpu_seconds"] == 3.0
    assert summary["mem_available_kb_min"] == 6999000
    assert summary["window_seconds"] == 1.0


def test_an_empty_sampler_file_is_reported_as_no_samples() -> None:
    assert summarise_samples("") == {"samples": 0}


def _record(
    *,
    wall: float,
    wire: int,
    tokens: list[int],
    error: float,
    retransmits: int,
    gaps: int = 0,
    verdict: str = "tls13_only",
) -> dict[str, object]:
    return {
        "client_wall_seconds": wall,
        "tokens": tokens,
        "worst_max_abs_error": error,
        "step_client_ms": [1, 2, 3],
        "step_node_ms": {"P0": [1, 2, 3]},
        "link_seconds": {"P0": 4.6},
        "resources": {"P0": {"samples": 10}},
        "hygiene": "clean",
        "staged_shares_scrubbed": "clean",
        "wire": {
            "P0": {
                "wire_bytes": wire,
                "retransmits": retransmits,
                "capture_gaps": gaps,
                "verdict": verdict,
            }
        },
    }


def test_comparison_is_relative_to_lan_and_carries_the_profiles_forward() -> None:
    summary = build_summary(
        run_id="d8-demo",
        commit="a1f45db",
        profiles={
            "lan": _record(wall=16.0, wire=1000, tokens=[3200], error=0.065, retransmits=1),
            "wan-40ms": _record(
                wall=48.0, wire=1000, tokens=[3200], error=0.065, retransmits=40
            ),
        },
        platform={"P0": {"cpu_model": "Xeon", "cpu_count": "4"}},
    )
    rows = {row["profile"]: row for row in summary["comparison"]}
    assert rows["lan"]["slowdown_vs_lan"] == 1.0
    assert rows["wan-40ms"]["slowdown_vs_lan"] == 3.0
    assert rows["wan-40ms"]["wire_bytes_total"] == 1000
    assert rows["wan-40ms"]["captures_tls13_only"] is True
    assert rows["wan-40ms"]["tokens"] == [3200]
    # A profile that could not be shown to preserve the token does not get to
    # look like one that did.
    assert rows["wan-40ms"]["token_agreement_with_reference"] is True
    assert summary["gaps"], "the summary has to name what it did not measure"


def test_report_renders_the_numbers_and_refuses_to_leave_gaps_unstated() -> None:
    summary = build_summary(
        run_id="d8-demo",
        commit="a1f45db",
        profiles={
            "lan": _record(wall=16.0, wire=1000, tokens=[3200], error=0.065, retransmits=1),
            "wan-40ms": _record(
                wall=48.0, wire=1000, tokens=[3200], error=0.065, retransmits=40
            ),
        },
        platform={"P0": {"cpu_model": "Xeon", "cpu_count": "4"}},
    )
    markdown = report_markdown(summary)
    assert "| lan | 16.0 | 1.0 |" in markdown
    assert "| wan-40ms | 48.0 | 3.0 |" in markdown
    assert "EPC" in markdown
    assert "TODO" not in markdown and "TBD" not in markdown

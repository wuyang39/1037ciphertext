from __future__ import annotations

import pytest

from infra.d1_gramine_evidence import extract_quote


def _hello_output(*, report_data: bytes, quote: bytes) -> str:
    return "\n".join(
        [
            "A1_22_GRAMINE_HELLO_BEGIN",
            f"report_data_hex={report_data.hex()}",
            f"quote_len={len(quote)}",
            f"quote_hex={quote.hex()}",
            "A1_22_GRAMINE_HELLO_END",
            "",
        ]
    )


def test_extract_quote_recovers_both_hex_blobs() -> None:
    report_data = bytes(range(64))
    quote = bytes([0x03, 0x00, 0x02, 0x00]) + bytes(range(256))

    recovered_data, recovered_quote = extract_quote(
        _hello_output(report_data=report_data, quote=quote)
    )

    assert recovered_data == report_data
    assert recovered_quote == quote


def test_extract_quote_rejects_output_without_a_quote() -> None:
    with pytest.raises(ValueError, match="quote_hex"):
        extract_quote("A1_22_GRAMINE_HELLO_BEGIN\nA1_22_GRAMINE_HELLO_END\n")


def test_extract_quote_rejects_output_without_report_data() -> None:
    with pytest.raises(ValueError, match="report_data_hex"):
        extract_quote("quote_hex=0300\n")

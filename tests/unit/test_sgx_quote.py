from __future__ import annotations

import struct

import pytest

from infra.sgx_quote import (
    MIN_QUOTE_BYTES,
    QUOTE_HEADER_BYTES,
    REPORT_BODY_BYTES,
    SGX_ATTRIBUTES_DEBUG,
    parse_quote,
)


def _build_quote(
    *,
    version: int = 3,
    att_key_type: int = 2,
    attributes_flags: int = SGX_ATTRIBUTES_DEBUG | 0x04,
    mr_enclave: bytes = bytes(range(32)),
    mr_signer: bytes = bytes(range(32, 64)),
    report_data: bytes = bytes(range(64)),
    isv_svn: int = 7,
    signature_data_len: int = 16,
) -> bytes:
    header = struct.pack("<HHIHH", version, att_key_type, 0, 12, 17) + bytes(36)
    body = bytearray(REPORT_BODY_BYTES)
    struct.pack_into("<I", body, 16, 0)
    struct.pack_into("<QQ", body, 48, attributes_flags, 0)
    body[64:96] = mr_enclave
    body[128:160] = mr_signer
    struct.pack_into("<H", body, 256, 0)
    struct.pack_into("<H", body, 258, isv_svn)
    body[320:384] = report_data
    trailer = struct.pack("<I", signature_data_len) + bytes(signature_data_len)
    return header + bytes(body) + trailer


def test_parse_quote_reads_measurements_and_debug_flag() -> None:
    quote = _build_quote()
    claims = parse_quote(quote)
    assert claims.version == 3
    assert claims.att_key_type == 2
    assert claims.qe_svn == 12
    assert claims.pce_svn == 17
    assert claims.mr_enclave == bytes(range(32))
    assert claims.mr_signer == bytes(range(32, 64))
    assert claims.report_data == bytes(range(64))
    assert claims.isv_svn == 7
    assert claims.debug is True
    assert claims.quote_size == len(quote) == MIN_QUOTE_BYTES + 16
    evidence = claims.to_evidence()
    assert evidence["debug"] is True
    assert evidence["mrenclave"] == bytes(range(32)).hex()


def test_parse_quote_reports_non_debug_when_flag_clear() -> None:
    claims = parse_quote(_build_quote(attributes_flags=0x04))
    assert claims.debug is False


def test_parse_quote_rejects_short_and_wrong_version() -> None:
    with pytest.raises(ValueError):
        parse_quote(bytes(MIN_QUOTE_BYTES - 1))
    with pytest.raises(ValueError):
        parse_quote(_build_quote(version=2))
    with pytest.raises(ValueError):
        parse_quote(_build_quote(att_key_type=1))

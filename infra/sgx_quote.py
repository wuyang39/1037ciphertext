"""Pure-stdlib parser for SGX ECDSA (quote version 3) quotes.

Only structural parsing happens here. Cryptographic verification of the quote
signature chain and TCB is delegated to the deployment-provided DCAP verifier
(see ``kas/dcap.py`` and ``tee/attestation/dcap_verifier``).
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


QUOTE_HEADER_BYTES = 48
REPORT_BODY_BYTES = 384
SIGNATURE_DATA_LEN_BYTES = 4
MIN_QUOTE_BYTES = QUOTE_HEADER_BYTES + REPORT_BODY_BYTES + SIGNATURE_DATA_LEN_BYTES

# Offsets inside a report body, from ``sgx_report_body_t`` in sgx_report.h.
# Note that ``reserved1`` is only 12 bytes, so ``attributes`` starts at 48.
_REPORT_ATTRIBUTES = 48
_REPORT_MRENCLAVE = 64
_REPORT_MRSIGNER = 128
_REPORT_ISV_PROD_ID = 256
_REPORT_ISV_SVN = 258
_REPORT_REPORT_DATA = 320

SGX_ATTRIBUTES_DEBUG = 0x02

QUOTE_VERSION_ECDSA = 3
ATT_KEY_TYPE_ECDSA_P256 = 2


def _read_report_body(blob: bytes, offset: int) -> bytes:
    return blob[QUOTE_HEADER_BYTES + offset : QUOTE_HEADER_BYTES + offset + REPORT_BODY_BYTES]


@dataclass(frozen=True)
class QuoteClaims:
    """Measured claims carried by an SGX ECDSA quote."""

    version: int
    att_key_type: int
    qe_svn: int
    pce_svn: int
    cpu_svn: bytes
    misc_select: int
    attributes_flags: int
    attributes_xfrm: int
    mr_enclave: bytes
    mr_signer: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes
    signature_data_len: int

    @property
    def debug(self) -> bool:
        return bool(self.attributes_flags & SGX_ATTRIBUTES_DEBUG)

    @property
    def quote_size(self) -> int:
        return MIN_QUOTE_BYTES + self.signature_data_len

    def to_evidence(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "att_key_type": self.att_key_type,
            "qe_svn": self.qe_svn,
            "pce_svn": self.pce_svn,
            "cpu_svn": self.cpu_svn.hex(),
            "misc_select": self.misc_select,
            "attributes_flags": self.attributes_flags,
            "attributes_xfrm": self.attributes_xfrm,
            "mrenclave": self.mr_enclave.hex(),
            "mrsigner": self.mr_signer.hex(),
            "isv_prod_id": self.isv_prod_id,
            "isvsvn": self.isv_svn,
            "debug": self.debug,
            "report_data_hex": self.report_data.hex(),
            "quote_size": self.quote_size,
        }


def parse_quote(blob: bytes) -> QuoteClaims:
    """Extract the measured claims from an SGX ECDSA quote."""
    if len(blob) < MIN_QUOTE_BYTES:
        raise ValueError("quote is shorter than the fixed ECDSA quote layout")

    version, att_key_type, _att_key_data_0, qe_svn, pce_svn = struct.unpack_from(
        "<HHIHH", blob, 0
    )
    if version != QUOTE_VERSION_ECDSA:
        raise ValueError(f"unsupported quote version: {version}")
    if att_key_type != ATT_KEY_TYPE_ECDSA_P256:
        raise ValueError(f"unsupported attestation key type: {att_key_type}")

    body = blob[QUOTE_HEADER_BYTES : QUOTE_HEADER_BYTES + REPORT_BODY_BYTES]
    cpu_svn = body[0:16]
    (misc_select,) = struct.unpack_from("<I", body, 16)
    attributes_flags, attributes_xfrm = struct.unpack_from("<QQ", body, _REPORT_ATTRIBUTES)
    mr_enclave = body[_REPORT_MRENCLAVE : _REPORT_MRENCLAVE + 32]
    mr_signer = body[_REPORT_MRSIGNER : _REPORT_MRSIGNER + 32]
    (isv_prod_id,) = struct.unpack_from("<H", body, _REPORT_ISV_PROD_ID)
    (isv_svn,) = struct.unpack_from("<H", body, _REPORT_ISV_SVN)
    report_data = body[_REPORT_REPORT_DATA : _REPORT_REPORT_DATA + 64]

    (signature_data_len,) = struct.unpack_from(
        "<I", blob, QUOTE_HEADER_BYTES + REPORT_BODY_BYTES
    )
    return QuoteClaims(
        version=version,
        att_key_type=att_key_type,
        qe_svn=qe_svn,
        pce_svn=pce_svn,
        cpu_svn=cpu_svn,
        misc_select=misc_select,
        attributes_flags=attributes_flags,
        attributes_xfrm=attributes_xfrm,
        mr_enclave=mr_enclave,
        mr_signer=mr_signer,
        isv_prod_id=isv_prod_id,
        isv_svn=isv_svn,
        report_data=report_data,
        signature_data_len=signature_data_len,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse an SGX ECDSA quote.")
    parser.add_argument("quote", type=Path, help="path to a binary quote")
    args = parser.parse_args(argv)
    try:
        claims = parse_quote(args.quote.read_bytes())
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(claims.to_evidence(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["QuoteClaims", "parse_quote", "SGX_ATTRIBUTES_DEBUG", "main"]

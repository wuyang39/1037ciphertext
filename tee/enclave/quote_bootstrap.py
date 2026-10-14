"""Print one real DCAP quote from the enclave the node will run under.

The D4 release policy has to pin the MRENCLAVE and MRSIGNER of the enclave that
will attest. Those come from the platform, so the driver runs this module under
the *signed node manifest* and reads the claims out of the quote, rather than
deriving them from the signer's output on a different host.

This quote proves nothing on its own -- its REPORTDATA is a fixed constant and
no key is bound to it -- so it is never used as an attestation. It only tells
the driver what to register.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from infra.node_attestation import bootstrap_report_data
from infra.sgx_quote import parse_quote
from tee.enclave.node_common import log


REPORT_DATA_PATH = Path("/dev/attestation/user_report_data")
QUOTE_PATH = Path("/dev/attestation/quote")


def read_quote(
    *,
    report_data: bytes,
    report_data_path: Path = REPORT_DATA_PATH,
    quote_path: Path = QUOTE_PATH,
) -> bytes:
    with open(report_data_path, "wb") as handle:
        handle.write(report_data)
    quote = quote_path.read_bytes()
    if not quote:
        raise OSError("the platform returned an empty quote")
    return quote


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 bootstrap quote reader")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        quote = read_quote(report_data=bootstrap_report_data())
    except OSError as exc:
        log(f"A122-QUOTE-BOOTSTRAP-REFUSED {exc}")
        return 3
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(quote)
    claims = parse_quote(quote)
    log(
        "A122-QUOTE-BOOTSTRAP "
        + json.dumps(
            {
                "mrenclave": claims.mr_enclave.hex(),
                "mrsigner": claims.mr_signer.hex(),
                "isvsvn": claims.isv_svn,
                "debug": claims.debug,
                "quote_bytes": len(quote),
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


__all__ = ["main", "read_quote"]


if __name__ == "__main__":
    raise SystemExit(main())

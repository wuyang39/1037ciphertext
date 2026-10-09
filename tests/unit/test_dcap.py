from __future__ import annotations

from pathlib import Path

import pytest

from kas.dcap import DcapQuoteVerifier
from kas.errors import AttestationRejected


def test_dcap_verifier_fails_closed_when_binary_is_missing(tmp_path: Path) -> None:
    verifier = DcapQuoteVerifier(tmp_path / "missing-verifier")
    with pytest.raises(AttestationRejected, match="unavailable"):
        verifier.verify(b"quote")

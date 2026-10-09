"""External DCAP verifier adapter with no insecure fallback."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import AttestationRejected
from .policy import VerifiedQuote


@dataclass(frozen=True)
class DcapQuoteVerifier:
    """Invoke a deployment-provided wrapper around Intel DCAP verification."""

    executable: Path
    timeout_seconds: float = 30.0

    def verify(self, quote: bytes) -> VerifiedQuote:
        if not self.executable.is_file():
            raise AttestationRejected(
                f"DCAP verifier is unavailable: {self.executable}"
            )

        quote_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="a122-quote-", suffix=".bin", delete=False
            ) as handle:
                handle.write(quote)
                quote_path = Path(handle.name)
            completed = subprocess.run(
                [
                    str(self.executable),
                    "--quote",
                    str(quote_path),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AttestationRejected(f"DCAP verifier execution failed: {exc}") from exc
        finally:
            if quote_path is not None:
                quote_path.unlink(missing_ok=True)

        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise AttestationRejected(
                f"DCAP verification rejected the Quote: {detail or 'no detail'}"
            )
        try:
            document = json.loads(completed.stdout)
            report_data = base64.b64decode(
                document["report_data_b64"], validate=True
            )
            result = VerifiedQuote(
                mrenclave=str(document["mrenclave"]).lower(),
                mrsigner=str(document["mrsigner"]).lower(),
                isvsvn=int(document["isvsvn"]),
                debug=bool(document["debug"]),
                report_data=report_data,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AttestationRejected(
                "DCAP verifier returned an invalid JSON result"
            ) from exc
        if len(result.report_data) != 64:
            raise AttestationRejected("DCAP verifier returned invalid REPORTDATA")
        if len(result.mrenclave) != 64 or len(result.mrsigner) != 64:
            raise AttestationRejected("DCAP verifier returned invalid measurements")
        return result

"""Drive the real D1 SGX attestation closed loop against the production KAS.

This runs only on a machine with SGX hardware, the Intel DCAP stack and the
``tee/attestation`` tools built. It exercises the production wiring in
``kas/settings.py`` (including ``KAS_DCAP_VERIFY_BIN``) rather than a test
double, and records the accepted path plus the four D1 denial cases.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crypto.sm2 import SM2KeyPair
from infra.evidence import build_record, seal_directory, write_json
from infra.sgx_quote import parse_quote
from kas.binding import build_report_data, csr_public_key_der
from kas.errors import AttestationRejected, ChallengeNotFound, KASError, PolicyRejected
from kas.models import AttestRequest, ChallengeRequest
from kas.settings import KASSettings, build_service


RELEASE_ID = "a122-d1-quote-probe"
ROLE = "P0"
PROBE_BINARY = "quote_probe"
ZERO_REPORT_DATA = bytes(64)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _run_probe(
    probe_dir: Path,
    report_data: bytes,
    quote_path: Path,
    *,
    timeout: float = 120.0,
) -> tuple[int, str, str]:
    """Run the quote probe with an out-of-process (AESM) quote request."""
    binary = probe_dir / PROBE_BINARY
    if not binary.is_file():
        raise FileNotFoundError(f"quote probe is missing: {binary}")
    environment = dict(os.environ)
    environment["SGX_AESM_ADDR"] = "1"
    completed = subprocess.run(
        [
            str(binary),
            "--report-data",
            report_data.hex(),
            "--out",
            str(quote_path),
        ],
        cwd=str(probe_dir),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _generate_node_csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A1-22"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "a122-d1-node"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _generate_ca(secrets_dir: Path) -> tuple[Path, Path]:
    """Create a self-signed P-256 KAS CA and return (key path, cert path)."""
    secrets_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 D1 KAS CA")]
    )
    now = _now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = secrets_dir / "kas-ca-key.pem"
    cert_path = secrets_dir / "kas-ca-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _write_release_policy(path: Path, claims: Any, *, hours: int = 24) -> dict[str, Any]:
    manifest = {
        "release_id": RELEASE_ID,
        "mrenclave": claims.mr_enclave.hex(),
        "mrsigner": claims.mr_signer.hex(),
        "min_isvsvn": claims.isv_svn,
        "debug_allowed": False,
        "spu_build_hash": claims.mr_enclave.hex(),
        # D1 exercises attestation and key release without a model, so the
        # model binding for that release is the probe measurement itself.
        "model_version": "d1-attestation-probe",
        "model_manifest_hash": claims.mr_enclave.hex(),
        "precision_plan_hash": claims.mr_enclave.hex(),
        "expires_at": (_now() + dt.timedelta(hours=hours))
        .replace(microsecond=0)
        .isoformat(),
    }
    write_json(path, {"releases": [manifest]})
    return manifest


class _Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.output: Path = args.output
        self.secrets: Path = args.secrets
        self.output.mkdir(parents=True, exist_ok=True)
        self.secrets.mkdir(parents=True, exist_ok=True)
        self._steps: dict[str, Any] = {}

    def _record(
        self,
        name: str,
        outcome: str,
        command: str,
        *,
        details: dict[str, Any] | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        record = build_record(
            run_id=self.args.run_id,
            phase="D1",
            outcome=outcome,
            command=command,
            instance_id=self.args.instance_id,
            cloud_region=self.args.cloud_region,
            image_id=self.args.image_id,
            release_id=RELEASE_ID,
            stdout=stdout.encode("utf-8"),
            stderr=stderr.encode("utf-8"),
            details=details,
        )
        write_json(self.output / f"{name}.json", record)
        self._steps[name] = outcome

    def run(self) -> int:
        # 1. Bootstrap the release probe once to learn its measurements and
        #    register the release policy that the production KAS consumes.
        bootstrap_quote = self.secrets / "bootstrap-quote.bin"
        rc, out, err = _run_probe(
            self.args.release_probe, ZERO_REPORT_DATA, bootstrap_quote
        )
        if rc != 0:
            self._record(
                "bootstrap-quote",
                "failed",
                "quote_probe --report-data 0.. --out bootstrap-quote.bin",
                details={"returncode": rc},
                stdout=out,
                stderr=err,
            )
            return 1
        bootstrap_claims = parse_quote(bootstrap_quote.read_bytes())
        policy = _write_release_policy(self.output / "kas-policy.json", bootstrap_claims)

        # 2. Build the production KAS from environment settings only.
        ca_key, ca_cert = _generate_ca(self.secrets)
        ticket_key_path = self.secrets / "ticket-signing-key.txt"
        ticket_key_path.write_text(SM2KeyPair.generate().private_key + "\n", encoding="ascii")
        storage_master_path = self.secrets / "storage-key-master.txt"
        storage_master_path.write_text(os.urandom(32).hex() + "\n", encoding="ascii")

        settings = KASSettings.from_env(
            {
                "KAS_CA_KEY_PATH": str(ca_key),
                "KAS_CA_CERT_PATH": str(ca_cert),
                "KAS_RELEASE_POLICY_PATH": str(self.output / "kas-policy.json"),
                "KAS_DCAP_VERIFY_BIN": str(self.args.verifier),
                "KAS_TICKET_SIGNING_KEY_PATH": str(ticket_key_path),
                "KAS_STORAGE_KEY_MASTER_HEX": storage_master_path.read_text().strip(),
            }
        )
        service = build_service(settings)

        accepted = self._positive_flow(service)
        self._deny_debug_quote(service)
        self._deny_tampered_measurement(service)
        self._deny_replayed_challenge(service)
        self._deny_replaced_public_key(service)

        write_json(
            self.output / "d1-summary.json",
            {
                "run_id": self.args.run_id,
                "phase": "D1",
                "release_id": RELEASE_ID,
                "mrenclave": policy["mrenclave"],
                "mrsigner": policy["mrsigner"],
                "steps": dict(sorted(self._steps.items())),
                "accepted": accepted,
            },
        )
        # The private KAS material stays outside the sealed evidence directory.
        seal_directory(self.output)
        return 0 if accepted else 1

    def _positive_flow(self, service: Any) -> bool:
        challenge = service.issue_challenge(
            ChallengeRequest(role=ROLE, release_id=RELEASE_ID)
        )
        nonce = bytes.fromhex(challenge.nonce)
        csr_pem = _generate_node_csr()
        spki = csr_public_key_der(csr_pem)
        report_data = build_report_data(spki, ROLE, RELEASE_ID, nonce)

        quote_path = self.output / "quote.bin"
        rc, out, err = _run_probe(self.args.release_probe, report_data, quote_path)
        if rc != 0:
            self._record(
                "accepted-release",
                "failed",
                "quote_probe --report-data <kas-bound> --out quote.bin",
                details={"returncode": rc, "stage": "quote-generation"},
                stdout=out,
                stderr=err,
            )
            return False

        (self.output / "node-csr.pem").write_text(csr_pem, encoding="ascii")
        write_json(
            self.output / "quote-report.json",
            parse_quote(quote_path.read_bytes()).to_evidence(),
        )

        verify = subprocess.run(
            [str(self.args.verifier), "--quote", str(quote_path), "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        write_json(
            self.output / "dcap-verify.json",
            {
                "command": f"{self.args.verifier} --quote quote.bin --json",
                "returncode": verify.returncode,
                "document": _loads_or_none(verify.stdout),
                "stderr": verify.stderr.strip()[:2000],
            },
        )
        if verify.returncode != 0:
            self._record(
                "accepted-release",
                "failed",
                "KAS attest with a fresh real quote",
                details={"stage": "dcap-verify", "returncode": verify.returncode},
                stdout=verify.stdout,
                stderr=verify.stderr,
            )
            return False

        quote_b64 = base64.b64encode(quote_path.read_bytes()).decode("ascii")
        try:
            response = service.attest(
                AttestRequest(
                    challenge_id=challenge.challenge_id,
                    role=ROLE,
                    release_id=RELEASE_ID,
                    dcap_quote_b64=quote_b64,
                    csr_pem=csr_pem,
                )
            )
        except KASError as exc:
            self._record(
                "accepted-release",
                "failed",
                "KAS attest with a fresh real quote",
                details={"stage": "attest", "error": type(exc).__name__, "reason": str(exc)},
            )
            return False

        (self.output / "node-certificate.pem").write_text(
            response.node_certificate_pem, encoding="ascii"
        )
        write_json(
            self.output / "lease.json",
            {
                "lease_id": response.lease_id,
                "expires_at": response.expires_at.isoformat(),
                "role": ROLE,
                "release_id": RELEASE_ID,
                "challenge_id": challenge.challenge_id,
                "nonce_hex": challenge.nonce,
            },
        )
        self._record(
            "accepted-release",
            "accepted",
            "KAS issue_challenge -> quote_probe -> attest",
            details={
                "lease_id": response.lease_id,
                "node_certificate_pem_sha256": _sha256_text(
                    response.node_certificate_pem
                ),
                "dcap_verification_result": (
                    _loads_or_none(verify.stdout) or {}
                ).get("dcap_verification_result"),
            },
            stdout=verify.stdout,
        )
        return True

    def _attest_with_probe(
        self,
        service: Any,
        probe_dir: Path,
        quote_name: str,
    ) -> tuple[bytes, str]:
        challenge = service.issue_challenge(
            ChallengeRequest(role=ROLE, release_id=RELEASE_ID)
        )
        nonce = bytes.fromhex(challenge.nonce)
        csr_pem = _generate_node_csr()
        spki = csr_public_key_der(csr_pem)
        report_data = build_report_data(spki, ROLE, RELEASE_ID, nonce)
        quote_path = self.secrets / quote_name
        rc, out, err = _run_probe(probe_dir, report_data, quote_path)
        if rc != 0:
            raise RuntimeError(f"probe failed ({rc}): {err.strip() or out.strip()}")
        quote_bytes = quote_path.read_bytes()
        service.attest(
            AttestRequest(
                challenge_id=challenge.challenge_id,
                role=ROLE,
                release_id=RELEASE_ID,
                dcap_quote_b64=base64.b64encode(quote_bytes).decode("ascii"),
                csr_pem=csr_pem,
            )
        )
        return quote_bytes, csr_pem

    def _deny(
        self,
        name: str,
        command: str,
        *,
        expected: type[KASError],
        action: Any,
    ) -> None:
        try:
            action()
        except expected as exc:
            self._record(
                name,
                "rejected",
                command,
                details={
                    "rejection": type(exc).__name__,
                    "reason": str(exc),
                    "expected": expected.__name__,
                },
            )
            return
        except KASError as exc:  # rejected, but for an unexpected reason
            self._record(
                name,
                "rejected-unexpected",
                command,
                details={
                    "rejection": type(exc).__name__,
                    "reason": str(exc),
                    "expected": expected.__name__,
                },
            )
            return
        else:
            self._record(
                name,
                "not-rejected",
                command,
                details={"expected": expected.__name__},
            )

    def _deny_debug_quote(self, service: Any) -> None:
        if self.args.debug_probe is None:
            return
        self._deny(
            "deny-debug-quote",
            "KAS attest with an SGX_DEBUG=1 quote",
            expected=PolicyRejected,
            action=lambda: self._attest_with_probe(
                service, self.args.debug_probe, "deny-debug-quote.bin"
            ),
        )

    def _deny_tampered_measurement(self, service: Any) -> None:
        if self.args.tampered_probe is None:
            return
        self._deny(
            "deny-tampered-measurement",
            "KAS attest with a quote from a modified enclave image",
            expected=PolicyRejected,
            action=lambda: self._attest_with_probe(
                service, self.args.tampered_probe, "deny-tampered-measurement.bin"
            ),
        )

    def _deny_replayed_challenge(self, service: Any) -> None:
        challenge = service.issue_challenge(
            ChallengeRequest(role=ROLE, release_id=RELEASE_ID)
        )
        nonce = bytes.fromhex(challenge.nonce)
        csr_pem = _generate_node_csr()
        report_data = build_report_data(
            csr_public_key_der(csr_pem), ROLE, RELEASE_ID, nonce
        )
        quote_path = self.secrets / "deny-replayed-challenge.bin"
        rc, out, err = _run_probe(self.args.release_probe, report_data, quote_path)
        if rc != 0:
            raise RuntimeError(f"probe failed ({rc}): {err.strip() or out.strip()}")
        request = AttestRequest(
            challenge_id=challenge.challenge_id,
            role=ROLE,
            release_id=RELEASE_ID,
            dcap_quote_b64=base64.b64encode(quote_path.read_bytes()).decode("ascii"),
            csr_pem=csr_pem,
        )
        service.attest(request)

        def _replay() -> None:
            service.attest(request)

        self._deny(
            "deny-replayed-challenge",
            "KAS attest twice with the same challenge_id",
            expected=ChallengeNotFound,
            action=_replay,
        )

    def _deny_replaced_public_key(self, service: Any) -> None:
        challenge = service.issue_challenge(
            ChallengeRequest(role=ROLE, release_id=RELEASE_ID)
        )
        nonce = bytes.fromhex(challenge.nonce)
        bound_csr = _generate_node_csr()
        report_data = build_report_data(
            csr_public_key_der(bound_csr), ROLE, RELEASE_ID, nonce
        )
        quote_path = self.secrets / "deny-replaced-public-key.bin"
        rc, out, err = _run_probe(self.args.release_probe, report_data, quote_path)
        if rc != 0:
            raise RuntimeError(f"probe failed ({rc}): {err.strip() or out.strip()}")
        # Present a different node key than the one bound into REPORTDATA.
        replaced_csr = _generate_node_csr()
        request = AttestRequest(
            challenge_id=challenge.challenge_id,
            role=ROLE,
            release_id=RELEASE_ID,
            dcap_quote_b64=base64.b64encode(quote_path.read_bytes()).decode("ascii"),
            csr_pem=replaced_csr,
        )
        self._deny(
            "deny-replaced-public-key",
            "KAS attest with a CSR that REPORTDATA does not bind",
            expected=AttestationRejected,
            action=lambda: service.attest(request),
        )


def _loads_or_none(text: str) -> Any:
    import json

    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument("--release-probe", type=Path, required=True)
    parser.add_argument("--debug-probe", type=Path)
    parser.add_argument("--tampered-probe", type=Path)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance-id", default="unknown")
    parser.add_argument("--cloud-region", default="cn-shanghai")
    parser.add_argument("--image-id", default="unknown")
    args = parser.parse_args(argv)

    runner = _Runner(args)
    try:
        return runner.run()
    except (FileNotFoundError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "RELEASE_ID"]

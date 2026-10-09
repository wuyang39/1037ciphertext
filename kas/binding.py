"""REPORTDATA construction for temporary node key binding."""

from __future__ import annotations

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import serialization


REPORT_DATA_DOMAIN = b"A1-22:report-data:v1\0"
REPORT_DATA_BYTES = 64


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("binding field is too long")
    return len(value).to_bytes(4, "big") + value


def build_report_data(
    public_key_der: bytes,
    role: str,
    release_id: str,
    nonce: bytes,
) -> bytes:
    """Bind the temporary key, role, release, and fresh KAS nonce."""
    if len(nonce) != 32:
        raise ValueError("KAS nonce must be 32 bytes")
    transcript = b"".join(
        (
            REPORT_DATA_DOMAIN,
            _length_prefixed(public_key_der),
            _length_prefixed(role.encode("utf-8")),
            _length_prefixed(release_id.encode("utf-8")),
            _length_prefixed(nonce),
        )
    )
    return hashlib.sha256(transcript).digest() + b"\x00" * 32


def csr_public_key_der(csr_pem: str) -> bytes:
    """Extract the SubjectPublicKeyInfo bytes from a PEM CSR."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("csr_pem is not a valid PEM certificate request") from exc
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    return csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_report_data(
    actual: bytes,
    public_key_der: bytes,
    role: str,
    release_id: str,
    nonce: bytes,
) -> bool:
    """Constant-time comparison against the expected 64-byte REPORTDATA."""
    expected = build_report_data(public_key_der, role, release_id, nonce)
    return hmac.compare_digest(actual, expected)

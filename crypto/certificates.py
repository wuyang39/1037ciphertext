"""Canonical SM2 identity certificates and revocation checks for D2."""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

from contracts import canonical_bytes, validate_contract

from .sm2 import SM2Error, SM2KeyPair, validate_sm2_public_key, verify_sm2


CERTIFICATE_VERSION = "a122-sm2-cert-v1"
_MAX_CLOCK_SKEW = dt.timedelta(minutes=1)


class CertificateError(ValueError):
    """Base class for identity certificate failures."""


class CertificateExpired(CertificateError):
    """The certificate is outside its validity window."""


class CertificateRevoked(CertificateError):
    """The certificate serial is present in the active CRL."""


class CertificateForgery(CertificateError):
    """The certificate signature or binding is invalid."""


def _require_utc(value: dt.datetime, *, name: str) -> dt.datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return value.astimezone(dt.timezone.utc)


def _parse_timestamp(value: str, *, name: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return _require_utc(dt.datetime.fromisoformat(normalized), name=name)
    except ValueError as exc:
        raise CertificateError(f"{name} is not a valid timestamp") from exc


def _format_timestamp(value: dt.datetime) -> str:
    return _require_utc(value, name="timestamp").isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SM2Certificate:
    """Application-layer certificate signed directly by the KAS SM2 key."""

    serial_number: str
    role: str
    release_id: str
    public_key: str
    issued_at: str
    expires_at: str
    signature: str
    certificate_version: str = CERTIFICATE_VERSION

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "certificate_version": self.certificate_version,
            "serial_number": self.serial_number,
            "role": self.role,
            "release_id": self.release_id,
            "public_key": self.public_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.unsigned_dict()
        value["signature"] = self.signature
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SM2Certificate":
        validate_contract("sm2_certificate", value)
        _parse_timestamp(str(value["issued_at"]), name="issued_at")
        _parse_timestamp(str(value["expires_at"]), name="expires_at")
        return cls(
            certificate_version=str(value["certificate_version"]),
            serial_number=str(value["serial_number"]),
            role=str(value["role"]),
            release_id=str(value["release_id"]),
            public_key=str(value["public_key"]),
            issued_at=str(value["issued_at"]),
            expires_at=str(value["expires_at"]),
            signature=str(value["signature"]),
        )


class SM2CertificateAuthority:
    """Issue and verify short-lived role certificates with an active CRL."""

    def __init__(
        self,
        signing_key: SM2KeyPair,
        *,
        revoked_serial_numbers: set[str] | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._revoked = {
            serial.lower() for serial in (revoked_serial_numbers or set())
        }

    @property
    def public_key(self) -> str:
        return self._signing_key.public_key

    def revoke(self, serial_number: str) -> None:
        self._revoked.add(serial_number.lower())

    def issue(
        self,
        *,
        role: str,
        release_id: str,
        public_key: str,
        now: dt.datetime,
        ttl: dt.timedelta,
    ) -> SM2Certificate:
        if role not in {"C", "P0", "P1", "P2"}:
            raise CertificateError("invalid certificate role")
        if ttl <= dt.timedelta(0):
            raise CertificateError("certificate TTL must be positive")
        now = _require_utc(now, name="now")
        public_key = validate_sm2_public_key(public_key)
        unsigned = {
            "certificate_version": CERTIFICATE_VERSION,
            "serial_number": secrets.token_hex(16),
            "role": role,
            "release_id": release_id,
            "public_key": public_key,
            "issued_at": _format_timestamp(now),
            "expires_at": _format_timestamp(now + ttl),
        }
        signature = self._signing_key.sign(canonical_bytes(unsigned)).hex()
        certificate = SM2Certificate(
            serial_number=unsigned["serial_number"],
            role=unsigned["role"],
            release_id=unsigned["release_id"],
            public_key=unsigned["public_key"],
            issued_at=unsigned["issued_at"],
            expires_at=unsigned["expires_at"],
            signature=signature,
        )
        return SM2Certificate.from_dict(certificate.to_dict())

    def verify(
        self,
        certificate: SM2Certificate | Mapping[str, Any],
        *,
        now: dt.datetime,
        expected_role: str | None = None,
        expected_release_id: str | None = None,
        expected_public_key: str | None = None,
    ) -> SM2Certificate:
        parsed = SM2Certificate.from_dict(
            certificate.to_dict()
            if isinstance(certificate, SM2Certificate)
            else certificate
        )
        now = _require_utc(now, name="now")
        issued_at = _parse_timestamp(parsed.issued_at, name="issued_at")
        expires_at = _parse_timestamp(parsed.expires_at, name="expires_at")
        if expires_at <= issued_at:
            raise CertificateForgery("certificate validity window is inverted")
        if now + _MAX_CLOCK_SKEW < issued_at:
            raise CertificateExpired("certificate is not valid yet")
        if now >= expires_at:
            raise CertificateExpired("certificate has expired")
        if parsed.serial_number.lower() in self._revoked:
            raise CertificateRevoked("certificate serial has been revoked")
        if expected_role is not None and parsed.role != expected_role:
            raise CertificateForgery("certificate role binding mismatch")
        if (
            expected_release_id is not None
            and parsed.release_id != expected_release_id
        ):
            raise CertificateForgery("certificate release binding mismatch")
        if (
            expected_public_key is not None
            and parsed.public_key != expected_public_key
        ):
            raise CertificateForgery("certificate public key binding mismatch")
        try:
            valid = verify_sm2(
                bytes.fromhex(parsed.signature),
                canonical_bytes(parsed.unsigned_dict()),
                self._signing_key.public_key,
            )
        except (SM2Error, ValueError) as exc:
            raise CertificateForgery("certificate signature is malformed") from exc
        if not valid:
            raise CertificateForgery("certificate signature is invalid")
        return parsed

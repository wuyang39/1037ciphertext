"""Environment-only settings for the production KAS process."""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from crypto.sm2 import SM2KeyPair

from .ca import CertificateAuthority
from .dcap import DcapQuoteVerifier
from .policy import PolicyRegistry
from .service import KASService


@dataclass(frozen=True)
class KASSettings:
    ca_key_path: Path
    ca_certificate_path: Path
    release_policy_path: Path
    dcap_verifier_bin: Path
    ticket_signing_key_path: Path
    host: str = "127.0.0.1"
    port: int = 8443
    challenge_ttl_seconds: int = 120
    node_lease_ttl_seconds: int = 3600

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "KASSettings":
        values = os.environ if environ is None else environ
        required = (
            "KAS_CA_KEY_PATH",
            "KAS_CA_CERT_PATH",
            "KAS_RELEASE_POLICY_PATH",
            "KAS_DCAP_VERIFY_BIN",
            "KAS_TICKET_SIGNING_KEY_PATH",
        )
        missing = [name for name in required if not values.get(name)]
        if missing:
            raise ValueError(
                "missing required KAS settings: " + ", ".join(sorted(missing))
            )
        return cls(
            ca_key_path=Path(values["KAS_CA_KEY_PATH"]),
            ca_certificate_path=Path(values["KAS_CA_CERT_PATH"]),
            release_policy_path=Path(values["KAS_RELEASE_POLICY_PATH"]),
            dcap_verifier_bin=Path(values["KAS_DCAP_VERIFY_BIN"]),
            ticket_signing_key_path=Path(values["KAS_TICKET_SIGNING_KEY_PATH"]),
            host=values.get("KAS_HOST", "127.0.0.1"),
            port=int(values.get("KAS_PORT", "8443")),
            challenge_ttl_seconds=int(values.get("KAS_CHALLENGE_TTL_SECONDS", "120")),
            node_lease_ttl_seconds=int(
                values.get("KAS_NODE_LEASE_TTL_SECONDS", "3600")
            ),
        )


def build_service(settings: KASSettings) -> KASService:
    ticket_private_key = settings.ticket_signing_key_path.read_text(
        encoding="ascii"
    ).strip()
    if ticket_private_key.startswith("0x"):
        ticket_private_key = ticket_private_key[2:]
    return KASService(
        quote_verifier=DcapQuoteVerifier(settings.dcap_verifier_bin),
        policy_registry=PolicyRegistry.from_json_file(settings.release_policy_path),
        certificate_authority=CertificateAuthority.from_pem_files(
            settings.ca_key_path,
            settings.ca_certificate_path,
        ),
        ticket_signing_key=SM2KeyPair.from_private_key(ticket_private_key),
        challenge_ttl=dt.timedelta(seconds=settings.challenge_ttl_seconds),
        node_lease_ttl=dt.timedelta(seconds=settings.node_lease_ttl_seconds),
    )

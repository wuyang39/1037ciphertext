"""Generate the KAS's own secret material on the host that will run it.

The earlier D4 runs took every node identity from a PKI the driver built, so
nothing in them proved where a node ran. The attested run replaces that with a
KAS, and the KAS needs four pieces of material that must never travel: a CA
key, a ticket signing key, and a storage key master, plus the CA certificate
that is public.

Those are generated here, on the instance that runs the KAS, and stay there.
The driver only ever sees the paths and the digests this module prints, so a
record of the run can show which material issued which lease without the
material itself leaving the machine.

Usage::

    python -m infra.kas_material --directory /tmp/a122-kas-<run-id>
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any, Sequence

from crypto.sm2 import SM2KeyPair
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


CA_KEY_NAME = "kas-ca-key.pem"
CA_CERT_NAME = "kas-ca-cert.pem"
TICKET_KEY_NAME = "ticket-signing-key.hex"
STORAGE_MASTER_NAME = "storage-key-master.hex"
STORAGE_MASTER_BYTES = 32


class KasMaterialError(RuntimeError):
    """The KAS material could not be generated."""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii", newline="\n")
    path.chmod(0o600)


def generate(directory: Path, *, days: int = 2) -> dict[str, Any]:
    """Write the four files ``KASSettings`` reads and describe them publicly."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise KasMaterialError(
            f"the KAS material directory is not empty: {directory}"
        )
    directory.mkdir(parents=True, exist_ok=True)

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 KAS CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
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
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path = directory / CA_KEY_NAME
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_key_path.chmod(0o600)
    ca_certificate_pem = ca_certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")
    ca_cert_path = directory / CA_CERT_NAME
    ca_cert_path.write_text(ca_certificate_pem, encoding="ascii", newline="\n")

    ticket_key_path = directory / TICKET_KEY_NAME
    _write_private(ticket_key_path, SM2KeyPair.generate().private_key + "\n")
    storage_master_path = directory / STORAGE_MASTER_NAME
    _write_private(
        storage_master_path,
        secrets.token_bytes(STORAGE_MASTER_BYTES).hex() + "\n",
    )

    return {
        "directory": str(directory),
        "ca_key_path": str(ca_key_path),
        "ca_cert_path": str(ca_cert_path),
        "ticket_signing_key_path": str(ticket_key_path),
        "storage_key_master_hex_path": str(storage_master_path),
        "ca_certificate_pem": ca_certificate_pem,
        "ca_certificate_sha256": _digest(ca_cert_path),
        # Digests only: the reader can tell which material issued a lease
        # without the run shipping a private key or the master key.
        "ca_key_sha256": _digest(ca_key_path),
        "ticket_signing_key_sha256": _digest(ticket_key_path),
        "storage_key_master_sha256": _digest(storage_master_path),
        "created_utc": now.replace(microsecond=0).isoformat(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A1-22 KAS material generator")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--days", type=int, default=2)
    args = parser.parse_args(argv)
    try:
        document = generate(args.directory, days=args.days)
    except (KasMaterialError, OSError, ValueError) as exc:
        print(f"A122-KAS-MATERIAL-REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


__all__ = [
    "CA_CERT_NAME",
    "CA_KEY_NAME",
    "KasMaterialError",
    "STORAGE_MASTER_NAME",
    "TICKET_KEY_NAME",
    "generate",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())

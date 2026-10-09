"""Run local fail-closed checks that do not require a server."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mpc.secure_ops.rss import RSSContext, RSSProtocolError
from mpc.spu_backend.mtls import TLSPolicyError, TLSConfig
from model.share_import import ShareImportError, import_model_share, ModelShare
from tee.storage import ActiveLease, MockEncryptedFileSystem, StorageKey


def _expect_rejection(name: str, callback) -> dict[str, object]:
    try:
        callback()
    except Exception as exc:
        return {"check": name, "status": "rejected", "reason": type(exc).__name__}
    return {"check": name, "status": "FAILED", "reason": "unexpected acceptance"}


def run_checks() -> dict[str, object]:
    now = dt.datetime.now(dt.timezone.utc)
    results = [
        _expect_rejection(
            "tls_downgrade",
            lambda: TLSConfig(
                role="P0",
                certificate_pem="-----BEGIN CERTIFICATE-----\nAA\n",
                private_key_pem="-----BEGIN PRIVATE KEY-----\nAA\n",
                ca_bundle_pem="-----BEGIN CERTIFICATE-----\nAA\n",
                expected_peer_san="spiffe://a122/P1",
                min_version="TLS1.2",
            ),
        ),
        _expect_rejection(
            "simulation_reveal_disabled",
            lambda: RSSContext(ring_bits=64, reveal_allowed=False).compare(
                RSSContext(ring_bits=64).share(1),
                RSSContext(ring_bits=64).share(2),
            ),
        ),
        _expect_rejection(
            "share_epoch_mismatch",
            lambda: import_model_share(
                ModelShare("P0", "aa" * 32, 7, b"share"),
                expected_model_hash="aa" * 32,
                expected_share_epoch=8,
                expected_role="P0",
                attestation_release_id="release-v1",
                allowed_release_ids={"release-v1"},
            ),
        ),
        _expect_rejection(
            "wrong_storage_key",
            lambda: _wrong_storage_key(),
        ),
    ]
    return {
        "negative_test_version": "a122-local-negative-v1",
        "generated_at": now.isoformat(),
        "results": results,
        "all_rejected": all(item["status"] == "rejected" for item in results),
    }


def _wrong_storage_key() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        storage = MockEncryptedFileSystem(Path(directory), master_key=b"m" * 32)
        key = StorageKey("aa" * 32, b"k" * 32)
        storage.seal_material(
            material_id="share",
            model_version="tiny-v1",
            share_epoch=7,
            purpose="model-store",
            plaintext=b"protected",
            sealing_key=key,
        )
        storage.mount(
            lease=ActiveLease(
                "lease",
                "P0",
                "release-v1",
                7,
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
            ),
            storage_key=StorageKey("bb" * 32, b"z" * 32),
        )
        storage.open_material(
            "share",
            expected_model_version="tiny-v1",
            expected_share_epoch=7,
            purpose="model-store",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = run_checks()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if document["all_rejected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

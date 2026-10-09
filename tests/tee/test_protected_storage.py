from __future__ import annotations

import datetime as dt
import tempfile
from pathlib import Path

import pytest

from tee.storage import (
    ActiveLease,
    MockEncryptedFileSystem,
    StorageAccessRejected,
    StorageKey,
)


NOW = dt.datetime(2030, 1, 1, 8, 0, tzinfo=dt.timezone.utc)
MASTER_KEY = b"m" * 32
STORAGE_KEY = StorageKey(key_id="aa" * 32, key=b"k" * 32)


def make_lease(*, epoch: int = 7) -> ActiveLease:
    return ActiveLease(
        lease_id="lease-1",
        role="P0",
        release_id="a122-test-v1",
        share_epoch=epoch,
        expires_at=NOW + dt.timedelta(hours=1),
    )


def test_protected_material_is_ciphertext_on_host_and_authenticated() -> None:
    with tempfile.TemporaryDirectory() as directory:
        storage = MockEncryptedFileSystem(Path(directory), master_key=MASTER_KEY)
        storage.seal_material(
            material_id="model-share-p0",
            model_version="tiny-v1",
            share_epoch=7,
            purpose="model-store",
            plaintext=b"secret-model-share",
            nonce=b"n" * 12,
            sealing_key=STORAGE_KEY,
        )
        host_bytes = storage.ciphertext_for("model-share-p0")
        assert b"secret-model-share" not in host_bytes
        with pytest.raises(StorageAccessRejected, match="not mounted"):
            storage.open_material(
                "model-share-p0",
                expected_model_version="tiny-v1",
                expected_share_epoch=7,
                purpose="model-store",
            )
        storage.mount(lease=make_lease(), storage_key=STORAGE_KEY)
        assert storage.open_material(
            "model-share-p0",
            expected_model_version="tiny-v1",
            expected_share_epoch=7,
            purpose="model-store",
        ) == b"secret-model-share"
        storage.unmount()


def test_wrong_key_tamper_epoch_and_cleanup_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        storage = MockEncryptedFileSystem(Path(directory), master_key=MASTER_KEY)
        storage.seal_material(
            material_id="share",
            model_version="tiny-v1",
            share_epoch=7,
            purpose="model-store",
            plaintext=b"payload",
            nonce=b"a" * 12,
            sealing_key=STORAGE_KEY,
        )
        storage.mount(lease=make_lease(), storage_key=STORAGE_KEY)
        with pytest.raises(StorageAccessRejected, match="epoch"):
            storage.open_material(
                "share",
                expected_model_version="tiny-v1",
                expected_share_epoch=8,
                purpose="model-store",
            )
        storage.unmount()

        wrong = StorageKey(key_id="bb" * 32, key=b"z" * 32)
        storage.mount(lease=make_lease(), storage_key=wrong)
        with pytest.raises(StorageAccessRejected, match="authentication"):
            storage.open_material(
                "share",
                expected_model_version="tiny-v1",
                expected_share_epoch=7,
                purpose="model-store",
            )
        storage.unmount()

        path = Path(directory) / "share.enc"
        document = path.read_text(encoding="ascii")
        path.write_text(document.replace("ciphertext", "ciphertext"), encoding="ascii")
        injected = document.replace('"tag":', '"unused":', 1)
        path.write_text(injected, encoding="ascii")
        storage.mount(lease=make_lease(), storage_key=STORAGE_KEY)
        with pytest.raises(StorageAccessRejected):
            storage.open_material(
                "share",
                expected_model_version="tiny-v1",
                expected_share_epoch=7,
                purpose="model-store",
            )
        storage.unmount()
        storage.scrub_root()
        assert not path.exists()


def test_expired_lease_cannot_mount_or_open() -> None:
    with tempfile.TemporaryDirectory() as directory:
        storage = MockEncryptedFileSystem(
            Path(directory),
            master_key=MASTER_KEY,
            clock=lambda: NOW,
        )
        expired = ActiveLease(
            lease_id="lease-old",
            role="P0",
            release_id="a122-test-v1",
            share_epoch=7,
            expires_at=NOW - dt.timedelta(seconds=1),
        )
        with pytest.raises(StorageAccessRejected, match="expired"):
            storage.mount(lease=expired, storage_key=STORAGE_KEY)

"""Purpose-bound encrypted storage used by the local TEE Worker path.

This module is a deterministic software model of the Gramine encrypted-FS
boundary. It keeps key derivation, authentication, manifest hashing, and
failure cleanup testable without claiming that a host filesystem is a real
encrypted volume.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from contracts import canonical_bytes
from crypto.sm3 import hkdf, sm3
from crypto.sm4_gcm import AuthenticationError, SM4GCM


class StorageAccessRejected(ValueError):
    """A storage operation failed lease, key, or integrity checks."""


@dataclass(frozen=True)
class ActiveLease:
    """The subset of a verified KAS Lease needed before storage is mounted."""

    lease_id: str
    role: str
    release_id: str
    share_epoch: int
    expires_at: dt.datetime

    def require_active(
        self,
        *,
        now: dt.datetime,
        role: str | None = None,
        release_id: str | None = None,
        share_epoch: int | None = None,
    ) -> None:
        if self.expires_at.tzinfo is None or now.tzinfo is None:
            raise StorageAccessRejected("Lease and clock must be timezone-aware")
        if now.astimezone(dt.timezone.utc) >= self.expires_at.astimezone(
            dt.timezone.utc
        ):
            raise StorageAccessRejected("enclave Lease has expired")
        if role is not None and self.role != role:
            raise StorageAccessRejected("enclave Lease role mismatch")
        if release_id is not None and self.release_id != release_id:
            raise StorageAccessRejected("enclave Lease release mismatch")
        if share_epoch is not None and self.share_epoch != share_epoch:
            raise StorageAccessRejected("enclave Lease share epoch mismatch")


@dataclass(frozen=True)
class StorageKey:
    """A released per-node disk key. The representation is redacted."""

    key_id: str
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key_id) != 64:
            raise ValueError("storage key_id must be a 64-character digest")
        if len(self.key) != 32:
            raise ValueError("storage key must contain 32 bytes")

    @classmethod
    def from_hex(cls, *, key_id: str, key_hex: str) -> "StorageKey":
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ValueError("storage key is not hexadecimal") from exc
        return cls(key_id=key_id, key=key)

    def __repr__(self) -> str:
        return f"StorageKey(key_id={self.key_id!r}, key=<redacted>)"


@dataclass(frozen=True)
class EncryptedBlob:
    """Self-describing authenticated ciphertext stored outside the enclave."""

    material_id: str
    model_version: str
    share_epoch: int
    purpose: str
    plaintext_hash: str
    plaintext_size: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "material_id": self.material_id,
            "model_version": self.model_version,
            "share_epoch": self.share_epoch,
            "purpose": self.purpose,
            "plaintext_hash": self.plaintext_hash,
            "plaintext_size": self.plaintext_size,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.metadata_dict(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EncryptedBlob":
        required = {
            "material_id",
            "model_version",
            "share_epoch",
            "purpose",
            "plaintext_hash",
            "plaintext_size",
            "nonce",
            "ciphertext",
            "tag",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise StorageAccessRejected("encrypted blob has unexpected fields")
        try:
            nonce = bytes.fromhex(str(value["nonce"]))
            ciphertext = bytes.fromhex(str(value["ciphertext"]))
            tag = bytes.fromhex(str(value["tag"]))
        except (TypeError, ValueError) as exc:
            raise StorageAccessRejected("encrypted blob encoding is invalid") from exc
        if not isinstance(value["share_epoch"], int) or value["share_epoch"] < 0:
            raise StorageAccessRejected("encrypted blob share_epoch is invalid")
        if not isinstance(value["plaintext_size"], int) or value["plaintext_size"] < 0:
            raise StorageAccessRejected("encrypted blob plaintext_size is invalid")
        return cls(
            material_id=str(value["material_id"]),
            model_version=str(value["model_version"]),
            share_epoch=int(value["share_epoch"]),
            purpose=str(value["purpose"]),
            plaintext_hash=str(value["plaintext_hash"]),
            plaintext_size=int(value["plaintext_size"]),
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )


class MockEncryptedFileSystem:
    """Local encrypted-FS model with explicit mount and cleanup semantics."""

    def __init__(
        self,
        root: Path,
        *,
        master_key: bytes,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        if len(master_key) != 32:
            raise ValueError("master_key must contain 32 bytes")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._master_key = bytes(master_key)
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._mounted = False
        self._lease: ActiveLease | None = None
        self._storage_key: StorageKey | None = None
        self._lock = threading.Lock()

    @property
    def mounted(self) -> bool:
        return self._mounted

    def _path_for(self, material_id: str) -> Path:
        if not material_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in material_id
        ):
            raise ValueError("material_id must be a safe file identifier")
        return self.root / f"{material_id}.enc"

    def _blob_key(self, blob: EncryptedBlob, key: StorageKey) -> bytes:
        return hkdf(
            salt=key.key,
            input_key_material=self._master_key,
            info=(
                b"A1-22:protected-material:v1\0"
                + canonical_bytes(blob.metadata_dict())
            ),
            length=16,
        )

    @staticmethod
    def _plaintext_hash(plaintext: bytes) -> str:
        return hashlib.sha256(plaintext).hexdigest()

    def seal_material(
        self,
        *,
        material_id: str,
        model_version: str,
        share_epoch: int,
        purpose: str,
        plaintext: bytes,
        nonce: bytes | None = None,
        sealing_key: StorageKey | None = None,
    ) -> EncryptedBlob:
        """Encrypt one material and atomically publish its ciphertext."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not model_version or not purpose or share_epoch < 0:
            raise ValueError("material metadata is invalid")
        nonce = nonce or secrets.token_bytes(12)
        if len(nonce) != 12:
            raise ValueError("SM4-GCM nonce must contain 12 bytes")
        plaintext_hash = self._plaintext_hash(plaintext)
        metadata = {
            "material_id": material_id,
            "model_version": model_version,
            "share_epoch": share_epoch,
            "purpose": purpose,
            "plaintext_hash": plaintext_hash,
            "plaintext_size": len(plaintext),
        }
        if sealing_key is None:
            local_key = hkdf(
                salt=self._master_key,
                input_key_material=b"A1-22:local-seal-key:v1\0",
                info=canonical_bytes(metadata),
                length=16,
            )
        else:
            local_key = self._blob_key(
                EncryptedBlob(**metadata, nonce=nonce, ciphertext=b"", tag=b""),
                sealing_key,
            )
        ciphertext, tag = SM4GCM(local_key).encrypt(
            nonce,
            plaintext,
            canonical_bytes(metadata),
        )
        blob = EncryptedBlob(
            **metadata,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        path = self._path_for(material_id)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                blob.to_dict(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="ascii",
        )
        os.replace(temporary, path)
        return blob

    def mount(self, *, lease: ActiveLease, storage_key: StorageKey) -> None:
        """Mount only after an active Lease and the correct KAS key arrive."""
        lease.require_active(now=self._clock())
        with self._lock:
            self._lease = lease
            self._storage_key = storage_key
            self._mounted = True

    def unmount(self) -> None:
        """Drop key references and mark the encrypted FS unavailable."""
        with self._lock:
            self._mounted = False
            self._lease = None
            self._storage_key = None

    def open_material(
        self,
        material_id: str,
        *,
        expected_model_version: str,
        expected_share_epoch: int,
        purpose: str,
    ) -> bytes:
        """Verify metadata, key, tag, and plaintext hash before returning bytes."""
        with self._lock:
            if not self._mounted or self._lease is None or self._storage_key is None:
                raise StorageAccessRejected("encrypted FS is not mounted")
            lease = self._lease
            storage_key = self._storage_key
        lease.require_active(
            now=self._clock(),
            share_epoch=expected_share_epoch,
        )
        path = self._path_for(material_id)
        try:
            document = json.loads(path.read_text(encoding="ascii"))
            blob = EncryptedBlob.from_dict(document)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StorageAccessRejected("protected material is unavailable") from exc
        if (
            blob.model_version != expected_model_version
            or blob.share_epoch != expected_share_epoch
            or blob.purpose != purpose
        ):
            raise StorageAccessRejected("protected material binding mismatch")
        local_key = self._blob_key(blob, storage_key)
        try:
            plaintext = SM4GCM(local_key).decrypt(
                blob.nonce,
                blob.ciphertext,
                blob.tag,
                canonical_bytes(blob.metadata_dict()),
            )
        except AuthenticationError as exc:
            raise StorageAccessRejected(
                "protected material authentication failed"
            ) from exc
        if len(plaintext) != blob.plaintext_size or not hmac.compare_digest(
            self._plaintext_hash(plaintext),
            blob.plaintext_hash,
        ):
            raise StorageAccessRejected("protected material hash mismatch")
        return plaintext

    def ciphertext_for(self, material_id: str) -> bytes:
        """Return host-visible bytes for negative-path tests."""
        path = self._path_for(material_id)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise StorageAccessRejected("protected material is unavailable") from exc

    def remove_material(self, material_id: str) -> None:
        """Best-effort overwrite and unlink for failure-path cleanup."""
        path = self._path_for(material_id)
        try:
            size = path.stat().st_size
            with path.open("r+b") as handle:
                handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
            path.unlink()
        except FileNotFoundError:
            return

    def scrub_root(self) -> None:
        """Remove all host-visible blobs during abnormal worker teardown."""
        for path in self.root.glob("*.enc"):
            self.remove_material(path.stem)
        for path in self.root.glob("*.tmp"):
            try:
                path.unlink()
            except FileNotFoundError:
                continue


__all__ = [
    "ActiveLease",
    "EncryptedBlob",
    "MockEncryptedFileSystem",
    "StorageAccessRejected",
    "StorageKey",
]

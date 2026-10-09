"""Authenticated, encrypted result frames returned by one enclave node."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from contracts import canonical_bytes, canonical_hash, validate_contract
from crypto.sm2 import SM2Error, SM2KeyPair, verify_sm2
from crypto.sm3 import hkdf, sm3
from crypto.sm4_gcm import AuthenticationError, SM4GCM


RESULT_PROTOCOL_VERSION = "a122-result-frame-v1"


class ResultRejected(ValueError):
    """A result frame failed authentication, binding, or reconstruction."""


def _require_hex(value: Any, *, name: str, byte_length: int) -> str:
    try:
        raw = bytes.fromhex(str(value))
    except (TypeError, ValueError) as exc:
        raise ResultRejected(f"{name} is not hexadecimal") from exc
    if len(raw) != byte_length:
        raise ResultRejected(f"{name} must be {byte_length} bytes")
    return raw.hex()


@dataclass(frozen=True)
class ResultFrame:
    """One node's signed receipt and encrypted output share."""

    protocol_version: str
    session_id: str
    node_role: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    request_hash: str
    decode_step: int
    client_ephemeral_pub: str
    node_ephemeral_pub: str
    nonce: str
    ciphertext: str
    tag: str
    enclave_receipt: str

    def __post_init__(self) -> None:
        if self.protocol_version != RESULT_PROTOCOL_VERSION:
            raise ResultRejected("unsupported result-frame protocol version")
        if self.node_role not in {"P0", "P1", "P2"}:
            raise ResultRejected("result-frame node role is invalid")
        _require_hex(self.session_id, name="session_id", byte_length=32)
        _require_hex(
            self.model_manifest_hash,
            name="model_manifest_hash",
            byte_length=32,
        )
        _require_hex(
            self.precision_plan_hash,
            name="precision_plan_hash",
            byte_length=32,
        )
        _require_hex(self.request_hash, name="request_hash", byte_length=32)
        _require_hex(
            self.client_ephemeral_pub,
            name="client_ephemeral_pub",
            byte_length=64,
        )
        _require_hex(
            self.node_ephemeral_pub,
            name="node_ephemeral_pub",
            byte_length=64,
        )
        _require_hex(self.nonce, name="nonce", byte_length=12)
        _require_hex(self.tag, name="tag", byte_length=16)
        _require_hex(self.enclave_receipt, name="enclave_receipt", byte_length=64)
        if not isinstance(self.share_epoch, int) or self.share_epoch < 0:
            raise ResultRejected("result-frame share_epoch is invalid")
        if not isinstance(self.decode_step, int) or self.decode_step < 0:
            raise ResultRejected("result-frame decode_step is invalid")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "node_role": self.node_role,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": self.share_epoch,
            "request_hash": self.request_hash,
            "decode_step": self.decode_step,
            "client_ephemeral_pub": self.client_ephemeral_pub,
            "node_ephemeral_pub": self.node_ephemeral_pub,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "tag": self.tag,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.unsigned_dict()
        value["enclave_receipt"] = self.enclave_receipt
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResultFrame":
        required = {
            "protocol_version",
            "session_id",
            "node_role",
            "model_manifest_hash",
            "precision_plan_hash",
            "share_epoch",
            "request_hash",
            "decode_step",
            "client_ephemeral_pub",
            "node_ephemeral_pub",
            "nonce",
            "ciphertext",
            "tag",
            "enclave_receipt",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise ResultRejected("result frame has unexpected fields")
        return cls(**{name: value[name] for name in required})

    @classmethod
    def issue(
        cls,
        *,
        session_id: str,
        node_role: str,
        model_manifest_hash: str,
        precision_plan_hash: str,
        share_epoch: int,
        request_hash: str,
        decode_step: int,
        client_ephemeral_pub: str,
        node_identity: SM2KeyPair,
        node_ephemeral: SM2KeyPair,
        output_share: bytes,
        nonce: bytes | None = None,
    ) -> "ResultFrame":
        if not isinstance(output_share, bytes):
            raise TypeError("output_share must be bytes")
        nonce = nonce or secrets.token_bytes(12)
        shared_secret = node_ephemeral.exchange(client_ephemeral_pub)
        binding = {
            "protocol_version": RESULT_PROTOCOL_VERSION,
            "session_id": session_id,
            "node_role": node_role,
            "model_manifest_hash": model_manifest_hash,
            "precision_plan_hash": precision_plan_hash,
            "share_epoch": share_epoch,
            "request_hash": request_hash,
            "decode_step": decode_step,
            "client_ephemeral_pub": client_ephemeral_pub,
            "node_ephemeral_pub": node_ephemeral.public_key,
        }
        key = hkdf(
            salt=sm3(b"A1-22:result-frame-salt:v1\0" + bytes.fromhex(session_id)),
            input_key_material=shared_secret,
            info=canonical_bytes(binding),
            length=16,
        )
        ciphertext, tag = SM4GCM(key).encrypt(
            nonce,
            output_share,
            canonical_bytes(binding),
        )
        frame = cls(
            protocol_version=RESULT_PROTOCOL_VERSION,
            session_id=session_id,
            node_role=node_role,
            model_manifest_hash=model_manifest_hash,
            precision_plan_hash=precision_plan_hash,
            share_epoch=share_epoch,
            request_hash=request_hash,
            decode_step=decode_step,
            client_ephemeral_pub=client_ephemeral_pub,
            node_ephemeral_pub=node_ephemeral.public_key,
            nonce=nonce.hex(),
            ciphertext=ciphertext.hex(),
            tag=tag.hex(),
            enclave_receipt=node_identity.sign(
                canonical_bytes(
                    {
                        **binding,
                        "nonce": nonce.hex(),
                        "ciphertext": ciphertext.hex(),
                        "tag": tag.hex(),
                    }
                )
            ).hex(),
        )
        return frame

    def verify_receipt(self, *, node_public_key: str) -> None:
        try:
            valid = verify_sm2(
                bytes.fromhex(self.enclave_receipt),
                canonical_bytes(self.unsigned_dict()),
                node_public_key,
            )
        except (SM2Error, ValueError) as exc:
            raise ResultRejected("result-frame receipt is malformed") from exc
        if not valid:
            raise ResultRejected("result-frame receipt is invalid")

    def decrypt_for_client(self, client_ephemeral: SM2KeyPair) -> bytes:
        if client_ephemeral.public_key != self.client_ephemeral_pub:
            raise ResultRejected("client ephemeral key does not match the frame")
        shared_secret = client_ephemeral.exchange(self.node_ephemeral_pub)
        binding = {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "node_role": self.node_role,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": self.share_epoch,
            "request_hash": self.request_hash,
            "decode_step": self.decode_step,
            "client_ephemeral_pub": self.client_ephemeral_pub,
            "node_ephemeral_pub": self.node_ephemeral_pub,
        }
        key = hkdf(
            salt=sm3(
                b"A1-22:result-frame-salt:v1\0"
                + bytes.fromhex(self.session_id)
            ),
            input_key_material=shared_secret,
            info=canonical_bytes(binding),
            length=16,
        )
        try:
            return SM4GCM(key).decrypt(
                bytes.fromhex(self.nonce),
                bytes.fromhex(self.ciphertext),
                bytes.fromhex(self.tag),
                canonical_bytes(binding),
            )
        except AuthenticationError as exc:
            raise ResultRejected("result-frame ciphertext is invalid") from exc


def reconstruct_result_frames(
    frames: Sequence[ResultFrame],
    *,
    expected_session_id: str,
    expected_model_manifest_hash: str,
    expected_precision_plan_hash: str,
    expected_share_epoch: int,
    expected_request_hash: str,
    expected_decode_step: int,
    node_public_keys: Mapping[str, str],
    client_ephemeral: SM2KeyPair,
) -> list[bytes]:
    """Validate three distinct node receipts and return their output shares."""
    if len(frames) != 3:
        raise ResultRejected("exactly three node result frames are required")
    expected_roles = {"P0", "P1", "P2"}
    if {frame.node_role for frame in frames} != expected_roles:
        raise ResultRejected("result frames do not cover P0, P1, and P2")
    shares: list[bytes] = []
    for frame in frames:
        if frame.session_id != expected_session_id:
            raise ResultRejected("result-frame session mismatch")
        if frame.model_manifest_hash != expected_model_manifest_hash:
            raise ResultRejected("result-frame model mismatch")
        if frame.precision_plan_hash != expected_precision_plan_hash:
            raise ResultRejected("result-frame precision-plan mismatch")
        if frame.share_epoch != expected_share_epoch:
            raise ResultRejected("result-frame epoch mismatch")
        if frame.request_hash != expected_request_hash:
            raise ResultRejected("result-frame request mismatch")
        if frame.decode_step != expected_decode_step:
            raise ResultRejected("result-frame decode-step mismatch")
        if frame.client_ephemeral_pub != client_ephemeral.public_key:
            raise ResultRejected("result-frame client-key mismatch")
        public_key = node_public_keys.get(frame.node_role)
        if not public_key:
            raise ResultRejected("result frame has no trusted node key")
        frame.verify_receipt(node_public_key=public_key)
        shares.append(frame.decrypt_for_client(client_ephemeral))
    if len({release_fingerprint(share) for share in shares}) == 1:
        # Equal shares are legal for some values, but a stale replay of the
        # same frame set is not: callers should reject duplicate frame objects.
        if len({id(frame) for frame in frames}) != 3:
            raise ResultRejected("result-frame replay detected")
    return shares


def release_fingerprint(value: bytes) -> str:
    """Hash a reconstructed share for replay checks without logging it."""
    return canonical_hash({"length": len(value), "digest": sm3(value).hex()})


def assert_same_result_digest(
    left: bytes,
    right: bytes,
) -> None:
    if not hmac.compare_digest(sm3(left), sm3(right)):
        raise ResultRejected("result consistency check failed")


__all__ = [
    "RESULT_PROTOCOL_VERSION",
    "ResultFrame",
    "ResultRejected",
    "assert_same_result_digest",
    "reconstruct_result_frames",
]

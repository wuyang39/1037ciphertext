"""SM2-authenticated handshake and SM3-HKDF session key derivation."""

from __future__ import annotations

import datetime as dt
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from contracts import canonical_bytes, validate_contract

from .certificates import SM2Certificate, SM2CertificateAuthority
from .sm2 import SM2Error, SM2KeyPair, verify_sm2
from .sm3 import SM3_BYTES, hkdf, hmac_sm3, sm3
from .sm4_gcm import SM4_GCM_NONCE_BYTES, SM4_KEY_BYTES


PROTOCOL_VERSION = "a122-gm-session-v1"
SESSION_ID_BYTES = 32
_NONCE_PREFIX_BYTES = SM4_GCM_NONCE_BYTES - 4
_SESSION_SALT_LABEL = b"A1-22:session-hkdf-salt:v1\0"
_CLIENT_HELLO_LABEL = b"A1-22:client-hello:v1\0"
_SERVER_HELLO_LABEL = b"A1-22:server-hello:v1\0"
_CLIENT_FINISHED_LABEL = b"A1-22:client-finished:v1\0"
_SERVER_FINISHED_LABEL = b"A1-22:server-finished:v1\0"


class HandshakeError(ValueError):
    """Base class for handshake policy failures."""


class HandshakeRejected(HandshakeError):
    """A handshake message failed authentication or binding checks."""


class HandshakeStateError(HandshakeError):
    """A handshake method was called out of order."""


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise HandshakeError("handshake field is too long")
    return len(value).to_bytes(4, "big") + value


def _require_hex(value: str, *, name: str, byte_length: int) -> str:
    if not isinstance(value, str):
        raise HandshakeRejected(f"{name} must be hexadecimal text")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise HandshakeRejected(f"{name} is not valid hexadecimal") from exc
    if len(raw) != byte_length:
        raise HandshakeRejected(f"{name} must be {byte_length} bytes")
    return raw.hex()


@dataclass(frozen=True)
class HandshakeBindings:
    """Values that both peers must agree on before session keys are derived."""

    session_id: str
    node_role: str
    release_id: str
    model_version: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError("unsupported session protocol version")
        object.__setattr__(
            self,
            "session_id",
            _require_hex(
                self.session_id,
                name="session_id",
                byte_length=SESSION_ID_BYTES,
            ),
        )
        if self.node_role not in {"P0", "P1", "P2"}:
            raise ValueError("node_role must be P0, P1, or P2")
        if not self.release_id:
            raise ValueError("release_id must not be empty")
        if not self.model_version:
            raise ValueError("model_version must not be empty")
        object.__setattr__(
            self,
            "model_manifest_hash",
            _require_hex(
                self.model_manifest_hash,
                name="model_manifest_hash",
                byte_length=32,
            ),
        )
        object.__setattr__(
            self,
            "precision_plan_hash",
            _require_hex(
                self.precision_plan_hash,
                name="precision_plan_hash",
                byte_length=32,
            ),
        )
        if not isinstance(self.share_epoch, int) or self.share_epoch < 0:
            raise ValueError("share_epoch must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "node_role": self.node_role,
            "release_id": self.release_id,
            "model_version": self.model_version,
            "model_manifest_hash": self.model_manifest_hash,
            "precision_plan_hash": self.precision_plan_hash,
            "share_epoch": self.share_epoch,
        }


@dataclass(frozen=True)
class DirectionalKey:
    """One direction's SM4 key and deterministic nonce prefix."""

    key: bytes = field(repr=False)
    nonce_prefix: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.key) != SM4_KEY_BYTES:
            raise ValueError("directional SM4 key must be 16 bytes")
        if len(self.nonce_prefix) != _NONCE_PREFIX_BYTES:
            raise ValueError("directional nonce prefix must be 8 bytes")


@dataclass(frozen=True)
class SessionKeys:
    """Direction-separated keys derived from ECDH and the full handshake."""

    c2p: DirectionalKey
    p2c: DirectionalKey
    transcript_hash: bytes
    bindings: HandshakeBindings

    def __post_init__(self) -> None:
        if len(self.transcript_hash) != SM3_BYTES:
            raise ValueError("transcript_hash must be a 32-byte SM3 digest")


class HandshakeTranscript:
    """Unambiguous concatenation of complete canonical handshake messages."""

    def __init__(self) -> None:
        self._data = bytearray()

    def append(self, message: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(message)
        self._data.extend(_length_prefixed(encoded))

    def snapshot(self) -> bytes:
        return bytes(self._data)

    def digest(self) -> bytes:
        return sm3(self.snapshot())


def _expected_bindings(message: Mapping[str, Any], expected: HandshakeBindings) -> bool:
    return all(message.get(name) == value for name, value in expected.to_dict().items())


def _signature_input(
    label: bytes,
    transcript: bytes,
    unsigned_message: Mapping[str, Any],
) -> bytes:
    return (
        label
        + _length_prefixed(transcript)
        + canonical_bytes(unsigned_message)
    )


def _verify_message_signature(
    *,
    label: bytes,
    transcript: bytes,
    message: Mapping[str, Any],
    public_key: str,
) -> None:
    unsigned = {
        name: value for name, value in message.items() if name != "signature"
    }
    try:
        valid = verify_sm2(
            bytes.fromhex(str(message["signature"])),
            _signature_input(label, transcript, unsigned),
            public_key,
        )
    except (KeyError, SM2Error, ValueError) as exc:
        raise HandshakeRejected("handshake signature is malformed") from exc
    if not valid:
        raise HandshakeRejected("handshake signature is invalid")


def _derive_session_keys(
    *,
    shared_secret: bytes,
    transcript_hash: bytes,
    bindings: HandshakeBindings,
) -> SessionKeys:
    session_id = bytes.fromhex(bindings.session_id)
    context = b"".join(
        (
            _length_prefixed(bindings.protocol_version.encode("ascii")),
            _length_prefixed(transcript_hash),
            _length_prefixed(session_id),
            _length_prefixed(bindings.node_role.encode("ascii")),
            _length_prefixed(bindings.model_version.encode("utf-8")),
            _length_prefixed(bindings.model_manifest_hash.encode("ascii")),
            _length_prefixed(bindings.precision_plan_hash.encode("ascii")),
            bindings.share_epoch.to_bytes(8, "big"),
        )
    )
    salt = sm3(_SESSION_SALT_LABEL + session_id)

    def directional(label: bytes) -> DirectionalKey:
        material = hkdf(
            salt=salt,
            input_key_material=shared_secret,
            info=context + _length_prefixed(label),
            length=SM4_KEY_BYTES + _NONCE_PREFIX_BYTES,
        )
        return DirectionalKey(
            key=material[:SM4_KEY_BYTES],
            nonce_prefix=material[SM4_KEY_BYTES:],
        )

    return SessionKeys(
        c2p=directional(b"C2P"),
        p2c=directional(b"P2C"),
        transcript_hash=transcript_hash,
        bindings=bindings,
    )


class ClientHandshake:
    """Client-side ``ClientHello -> ServerHello -> Finished`` state machine."""

    def __init__(
        self,
        *,
        bindings: HandshakeBindings,
        identity_key: SM2KeyPair,
        ephemeral_key: SM2KeyPair,
        certificate: SM2Certificate,
        authority: SM2CertificateAuthority,
        client_nonce: bytes | None = None,
    ) -> None:
        if certificate.role != "C" or certificate.public_key != identity_key.public_key:
            raise HandshakeRejected("client certificate does not bind the identity key")
        self.bindings = bindings
        self._identity_key = identity_key
        self._ephemeral_key = ephemeral_key
        self._certificate = certificate
        self._authority = authority
        self._client_nonce = client_nonce or secrets.token_bytes(32)
        if len(self._client_nonce) != 32:
            raise ValueError("client_nonce must be 32 bytes")
        self._transcript = HandshakeTranscript()
        self._state = "new"
        self._server_hello: dict[str, Any] | None = None
        self._node_certificate: SM2Certificate | None = None
        self._keys: SessionKeys | None = None
        self._client_finished: dict[str, Any] | None = None

    @property
    def state(self) -> str:
        return self._state

    def create_client_hello(self) -> dict[str, Any]:
        if self._state != "new":
            raise HandshakeStateError("ClientHello has already been created")
        unsigned = self.bindings.to_dict()
        unsigned.update(
            {
                "client_nonce": self._client_nonce.hex(),
                "client_ephemeral_pub": self._ephemeral_key.public_key,
                "client_certificate": self._certificate.to_dict(),
            }
        )
        signature = self._identity_key.sign(
            _signature_input(
                _CLIENT_HELLO_LABEL,
                self._transcript.snapshot(),
                unsigned,
            )
        )
        message = dict(unsigned)
        message["signature"] = signature.hex()
        validate_contract("client_hello", message)
        self._transcript.append(message)
        self._state = "client_hello_sent"
        return message

    def receive_server_hello(
        self,
        message: Mapping[str, Any],
        *,
        now: dt.datetime,
    ) -> dict[str, Any]:
        if self._state != "client_hello_sent":
            raise HandshakeStateError("ServerHello is not expected in this state")
        value = dict(message)
        validate_contract("server_hello", value)
        if not _expected_bindings(value, self.bindings):
            raise HandshakeRejected("ServerHello binding mismatch")

        node_certificate = SM2Certificate.from_dict(value["node_certificate"])
        self._authority.verify(
            node_certificate,
            now=now,
            expected_role=self.bindings.node_role,
            expected_release_id=self.bindings.release_id,
        )
        _verify_message_signature(
            label=_SERVER_HELLO_LABEL,
            transcript=self._transcript.snapshot(),
            message=value,
            public_key=node_certificate.public_key,
        )
        self._transcript.append(value)
        self._server_hello = value
        self._node_certificate = node_certificate

        shared_secret = self._ephemeral_key.exchange(
            str(value["server_ephemeral_pub"])
        )
        self._keys = _derive_session_keys(
            shared_secret=shared_secret,
            transcript_hash=self._transcript.digest(),
            bindings=self.bindings,
        )

        transcript_hash = self._keys.transcript_hash.hex()
        verify_data = hmac_sm3(
            self._keys.c2p.key,
            _CLIENT_FINISHED_LABEL + self._keys.transcript_hash,
        ).hex()
        unsigned_finished = {
            "protocol_version": self.bindings.protocol_version,
            "session_id": self.bindings.session_id,
            "transcript_hash": transcript_hash,
            "verify_data": verify_data,
        }
        signature = self._identity_key.sign(
            _signature_input(
                _CLIENT_FINISHED_LABEL,
                self._transcript.snapshot(),
                unsigned_finished,
            )
        ).hex()
        finished = dict(unsigned_finished)
        finished["signature"] = signature
        validate_contract("finished", finished)
        self._transcript.append(finished)
        self._client_finished = finished
        self._state = "finished_sent"
        return finished

    def receive_finished_ack(
        self,
        message: Mapping[str, Any],
    ) -> SessionKeys:
        if self._state != "finished_sent":
            raise HandshakeStateError("FinishedAck is not expected in this state")
        if self._keys is None or self._node_certificate is None:
            raise HandshakeStateError("ServerHello has not been processed")
        value = dict(message)
        validate_contract("finished", value)
        if value.get("protocol_version") != self.bindings.protocol_version:
            raise HandshakeRejected("FinishedAck protocol version mismatch")
        if value.get("session_id") != self.bindings.session_id:
            raise HandshakeRejected("FinishedAck session mismatch")
        expected_transcript_hash = self._transcript.digest()
        if value.get("transcript_hash") != expected_transcript_hash.hex():
            raise HandshakeRejected("FinishedAck transcript mismatch")
        expected_verify_data = hmac_sm3(
            self._keys.p2c.key,
            _SERVER_FINISHED_LABEL + expected_transcript_hash,
        )
        try:
            actual_verify_data = bytes.fromhex(str(value["verify_data"]))
        except (KeyError, ValueError) as exc:
            raise HandshakeRejected("FinishedAck verify_data is malformed") from exc
        if not hmac.compare_digest(actual_verify_data, expected_verify_data):
            raise HandshakeRejected("FinishedAck verify_data is invalid")
        _verify_message_signature(
            label=_SERVER_FINISHED_LABEL,
            transcript=self._transcript.snapshot(),
            message=value,
            public_key=self._node_certificate.public_key,
        )
        self._transcript.append(value)
        self._state = "established"
        return self._keys


class NodeHandshake:
    """Node-side ``ServerHello -> FinishedAck`` state machine."""

    def __init__(
        self,
        *,
        bindings: HandshakeBindings,
        identity_key: SM2KeyPair,
        ephemeral_key: SM2KeyPair,
        certificate: SM2Certificate,
        authority: SM2CertificateAuthority,
        server_nonce: bytes | None = None,
    ) -> None:
        if (
            certificate.role != bindings.node_role
            or certificate.public_key != identity_key.public_key
        ):
            raise HandshakeRejected("node certificate does not bind the identity key")
        self.bindings = bindings
        self._identity_key = identity_key
        self._ephemeral_key = ephemeral_key
        self._certificate = certificate
        self._authority = authority
        self._server_nonce = server_nonce or secrets.token_bytes(32)
        if len(self._server_nonce) != 32:
            raise ValueError("server_nonce must be 32 bytes")
        self._transcript = HandshakeTranscript()
        self._state = "new"
        self._client_certificate: SM2Certificate | None = None
        self._keys: SessionKeys | None = None
        self._server_hello_hash: bytes | None = None

    @property
    def state(self) -> str:
        return self._state

    def receive_client_hello(
        self,
        message: Mapping[str, Any],
        *,
        now: dt.datetime,
    ) -> dict[str, Any]:
        if self._state != "new":
            raise HandshakeStateError("ClientHello is not expected in this state")
        value = dict(message)
        validate_contract("client_hello", value)
        if not _expected_bindings(value, self.bindings):
            raise HandshakeRejected("ClientHello binding mismatch")
        client_certificate = SM2Certificate.from_dict(value["client_certificate"])
        self._authority.verify(
            client_certificate,
            now=now,
            expected_role="C",
            expected_release_id=self.bindings.release_id,
        )
        _verify_message_signature(
            label=_CLIENT_HELLO_LABEL,
            transcript=self._transcript.snapshot(),
            message=value,
            public_key=client_certificate.public_key,
        )
        self._transcript.append(value)
        self._client_certificate = client_certificate

        unsigned = self.bindings.to_dict()
        unsigned.update(
            {
                "server_nonce": self._server_nonce.hex(),
                "server_ephemeral_pub": self._ephemeral_key.public_key,
                "node_certificate": self._certificate.to_dict(),
            }
        )
        signature = self._identity_key.sign(
            _signature_input(
                _SERVER_HELLO_LABEL,
                self._transcript.snapshot(),
                unsigned,
            )
        ).hex()
        server_hello = dict(unsigned)
        server_hello["signature"] = signature
        validate_contract("server_hello", server_hello)
        self._transcript.append(server_hello)

        shared_secret = self._ephemeral_key.exchange(
            str(value["client_ephemeral_pub"])
        )
        self._server_hello_hash = self._transcript.digest()
        self._keys = _derive_session_keys(
            shared_secret=shared_secret,
            transcript_hash=self._server_hello_hash,
            bindings=self.bindings,
        )
        self._state = "server_hello_sent"
        return server_hello

    def receive_finished(
        self,
        message: Mapping[str, Any],
    ) -> tuple[dict[str, Any], SessionKeys]:
        if self._state != "server_hello_sent":
            raise HandshakeStateError("Finished is not expected in this state")
        if (
            self._keys is None
            or self._server_hello_hash is None
            or self._client_certificate is None
        ):
            raise HandshakeStateError("ClientHello has not been processed")
        value = dict(message)
        validate_contract("finished", value)
        if value.get("protocol_version") != self.bindings.protocol_version:
            raise HandshakeRejected("Finished protocol version mismatch")
        if value.get("session_id") != self.bindings.session_id:
            raise HandshakeRejected("Finished session mismatch")
        if value.get("transcript_hash") != self._server_hello_hash.hex():
            raise HandshakeRejected("Finished transcript hash mismatch")

        expected_verify_data = hmac_sm3(
            self._keys.c2p.key,
            _CLIENT_FINISHED_LABEL + self._server_hello_hash,
        )
        try:
            actual_verify_data = bytes.fromhex(str(value["verify_data"]))
        except (KeyError, ValueError) as exc:
            raise HandshakeRejected("Finished verify_data is malformed") from exc
        if not hmac.compare_digest(actual_verify_data, expected_verify_data):
            raise HandshakeRejected("Finished verify_data is invalid")
        _verify_message_signature(
            label=_CLIENT_FINISHED_LABEL,
            transcript=self._transcript.snapshot(),
            message=value,
            public_key=self._client_certificate.public_key,
        )
        self._transcript.append(value)

        final_transcript_hash = self._transcript.digest()
        verify_data = hmac_sm3(
            self._keys.p2c.key,
            _SERVER_FINISHED_LABEL + final_transcript_hash,
        ).hex()
        unsigned_ack = {
            "protocol_version": self.bindings.protocol_version,
            "session_id": self.bindings.session_id,
            "transcript_hash": final_transcript_hash.hex(),
            "verify_data": verify_data,
        }
        signature = self._identity_key.sign(
            _signature_input(
                _SERVER_FINISHED_LABEL,
                self._transcript.snapshot(),
                unsigned_ack,
            )
        ).hex()
        ack = dict(unsigned_ack)
        ack["signature"] = signature
        validate_contract("finished", ack)
        self._transcript.append(ack)
        self._state = "established"
        return ack, self._keys

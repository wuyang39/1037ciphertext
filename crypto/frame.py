"""SM4-GCM business frames with replay protection and close semantics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from contracts import canonical_bytes, validate_contract

from .handshake import DirectionalKey, SessionKeys
from .sm3 import sm3
from .sm4_gcm import AuthenticationError, SM4GCM, SM4_GCM_NONCE_BYTES


ALLOWED_MESSAGE_TYPES = {"Request", "Response", "Result", "Close"}
_FRAME_AAD_LABEL = b"A1-22:frame-aad:v1\0"
_MAX_COUNTER = 0xFFFFFFFF


class SessionError(ValueError):
    """Base class for frame session failures."""


class FrameRejected(SessionError):
    """The frame failed binding, replay, or authentication checks."""


class ReplayRejected(FrameRejected):
    """The counter is duplicated, out of order, or outside the window."""


class SessionClosed(SessionError):
    """The session state machine no longer accepts frames."""


def request_digest(payload: bytes) -> str:
    """Return the SM3 request binding for one payload."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    return sm3(payload).hex()


def _require_hash(value: str, *, name: str) -> str:
    if not isinstance(value, str):
        raise FrameRejected(f"{name} must be hexadecimal text")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise FrameRejected(f"{name} is not valid hexadecimal") from exc
    if len(raw) != 32:
        raise FrameRejected(f"{name} must be 32 bytes")
    return raw.hex()


@dataclass(frozen=True)
class FrameAAD:
    """Authenticated metadata frozen for every business frame."""

    protocol_version: str
    session_id: str
    epoch: int
    counter: int
    sender: str
    receiver: str
    model_manifest_hash: str
    request_hash: str
    message_type: str

    def __post_init__(self) -> None:
        if self.sender not in {"C", "P0", "P1", "P2"}:
            raise FrameRejected("invalid frame sender")
        if self.receiver not in {"C", "P0", "P1", "P2"}:
            raise FrameRejected("invalid frame receiver")
        if self.sender == self.receiver:
            raise FrameRejected("frame sender and receiver must differ")
        if self.message_type not in ALLOWED_MESSAGE_TYPES:
            raise FrameRejected("invalid frame message_type")
        if not isinstance(self.epoch, int) or self.epoch < 0:
            raise FrameRejected("frame epoch must be non-negative")
        if not isinstance(self.counter, int) or not 1 <= self.counter <= _MAX_COUNTER:
            raise FrameRejected("frame counter is outside the uint32 range")
        _require_hash(self.session_id, name="session_id")
        _require_hash(self.model_manifest_hash, name="model_manifest_hash")
        _require_hash(self.request_hash, name="request_hash")

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "epoch": self.epoch,
            "counter": self.counter,
            "sender": self.sender,
            "receiver": self.receiver,
            "model_manifest_hash": self.model_manifest_hash,
            "request_hash": self.request_hash,
            "message_type": self.message_type,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FrameAAD":
        validate_contract("business_frame_aad", value)
        return cls(**value)


@dataclass(frozen=True)
class EncryptedFrame:
    """Wire representation of one authenticated business frame."""

    aad: FrameAAD
    ciphertext: bytes = field(repr=False)
    tag: bytes = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "aad": self.aad.to_dict(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EncryptedFrame":
        if not isinstance(value, Mapping) or set(value) != {
            "aad",
            "ciphertext",
            "tag",
        }:
            raise FrameRejected("encrypted frame has unexpected fields")
        try:
            aad = FrameAAD.from_dict(value["aad"])
            ciphertext = bytes.fromhex(str(value["ciphertext"]))
            tag = bytes.fromhex(str(value["tag"]))
        except (TypeError, ValueError) as exc:
            raise FrameRejected("encrypted frame encoding is invalid") from exc
        if len(tag) != 16:
            raise FrameRejected("encrypted frame tag must be 16 bytes")
        return cls(aad=aad, ciphertext=ciphertext, tag=tag)


class ReplayWindow:
    """Sliding uint32 replay window.

    Strict ordering is the default so gaps and delayed frames are rejected at
    the protocol boundary. ``allow_out_of_order`` exists for transports that
    intentionally retain a bounded reorder window.
    """

    def __init__(
        self,
        *,
        window_size: int = 64,
        allow_out_of_order: bool = False,
    ) -> None:
        if window_size <= 0 or window_size > 1024:
            raise ValueError("window_size must be between 1 and 1024")
        self.window_size = window_size
        self.allow_out_of_order = allow_out_of_order
        self.highest = 0
        self._bitmap = 0

    def _bit(self, counter: int) -> int:
        offset = self.highest - counter
        return 1 << offset

    def validate(self, counter: int) -> None:
        if not isinstance(counter, int) or not 1 <= counter <= _MAX_COUNTER:
            raise ReplayRejected("counter is outside the uint32 range")
        if self.highest == 0:
            if counter != 1:
                raise ReplayRejected("first frame counter must be 1")
            return
        if counter <= self.highest:
            if not self.allow_out_of_order:
                raise ReplayRejected("counter is duplicated or out of order")
            offset = self.highest - counter
            if offset >= self.window_size or self._bitmap & (1 << offset):
                raise ReplayRejected("counter is outside or already in the window")
            return
        if not self.allow_out_of_order and counter != self.highest + 1:
            raise ReplayRejected("counter gap is not permitted")
        if counter - self.highest >= self.window_size and not self.allow_out_of_order:
            raise ReplayRejected("counter is outside the receive window")

    def commit(self, counter: int) -> None:
        if self.highest == 0:
            self.highest = counter
            self._bitmap = 1
            return
        if counter > self.highest:
            difference = counter - self.highest
            if difference >= self.window_size:
                self._bitmap = 1
            else:
                self._bitmap = (self._bitmap << difference) | 1
            self.highest = counter
            return
        if not self.allow_out_of_order:
            raise ReplayRejected("counter is duplicated or out of order")
        self._bitmap |= self._bit(self.highest - counter)


class SecureSession:
    """Direction-separated SM4-GCM session with strict counter ordering."""

    def __init__(
        self,
        *,
        keys: SessionKeys,
        local_role: str,
        peer_role: str,
        replay_window_size: int = 64,
        allow_out_of_order: bool = False,
    ) -> None:
        self.keys = keys
        self.local_role = local_role
        self.peer_role = peer_role
        node_role = keys.bindings.node_role
        if {local_role, peer_role} != {"C", node_role}:
            raise FrameRejected("session roles must be exactly C and the bound node")
        if local_role == "C":
            self._send_key = keys.c2p
            self._receive_key = keys.p2c
        else:
            self._send_key = keys.p2c
            self._receive_key = keys.c2p
        self._send_counter = 0
        self._replay_window = ReplayWindow(
            window_size=replay_window_size,
            allow_out_of_order=allow_out_of_order,
        )
        self._closed = False
        self._key_bytes_wiped = 0
        self._session_hash: str | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def session_hash(self) -> str:
        """A stable name for the session, cached so ``wipe()`` cannot change it."""
        if self._session_hash is None:
            material = (
                b"A1-22:session-hash:v1\0"
                + canonical_bytes(self.keys.bindings.to_dict())
                + self.keys.transcript_hash
            )
            self._session_hash = sm3(material).hex()
        return self._session_hash

    def _nonce(self, key: DirectionalKey, counter: int) -> bytes:
        nonce = key.nonce_prefix + counter.to_bytes(4, "big")
        if len(nonce) != SM4_GCM_NONCE_BYTES:
            raise FrameRejected("derived frame nonce has the wrong length")
        return nonce

    def _aad_bytes(self, aad: FrameAAD) -> bytes:
        return _FRAME_AAD_LABEL + canonical_bytes(aad.to_dict())

    def _make_frame(
        self,
        *,
        payload: bytes,
        message_type: str,
        request_hash: str,
    ) -> EncryptedFrame:
        if self._closed:
            raise SessionClosed("session is closed")
        if self._send_counter >= _MAX_COUNTER:
            raise SessionError("send counter exhausted")
        self._send_counter += 1
        aad = FrameAAD(
            protocol_version=self.keys.bindings.protocol_version,
            session_id=self.keys.bindings.session_id,
            epoch=self.keys.bindings.share_epoch,
            counter=self._send_counter,
            sender=self.local_role,
            receiver=self.peer_role,
            model_manifest_hash=self.keys.bindings.model_manifest_hash,
            request_hash=request_hash,
            message_type=message_type,
        )
        validate_contract("business_frame_aad", aad.to_dict())
        ciphertext, tag = SM4GCM(self._send_key.key).encrypt(
            self._nonce(self._send_key, aad.counter),
            payload,
            self._aad_bytes(aad),
        )
        return EncryptedFrame(aad=aad, ciphertext=ciphertext, tag=tag)

    def send(
        self,
        payload: bytes,
        *,
        message_type: str,
        request_hash: str,
    ) -> EncryptedFrame:
        """Encrypt one payload and consume the next send counter."""
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if message_type == "Close":
            raise FrameRejected("use close() for Close frames")
        return self._make_frame(
            payload=payload,
            message_type=message_type,
            request_hash=_require_hash(request_hash, name="request_hash"),
        )

    def receive(self, frame: EncryptedFrame | Mapping[str, Any]) -> bytes:
        """Authenticate and return payload, or reject before reaching MPC."""
        if self._closed:
            raise SessionClosed("session is closed")
        parsed = frame if isinstance(frame, EncryptedFrame) else EncryptedFrame.from_dict(frame)
        aad = parsed.aad
        validate_contract("business_frame_aad", aad.to_dict())
        if aad.protocol_version != self.keys.bindings.protocol_version:
            raise FrameRejected("frame protocol version mismatch")
        if aad.session_id != self.keys.bindings.session_id:
            raise FrameRejected("frame session mismatch")
        if aad.epoch != self.keys.bindings.share_epoch:
            raise FrameRejected("frame epoch mismatch")
        if aad.model_manifest_hash != self.keys.bindings.model_manifest_hash:
            raise FrameRejected("frame model manifest mismatch")
        if aad.sender != self.peer_role or aad.receiver != self.local_role:
            raise FrameRejected("frame direction mismatch")

        self._replay_window.validate(aad.counter)
        try:
            plaintext = SM4GCM(self._receive_key.key).decrypt(
                self._nonce(self._receive_key, aad.counter),
                parsed.ciphertext,
                parsed.tag,
                self._aad_bytes(aad),
            )
        except AuthenticationError as exc:
            raise FrameRejected("frame authentication failed") from exc
        self._replay_window.commit(aad.counter)
        if aad.message_type == "Close":
            self._closed = True
        return plaintext

    def close(self, payload: bytes = b"") -> EncryptedFrame:
        """Send one authenticated Close frame and enter the closed state."""
        if self._closed:
            raise SessionClosed("session is already closed")
        frame = self._make_frame(
            payload=payload,
            message_type="Close",
            request_hash=request_digest(payload),
        )
        self._closed = True
        return frame

    @property
    def keys_wiped(self) -> bool:
        return self._key_bytes_wiped > 0

    @property
    def wiped_key_bytes(self) -> int:
        return self._key_bytes_wiped

    def wipe(self) -> int:
        """Drop this session's key material and refuse every later frame.

        The directional keys, their nonce prefixes and the transcript hash are
        immutable ``bytes`` in CPython, so "zeroing" them means replacing them
        with same-shaped blanks: neither this object nor anything reading its
        attributes can reach a usable key afterwards, and the closed session
        still refuses every frame. The session name computed before the wipe
        stays readable, so a node can keep pointing at the session it just
        retired. Anything the interpreter may have copied elsewhere is out of
        reach of this method, which is why it reports the byte count it
        replaced instead of claiming a memory audit.
        """
        if self._key_bytes_wiped:
            return self._key_bytes_wiped
        # Read the name first: its inputs are about to be replaced.
        self.session_hash
        keys = self.keys
        c2p = DirectionalKey(key=bytes(len(keys.c2p.key)), nonce_prefix=bytes(8))
        p2c = DirectionalKey(key=bytes(len(keys.p2c.key)), nonce_prefix=bytes(8))
        replaced = (
            2 * (len(keys.c2p.key) + len(keys.c2p.nonce_prefix))
            + len(keys.transcript_hash)
        )
        self.keys = SessionKeys(
            c2p=c2p,
            p2c=p2c,
            transcript_hash=bytes(len(keys.transcript_hash)),
            bindings=keys.bindings,
        )
        if self.local_role == "C":
            self._send_key, self._receive_key = c2p, p2c
        else:
            self._send_key, self._receive_key = p2c, c2p
        self._closed = True
        self._key_bytes_wiped = replaced
        return replaced

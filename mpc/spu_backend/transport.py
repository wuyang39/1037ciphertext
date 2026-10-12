"""Real TCP/TLS 1.3 frame transport for local three-node integration tests.

This transport terminates TLS in the host process. It is intentionally marked
as a local integration backend and is not evidence of enclave-internal TLS.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography import x509


MAX_FRAME_BYTES = 16 * 1024 * 1024


class TLSChannelError(RuntimeError):
    """A TLS channel could not be established or violated its policy."""


class TLSChannelClosed(TLSChannelError):
    """The peer hung up between frames.

    The integration transport opens one connection per request, so a peer that
    closed the socket after its reply is normal traffic rather than a failed
    handler. Subclassing keeps every existing ``except TLSChannelError`` guard
    working while letting the server tell the two apart.
    """


@dataclass(frozen=True)
class TLSIdentity:
    """One local endpoint identity and its allowed peer roles."""

    role: str
    certificate_pem: str
    private_key_pem: str
    ca_bundle_pem: str
    allowed_peer_roles: tuple[str, ...]
    min_version: str = "TLS1.3"

    def __post_init__(self) -> None:
        if self.role not in {"P0", "P1", "P2"}:
            raise TLSChannelError("SPU role must be P0, P1, or P2")
        if self.min_version != "TLS1.3":
            raise TLSChannelError("TLS versions below 1.3 are forbidden")
        if not self.allowed_peer_roles:
            raise TLSChannelError("at least one peer role must be allowed")
        if any(role not in {"P0", "P1", "P2"} for role in self.allowed_peer_roles):
            raise TLSChannelError("peer allowlist contains an invalid role")
        if self.role in self.allowed_peer_roles:
            raise TLSChannelError("an endpoint cannot allow itself as a peer")
        for name in ("certificate_pem", "private_key_pem", "ca_bundle_pem"):
            if not getattr(self, name):
                raise TLSChannelError(f"{name} must not be empty")


def _write_identity_files(identity: TLSIdentity, directory: Path) -> tuple[Path, Path, Path]:
    certificate = directory / "certificate.pem"
    private_key = directory / "private-key.pem"
    ca_bundle = directory / "ca-bundle.pem"
    certificate.write_text(identity.certificate_pem, encoding="ascii")
    private_key.write_text(identity.private_key_pem, encoding="ascii")
    ca_bundle.write_text(identity.ca_bundle_pem, encoding="ascii")
    return certificate, private_key, ca_bundle


def _server_context(identity: TLSIdentity) -> ssl.SSLContext:
    with tempfile.TemporaryDirectory(prefix="a122-local-tls-") as directory:
        cert, key, ca = _write_identity_files(identity, Path(directory))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert), str(key))
        context.load_verify_locations(cafile=str(ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
    return context


def _client_context(identity: TLSIdentity) -> ssl.SSLContext:
    with tempfile.TemporaryDirectory(prefix="a122-local-tls-") as directory:
        cert, key, ca = _write_identity_files(identity, Path(directory))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert), str(key))
        context.load_verify_locations(cafile=str(ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
    return context


def _peer_role(tls_socket: ssl.SSLSocket, allowed_roles: tuple[str, ...]) -> str:
    raw_certificate = tls_socket.getpeercert(binary_form=True)
    if not raw_certificate:
        raise TLSChannelError("peer certificate is missing")
    try:
        certificate = x509.load_der_x509_certificate(raw_certificate)
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise TLSChannelError("peer certificate has no valid role SAN") from exc
    uris = set(san.get_values_for_type(x509.UniformResourceIdentifier))
    for role in allowed_roles:
        if f"spiffe://a122/{role}" in uris:
            return role
    raise TLSChannelError("peer certificate role is not allowed")


class TLSFrameChannel:
    """Length-prefixed byte frames over one mutually authenticated TLS socket."""

    def __init__(self, tls_socket: ssl.SSLSocket, *, peer_role: str) -> None:
        self._socket = tls_socket
        self.peer_role = peer_role
        self._closed = False

    @property
    def tls_version(self) -> str:
        return self._socket.version() or "unknown"

    @property
    def closed(self) -> bool:
        return self._closed

    @staticmethod
    def _recv_exact(tls_socket: ssl.SSLSocket, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            try:
                chunk = tls_socket.recv(length - len(chunks))
            except (ssl.SSLEOFError, ConnectionResetError) as exc:
                raise TLSChannelClosed("TLS peer closed the connection") from exc
            if not chunk:
                raise TLSChannelClosed("TLS peer closed the connection")
            chunks.extend(chunk)
        return bytes(chunks)

    def send_frame(self, payload: bytes) -> None:
        if self._closed:
            raise TLSChannelError("TLS channel is closed")
        if not isinstance(payload, bytes):
            raise TypeError("TLS frame payload must be bytes")
        if len(payload) > MAX_FRAME_BYTES:
            raise TLSChannelError("TLS frame exceeds the size limit")
        self._socket.sendall(len(payload).to_bytes(4, "big") + payload)

    def receive_frame(self) -> bytes:
        if self._closed:
            raise TLSChannelError("TLS channel is closed")
        length = int.from_bytes(self._recv_exact(self._socket, 4), "big")
        if length > MAX_FRAME_BYTES:
            raise TLSChannelError("TLS peer announced an oversized frame")
        return self._recv_exact(self._socket, length)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            self._socket.close()

    def __enter__(self) -> "TLSFrameChannel":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    @classmethod
    def connect(
        cls,
        *,
        host: str,
        port: int,
        identity: TLSIdentity,
        peer_role: str,
        timeout_seconds: float = 10.0,
    ) -> "TLSFrameChannel":
        if peer_role not in identity.allowed_peer_roles:
            raise TLSChannelError("requested peer role is not allowed")
        context = _client_context(identity)
        raw_socket = socket.create_connection((host, port), timeout=timeout_seconds)
        raw_socket.settimeout(timeout_seconds)
        try:
            tls_socket = context.wrap_socket(raw_socket, server_hostname=peer_role)
        except Exception:
            raw_socket.close()
            raise
        try:
            actual_role = _peer_role(tls_socket, identity.allowed_peer_roles)
            if actual_role != peer_role:
                raise TLSChannelError("connected peer does not match the requested role")
            if tls_socket.version() != "TLSv1.3":
                raise TLSChannelError("peer negotiated a TLS version below 1.3")
            return cls(tls_socket, peer_role=actual_role)
        except Exception:
            tls_socket.close()
            raise


class TLSFrameServer:
    """Single-connection-at-a-time TLS frame server for local integration."""

    def __init__(
        self,
        *,
        identity: TLSIdentity,
        handler: Callable[[TLSFrameChannel], None],
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.identity = identity
        self.handler = handler
        self._context = _server_context(identity)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.address = self._listener.getsockname()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._errors: list[BaseException] = []
        self._error_lock = threading.Lock()

    def _record_error(self, error: BaseException) -> None:
        with self._error_lock:
            self._errors.append(error)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                raw_socket, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._record_error(TLSChannelError("TLS listener failed"))
                return
            try:
                raw_socket.settimeout(10.0)
                try:
                    tls_socket = self._context.wrap_socket(
                        raw_socket,
                        server_side=True,
                    )
                except (ssl.SSLError, ConnectionError):
                    # The peer never completed a TLS handshake: a bare port
                    # probe, a plaintext request (the D4 acceptance sends one
                    # on purpose), or a client that fails certificate
                    # verification. Those connections are refused, which is
                    # the wanted outcome; they are not handler failures, and
                    # treating them as such used to kill the peer before the
                    # collective link teardown. A peer that completes the
                    # handshake and then misbehaves still raises below.
                    continue
                with tls_socket:
                    peer_role = _peer_role(
                        tls_socket,
                        self.identity.allowed_peer_roles,
                    )
                    with TLSFrameChannel(
                        tls_socket,
                        peer_role=peer_role,
                    ) as channel:
                        self.handler(channel)
            except TLSChannelClosed:
                # The client hung up between frames: normal for this
                # one-connection-per-request transport, not a handler failure.
                continue
            except BaseException as exc:
                self._record_error(exc)
            finally:
                with suppress(OSError):
                    raw_socket.close()

    def start(self) -> "TLSFrameServer":
        if self._thread is not None:
            raise TLSChannelError("TLS server has already started")
        self._thread = threading.Thread(
            target=self._run,
            name=f"a122-tls-{self.identity.role}",
            daemon=True,
        )
        self._thread.start()
        return self

    def wait(self, timeout_seconds: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout_seconds)
        with self._error_lock:
            errors = list(self._errors)
        if errors:
            raise TLSChannelError(f"TLS server handler failed: {errors[0]}")

    def close(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._listener.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "TLSFrameServer":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


__all__ = [
    "MAX_FRAME_BYTES",
    "TLSChannelClosed",
    "TLSChannelError",
    "TLSFrameChannel",
    "TLSFrameServer",
    "TLSIdentity",
]

from __future__ import annotations

import socket
import ssl

import pytest

from infra.local_pki import LocalPKI
from mpc.spu_backend.transport import (
    TLSChannelClosed,
    TLSChannelError,
    TLSFrameChannel,
    TLSFrameServer,
)


def test_real_local_tls13_three_role_identity_and_frames() -> None:
    pki = LocalPKI()
    p0 = pki.identity("P0", allowed_peer_roles=("P1",))
    p1 = pki.identity("P1", allowed_peer_roles=("P0",))

    with TLSFrameServer(
        identity=p1,
        handler=lambda channel: (
            channel.send_frame(channel.receive_frame() + b":P1")
        ),
    ) as server:
        with TLSFrameChannel.connect(
            host="127.0.0.1",
            port=server.address[1],
            identity=p0,
            peer_role="P1",
        ) as channel:
            assert channel.tls_version == "TLSv1.3"
            assert channel.peer_role == "P1"
            channel.send_frame(b"request")
            assert channel.receive_frame() == b"request:P1"
        server.close()
        server.wait(timeout_seconds=1.0)


def test_local_tls_rejects_wrong_role_and_untrusted_ca() -> None:
    first_pki = LocalPKI()
    p1 = first_pki.identity("P1", allowed_peer_roles=("P0",))
    p2 = first_pki.identity("P2", allowed_peer_roles=("P0",))

    with TLSFrameServer(
        identity=p1,
        handler=lambda channel: channel.send_frame(b"unexpected"),
    ) as server:
        with pytest.raises(TLSChannelError, match="not allowed"):
            TLSFrameChannel.connect(
                host="127.0.0.1",
                port=server.address[1],
                identity=p2,
                peer_role="P0",
            )
        server.close()

    second_pki = LocalPKI()
    untrusted = second_pki.identity("P0", allowed_peer_roles=("P1",))
    with TLSFrameServer(
        identity=p1,
        handler=lambda channel: channel.send_frame(b"unexpected"),
    ) as server:
        with pytest.raises((ssl.SSLError, TLSChannelError)):
            TLSFrameChannel.connect(
                host="127.0.0.1",
                port=server.address[1],
                identity=untrusted,
                peer_role="P1",
            )
        server.close()


def test_a_hangup_between_frames_is_not_a_handler_failure() -> None:
    """The D4 share channel opens one connection per request.

    P0 closes each connection right after the reply, so the server handler
    always sees an end-of-stream between frames. That close used to be recorded
    as a handler failure, which made P1/P2 abort before the collective link
    teardown and left P0 waiting on a barrier that could never complete.
    """
    pki = LocalPKI()
    p0 = pki.identity("P0", allowed_peer_roles=("P1",))
    p1 = pki.identity("P1", allowed_peer_roles=("P0",))

    def handler(channel: TLSFrameChannel) -> None:
        while True:
            try:
                request = channel.receive_frame()
            except TLSChannelClosed:
                return
            channel.send_frame(request + b":P1")

    with TLSFrameServer(identity=p1, handler=handler) as server:
        for request in (b"ping", b"run"):
            with TLSFrameChannel.connect(
                host="127.0.0.1",
                port=server.address[1],
                identity=p0,
                peer_role="P1",
            ) as channel:
                channel.send_frame(request)
                assert channel.receive_frame() == request + b":P1"
        server.close()
        server.wait(timeout_seconds=2.0)


def test_a_bare_port_probe_does_not_fail_the_tls_server() -> None:
    """P0 waits for a peer by opening a TCP connection and closing it.

    That probe aborts the TLS handshake, which used to be recorded as a
    handler failure and made the peer exit before the link teardown.
    """
    pki = LocalPKI()
    p1 = pki.identity("P1", allowed_peer_roles=("P0",))
    p0 = pki.identity("P0", allowed_peer_roles=("P1",))

    def handler(channel: TLSFrameChannel) -> None:
        channel.send_frame(b"served")

    with TLSFrameServer(identity=p1, handler=handler) as server:
        for _ in range(3):
            probe = socket.create_connection(("127.0.0.1", server.address[1]), timeout=5.0)
            probe.close()
        with TLSFrameChannel.connect(
            host="127.0.0.1",
            port=server.address[1],
            identity=p0,
            peer_role="P1",
        ) as channel:
            assert channel.receive_frame() == b"served"
        server.close()
        server.wait(timeout_seconds=2.0)

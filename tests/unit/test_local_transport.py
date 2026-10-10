from __future__ import annotations

import ssl

import pytest

from infra.local_pki import LocalPKI
from mpc.spu_backend.transport import (
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

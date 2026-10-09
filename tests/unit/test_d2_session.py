from __future__ import annotations

import datetime as dt

import pytest

from crypto.certificates import (
    CertificateExpired,
    CertificateForgery,
    CertificateRevoked,
    SM2CertificateAuthority,
)
from crypto.frame import (
    FrameRejected,
    FrameAAD,
    ReplayRejected,
    SecureSession,
    SessionClosed,
    request_digest,
)
from crypto.handshake import (
    ClientHandshake,
    HandshakeBindings,
    HandshakeRejected,
    NodeHandshake,
)
from crypto.sm2 import SM2KeyPair


NOW = dt.datetime(2026, 10, 9, 8, 0, tzinfo=dt.timezone.utc)
RELEASE_ID = "a122-test-v1"
MODEL_VERSION = "tiny-decoder-v1"
MODEL_HASH = "31" * 32
PRECISION_HASH = "42" * 32


def make_bindings(role: str, *, session_byte: int = 1) -> HandshakeBindings:
    return HandshakeBindings(
        session_id=bytes([session_byte]).hex() * 32,
        node_role=role,
        release_id=RELEASE_ID,
        model_version=MODEL_VERSION,
        model_manifest_hash=MODEL_HASH,
        precision_plan_hash=PRECISION_HASH,
        share_epoch=7,
    )


def establish(
    role: str,
    *,
    now: dt.datetime = NOW,
    authority: SM2CertificateAuthority | None = None,
    session_byte: int = 1,
) -> tuple[SM2CertificateAuthority, SecureSession, SecureSession]:
    authority = authority or SM2CertificateAuthority(SM2KeyPair.generate())
    bindings = make_bindings(role, session_byte=session_byte)

    client_identity = SM2KeyPair.generate()
    client_ephemeral = SM2KeyPair.generate()
    client_certificate = authority.issue(
        role="C",
        release_id=RELEASE_ID,
        public_key=client_identity.public_key,
        now=now,
        ttl=dt.timedelta(hours=1),
    )
    node_identity = SM2KeyPair.generate()
    node_ephemeral = SM2KeyPair.generate()
    node_certificate = authority.issue(
        role=role,
        release_id=RELEASE_ID,
        public_key=node_identity.public_key,
        now=now,
        ttl=dt.timedelta(hours=1),
    )

    client = ClientHandshake(
        bindings=bindings,
        identity_key=client_identity,
        ephemeral_key=client_ephemeral,
        certificate=client_certificate,
        authority=authority,
    )
    node = NodeHandshake(
        bindings=bindings,
        identity_key=node_identity,
        ephemeral_key=node_ephemeral,
        certificate=node_certificate,
        authority=authority,
    )
    client_hello = client.create_client_hello()
    server_hello = node.receive_client_hello(client_hello, now=now)
    finished = client.receive_server_hello(server_hello, now=now)
    finished_ack, node_keys = node.receive_finished(finished)
    client_keys = client.receive_finished_ack(finished_ack)
    assert client.state == node.state == "established"
    assert client_keys == node_keys
    assert client_keys.c2p.key != client_keys.p2c.key

    client_session = SecureSession(
        keys=client_keys,
        local_role="C",
        peer_role=role,
    )
    node_session = SecureSession(
        keys=node_keys,
        local_role=role,
        peer_role="C",
    )
    return authority, client_session, node_session


def test_three_node_sessions_establish_and_encrypt() -> None:
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    for index, role in enumerate(("P0", "P1", "P2"), start=1):
        _, client, node = establish(
            role,
            authority=authority,
            session_byte=index,
        )
        payload = f"private-share-{role}".encode("ascii")
        frame = client.send(
            payload,
            message_type="Request",
            request_hash=request_digest(payload),
        )
        assert node.receive(frame) == payload


def test_expired_and_forged_node_certificates_are_rejected() -> None:
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    bindings = make_bindings("P0")
    client_identity = SM2KeyPair.generate()
    client_ephemeral = SM2KeyPair.generate()
    client_certificate = authority.issue(
        role="C",
        release_id=RELEASE_ID,
        public_key=client_identity.public_key,
        now=NOW,
        ttl=dt.timedelta(hours=2),
    )
    node_identity = SM2KeyPair.generate()
    expired_certificate = authority.issue(
        role="P0",
        release_id=RELEASE_ID,
        public_key=node_identity.public_key,
        now=NOW,
        ttl=dt.timedelta(minutes=1),
    )
    client = ClientHandshake(
        bindings=bindings,
        identity_key=client_identity,
        ephemeral_key=client_ephemeral,
        certificate=client_certificate,
        authority=authority,
    )
    node = NodeHandshake(
        bindings=bindings,
        identity_key=node_identity,
        ephemeral_key=SM2KeyPair.generate(),
        certificate=expired_certificate,
        authority=authority,
    )
    client_hello = client.create_client_hello()
    expired_at = NOW + dt.timedelta(minutes=2)
    server_hello = node.receive_client_hello(client_hello, now=expired_at)
    with pytest.raises(CertificateExpired):
        client.receive_server_hello(server_hello, now=expired_at)

    other_authority = SM2CertificateAuthority(SM2KeyPair.generate())
    forged_certificate = other_authority.issue(
        role="P0",
        release_id=RELEASE_ID,
        public_key=node_identity.public_key,
        now=NOW,
        ttl=dt.timedelta(hours=1),
    )
    with pytest.raises(CertificateForgery):
        authority.verify(
            forged_certificate,
            now=NOW,
            expected_role="P0",
            expected_release_id=RELEASE_ID,
        )


def test_revoked_certificate_is_rejected() -> None:
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    identity = SM2KeyPair.generate()
    certificate = authority.issue(
        role="P2",
        release_id=RELEASE_ID,
        public_key=identity.public_key,
        now=NOW,
        ttl=dt.timedelta(hours=1),
    )
    authority.revoke(certificate.serial_number)
    with pytest.raises(CertificateRevoked):
        authority.verify(
            certificate,
            now=NOW,
            expected_role="P2",
            expected_release_id=RELEASE_ID,
        )


def test_handshake_rejects_tampered_finished_and_bindings() -> None:
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    bindings = make_bindings("P1")
    client_identity = SM2KeyPair.generate()
    client_certificate = authority.issue(
        role="C",
        release_id=RELEASE_ID,
        public_key=client_identity.public_key,
        now=NOW,
        ttl=dt.timedelta(hours=1),
    )
    node_identity = SM2KeyPair.generate()
    node_certificate = authority.issue(
        role="P1",
        release_id=RELEASE_ID,
        public_key=node_identity.public_key,
        now=NOW,
        ttl=dt.timedelta(hours=1),
    )
    client = ClientHandshake(
        bindings=bindings,
        identity_key=client_identity,
        ephemeral_key=SM2KeyPair.generate(),
        certificate=client_certificate,
        authority=authority,
    )
    node = NodeHandshake(
        bindings=bindings,
        identity_key=node_identity,
        ephemeral_key=SM2KeyPair.generate(),
        certificate=node_certificate,
        authority=authority,
    )
    client_hello = client.create_client_hello()
    server_hello = node.receive_client_hello(client_hello, now=NOW)
    finished = client.receive_server_hello(server_hello, now=NOW)
    tampered = dict(finished)
    tampered["verify_data"] = "00" * 32
    with pytest.raises(HandshakeRejected, match="verify_data"):
        node.receive_finished(tampered)


def test_frame_rejects_tamper_replay_gap_cross_session_and_cross_model() -> None:
    authority = SM2CertificateAuthority(SM2KeyPair.generate())
    _, client_a, node_a = establish(
        "P0",
        authority=authority,
        session_byte=1,
    )
    _, client_b, _ = establish(
        "P1",
        authority=authority,
        session_byte=2,
    )

    payload = b"first"
    first = client_a.send(
        payload,
        message_type="Request",
        request_hash=request_digest(payload),
    )
    with pytest.raises(FrameRejected, match="session"):
        node_a.receive(client_b.send(
            b"other-session",
            message_type="Request",
            request_hash=request_digest(b"other-session"),
        ))
    assert node_a.receive(first) == payload

    with pytest.raises(ReplayRejected):
        node_a.receive(first)

    second = client_a.send(
        b"second",
        message_type="Request",
        request_hash=request_digest(b"second"),
    )
    third = client_a.send(
        b"third",
        message_type="Request",
        request_hash=request_digest(b"third"),
    )
    with pytest.raises(ReplayRejected):
        node_a.receive(third)
    assert node_a.receive(second) == b"second"
    assert node_a.receive(third) == b"third"

    fourth = client_a.send(
        b"fourth",
        message_type="Result",
        request_hash=request_digest(b"fourth"),
    )
    tampered_aad = FrameAAD(
        **{
            **fourth.aad.to_dict(),
            "request_hash": "99" * 32,
        }
    )
    with pytest.raises(FrameRejected, match="authentication"):
        node_a.receive(
            type(fourth)(
                aad=tampered_aad,
                ciphertext=fourth.ciphertext,
                tag=fourth.tag,
            )
        )

    cross_model = FrameAAD(
        **{
            **fourth.aad.to_dict(),
            "model_manifest_hash": "88" * 32,
        }
    )
    with pytest.raises(FrameRejected, match="model"):
        node_a.receive(
            type(fourth)(
                aad=cross_model,
                ciphertext=fourth.ciphertext,
                tag=fourth.tag,
            )
        )


def test_close_frame_transitions_both_sides_and_blocks_later_traffic() -> None:
    _, client, node = establish("P2")
    close_frame = client.close(b"done")
    assert client.closed
    assert node.receive(close_frame) == b"done"
    assert node.closed
    with pytest.raises(SessionClosed):
        client.send(
            b"late",
            message_type="Request",
            request_hash=request_digest(b"late"),
        )
    with pytest.raises(SessionClosed):
        node.receive(close_frame)

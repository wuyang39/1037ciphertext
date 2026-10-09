from __future__ import annotations

import pytest

from client.result import ResultRejected, reconstruct_result_frames
from client.session_runtime import NodeSessionRuntime
from crypto.frame import SessionClosed, request_digest
from crypto.handshake import HandshakeBindings
from crypto.sm2 import SM2KeyPair
from kas.models import IssueJobTicketRequest
from kas.tickets import JobTicketLedger
from mpc.secure_ops.kv_cache import SecureKVCache
from mpc.secure_ops.rss import RSSContext
from tests.unit.test_d2_session import NOW, establish, make_bindings


MODEL_HASH = "31" * 32
PLAN_HASH = "42" * 32


def test_three_node_runtime_results_bind_and_reconstruct() -> None:
    authority = __import__(
        "crypto.certificates", fromlist=["SM2CertificateAuthority"]
    ).SM2CertificateAuthority(SM2KeyPair.generate())
    kas_key = SM2KeyPair.generate()
    client_ephemeral = SM2KeyPair.generate()
    runtimes = []
    client_sessions = []
    frames = []
    for index, role in enumerate(("P0", "P1", "P2"), start=1):
        bindings = make_bindings(role, session_byte=1)
        _, client_session, node_session = establish(
            role,
            authority=authority,
            session_byte=1,
        )
        ticket = JobTicketLedger(signing_key=kas_key, clock=lambda: NOW).issue(
            IssueJobTicketRequest(
                session_id=bindings.session_id,
                node_role=role,
                release_id="a122-test-v1",
                model_manifest_hash=bindings.model_manifest_hash,
                precision_plan_hash=bindings.precision_plan_hash,
                share_epoch=bindings.share_epoch,
                length_bound=128,
                max_new_tokens=2,
                client_ephemeral_pub=client_ephemeral.public_key,
            )
        )
        node_identity = SM2KeyPair.generate()
        node_ephemeral = SM2KeyPair.generate()
        runtime = NodeSessionRuntime(
            session=node_session,
            ticket=ticket,
            kas_public_key=kas_key.public_key,
            node_identity=node_identity,
            node_ephemeral=node_ephemeral,
            client_ephemeral_pub=client_ephemeral.public_key,
            graph=lambda payload, role=role: payload + role.encode("ascii"),
            clock=lambda: NOW,
        )
        payload = b'{"prompt_share":"' + role.encode("ascii") + b'"}'
        shared_request_hash = request_digest(b"shared-runtime-request")
        request = client_session.send(
            payload,
            message_type="Request",
            request_hash=shared_request_hash,
        )
        assert runtime.receive(request) == payload
        output_share, result = runtime.execute(payload)
        assert output_share == payload + role.encode("ascii")
        frames.append(result)
        runtimes.append(runtime)
        client_sessions.append(client_session)

    shares = reconstruct_result_frames(
        frames,
        expected_session_id=make_bindings("P0", session_byte=1).session_id,
        expected_model_manifest_hash=MODEL_HASH,
        expected_precision_plan_hash=PLAN_HASH,
        expected_share_epoch=7,
        expected_request_hash=frames[0].request_hash,
        expected_decode_step=1,
        node_public_keys={
            frame.node_role: runtimes[index].node_identity.public_key
            for index, frame in enumerate(frames)
        },
        client_ephemeral=client_ephemeral,
    )
    assert len(shares) == 3
    assert shares[0].startswith(b'{"prompt_share":"P0"}')

    tampered = frames[0].to_dict()
    tampered["decode_step"] = 2
    with pytest.raises(ResultRejected):
        reconstruct_result_frames(
            [type(frames[0]).from_dict(tampered), frames[1], frames[2]],
            expected_session_id=make_bindings("P0", session_byte=1).session_id,
            expected_model_manifest_hash=MODEL_HASH,
            expected_precision_plan_hash=PLAN_HASH,
            expected_share_epoch=7,
            expected_request_hash=frames[0].request_hash,
            expected_decode_step=1,
            node_public_keys={
                frame.node_role: runtimes[index].node_identity.public_key
                for index, frame in enumerate(frames)
            },
            client_ephemeral=client_ephemeral,
        )

    close = runtimes[0].close()
    with pytest.raises(SessionClosed):
        runtimes[0].receive(close)


def test_kv_cache_is_session_local_and_wipes_share_storage() -> None:
    context = RSSContext(ring_bits=64, seed=13)
    key = context.share([[1, 2]])
    value = context.share([[3, 4]])
    cache = SecureKVCache(max_layers=2, max_tokens=4)
    cache.append(layer=0, key=key, value=value)
    assert len(cache.layer(0)) == 1
    original_shares = tuple(tuple(share) for share in key.shares)
    cache.wipe()
    assert cache.closed
    assert cache.wipe_count == 1
    cache.assert_empty()
    assert key.shares != original_shares
    with pytest.raises(Exception):
        cache.layer(0)

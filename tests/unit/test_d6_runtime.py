from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

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
REPO_ROOT = Path(__file__).resolve().parents[2]


def test_the_node_import_chain_needs_no_framework() -> None:
    """The D6 node runs in an enclave venv that has no torch.

    It reaches for ``mpc.secure_ops.kv_cache``, whose package pulls in the
    fixed-point adapter, which pulls in ``model``. Blocking ``torch`` in a
    fresh interpreter is the cheapest way to keep that chain honest, because
    on an operator machine with torch installed the mistake is invisible.
    """
    code = (
        "import sys\n"
        "sys.modules['torch'] = None\n"
        "from mpc.secure_ops.kv_cache import SecureKVCache\n"
        "from mpc.secure_ops import FixedPointAdapter\n"
        "import model\n"
        "assert callable(model.add_fixed)\n"
        "print('torch-free')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert result.returncode == 0, result.stderr
    assert "torch-free" in result.stdout


def test_the_decoder_is_resolved_on_first_use() -> None:
    import model

    assert "TinyDecoder" not in vars(model)
    assert "TinyDecoderConfig" not in vars(model)
    with pytest.raises(AttributeError):
        model.not_a_real_attribute


def test_the_node_module_binds_every_frame_type_it_uses() -> None:
    """The node's step and close branches decode an ``EncryptedFrame``.

    Those branches only run against a live client, so a missing import there
    stays invisible to the in-process flow test -- which builds its own
    channel -- and shows up as ``NameError`` on a real run instead.
    """
    import tee.enclave.d6_node as node
    from crypto.frame import EncryptedFrame

    assert node.EncryptedFrame is EncryptedFrame


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

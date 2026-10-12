from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from crypto.enclave_key import (
    EnclaveKeyError,
    decode_bundle,
    enclave_report_data,
    encode_bundle,
    open_bundle,
    protected_files_key,
    seal_bundle,
    storage_key_id,
    verify_enclave_report_data,
    worker_startup_digest,
)
from crypto.sm2 import SM2Error, SM2KeyPair, sm2_decrypt, sm2_encrypt
from kas.app import create_app
from kas.ca import CertificateAuthority
from kas.models import ChallengeRequest, SealedStorageKeyRequest
from kas.policy import PolicyRegistry, ReleaseManifest, VerifiedQuote
from kas.service import KASService
from tee.storage import StorageKey
from tee.worker import WorkerStartup


ROOT = Path(__file__).resolve().parents[2]
NOW = dt.datetime(2026, 10, 12, 9, 0, tzinfo=dt.timezone.utc)
MRENCLAVE = "ab" * 32
MRSIGNER = "cd" * 32
MODEL_VERSION = "gpt2-small-int8"
MODEL_MANIFEST_HASH = "11" * 32
PRECISION_PLAN_HASH = "22" * 32


def _load_enclave_worker():
    spec = importlib.util.spec_from_file_location(
        "a122_enclave_worker",
        ROOT / "tee" / "enclave" / "encfs_worker.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


enclave_worker = _load_enclave_worker()


def make_release(**overrides) -> ReleaseManifest:
    document = {
        "release_id": "a122-test-v1",
        "mrenclave": MRENCLAVE,
        "mrsigner": MRSIGNER,
        "min_isvsvn": 3,
        "debug_allowed": False,
        "spu_build_hash": "33" * 32,
        "model_version": MODEL_VERSION,
        "model_manifest_hash": MODEL_MANIFEST_HASH,
        "precision_plan_hash": PRECISION_PLAN_HASH,
        "expires_at": "2027-01-01T00:00:00Z",
    }
    document.update(overrides)
    return ReleaseManifest.from_dict(document)


def make_ca() -> CertificateAuthority:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A1-22 Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return CertificateAuthority(private_key, certificate)


class BoundVerifier:
    """A verifier whose REPORTDATA binds whatever the caller asks for."""

    def __init__(
        self,
        release_id: str,
        role: str,
        public_key: str,
        *,
        mrenclave: str = MRENCLAVE,
    ) -> None:
        self._release_id = release_id
        self._role = role
        self._public_key = public_key
        self.mrenclave = mrenclave
        self.nonce: bytes | None = None

    def verify(self, quote: bytes) -> VerifiedQuote:
        assert self.nonce is not None
        return VerifiedQuote(
            mrenclave=self.mrenclave,
            mrsigner=MRSIGNER,
            isvsvn=3,
            debug=False,
            report_data=enclave_report_data(
                public_key=self._public_key,
                role=self._role,
                release_id=self._release_id,
                nonce=self.nonce,
            ),
        )


def make_service(verifier) -> KASService:
    return KASService(
        quote_verifier=verifier,
        policy_registry=PolicyRegistry([make_release()]),
        certificate_authority=make_ca(),
        ticket_signing_key=SM2KeyPair.generate(),
        storage_key_master=bytes(range(32, 64)),
        clock=lambda: NOW,
    )


def seal_once(*, enclave_key: SM2KeyPair, **overrides):
    role = overrides.pop("role", "P0")
    release_id = overrides.pop("release_id", "a122-test-v1")
    share_epoch = overrides.pop("share_epoch", 4)
    purpose = overrides.pop("purpose", "model-store")
    verifier = BoundVerifier(release_id, role, enclave_key.public_key)
    service = make_service(verifier)
    challenge = service.issue_challenge(
        ChallengeRequest(role=role, release_id=release_id)
    )
    verifier.nonce = bytes.fromhex(challenge.nonce)
    request = SealedStorageKeyRequest(
        challenge_id=challenge.challenge_id,
        role=role,
        release_id=release_id,
        share_epoch=share_epoch,
        purpose=purpose,
        enclave_public_key=enclave_key.public_key,
        dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
    )
    return service, request


def enclave_args(**overrides) -> argparse.Namespace:
    document = {
        "role": "P0",
        "release_id": "a122-test-v1",
        "share_epoch": 4,
        "model_version": MODEL_VERSION,
        "model_manifest_hash": MODEL_MANIFEST_HASH,
        "precision_plan_hash": PRECISION_PLAN_HASH,
        "expected_key_id": "",
    }
    document.update(overrides)
    return argparse.Namespace(**document)


def test_sm2_encryption_round_trip_and_tamper_detection() -> None:
    key_pair = SM2KeyPair.generate()
    message = bytes(range(128))
    ciphertext = sm2_encrypt(key_pair.public_key, message)
    assert len(ciphertext) == len(message) + 96
    assert sm2_decrypt(key_pair.private_key, ciphertext) == message

    tampered = bytearray(ciphertext)
    tampered[100] ^= 0x5A
    with pytest.raises(SM2Error):
        sm2_decrypt(key_pair.private_key, bytes(tampered))

    other = SM2KeyPair.generate()
    with pytest.raises(SM2Error):
        sm2_decrypt(other.private_key, ciphertext)


def test_startup_digest_matches_the_worker_contract() -> None:
    startup = WorkerStartup(
        role="P0",
        release_id="a122-test-v1",
        model_version=MODEL_VERSION,
        model_manifest_hash=MODEL_MANIFEST_HASH,
        precision_plan_hash=PRECISION_PLAN_HASH,
        share_epoch=4,
        expected_storage_key_id="44" * 32,
    )
    assert startup.digest() == worker_startup_digest(
        role="P0",
        release_id="a122-test-v1",
        model_version=MODEL_VERSION,
        model_manifest_hash=MODEL_MANIFEST_HASH,
        precision_plan_hash=PRECISION_PLAN_HASH,
        share_epoch=4,
        expected_storage_key_id="44" * 32,
    )


def test_bundle_codec_rejects_mismatched_key_and_reserved_bytes() -> None:
    key = bytes(range(32))
    key_id = storage_key_id(key)
    bundle = encode_bundle(
        key_id=key_id,
        startup_hash="55" * 32,
        share_epoch=7,
        expires_at_unix=1_800_000_000,
        storage_key=key,
    )
    decoded = decode_bundle(bundle)
    assert decoded["key_id"] == key_id
    assert decoded["share_epoch"] == 7
    assert decoded["expires_at_unix"] == 1_800_000_000
    assert decoded["storage_key"] == key
    assert protected_files_key(key) == protected_files_key(bytes(key))
    assert len(protected_files_key(key)) == 16

    with pytest.raises(EnclaveKeyError):
        encode_bundle(
            key_id="66" * 32,
            startup_hash="55" * 32,
            share_epoch=7,
            expires_at_unix=1_800_000_000,
            storage_key=key,
        )

    reserved = bytearray(bundle)
    reserved[10] = 1
    with pytest.raises(EnclaveKeyError):
        decode_bundle(bytes(reserved))


def test_report_data_binding_rejects_other_nonce_and_key() -> None:
    key_pair = SM2KeyPair.generate()
    nonce = bytes(range(32))
    report_data = enclave_report_data(
        public_key=key_pair.public_key,
        role="P0",
        release_id="a122-test-v1",
        nonce=nonce,
    )
    assert verify_enclave_report_data(
        report_data,
        public_key=key_pair.public_key,
        role="P0",
        release_id="a122-test-v1",
        nonce=nonce,
    )
    assert not verify_enclave_report_data(
        report_data,
        public_key=SM2KeyPair.generate().public_key,
        role="P0",
        release_id="a122-test-v1",
        nonce=nonce,
    )
    assert not verify_enclave_report_data(
        report_data,
        public_key=key_pair.public_key,
        role="P0",
        release_id="a122-test-v1",
        nonce=bytes(reversed(nonce)),
    )


def test_kas_sealed_release_opens_only_inside_the_enclave() -> None:
    enclave_key = SM2KeyPair.generate()
    service, request = seal_once(enclave_key=enclave_key)
    response = service.seal_storage_key(request)

    sealed = bytes.fromhex(response.sealed_bundle_hex)
    assert response.bundle_bytes == 128
    fields = enclave_worker._Fields()
    bundle = enclave_worker._check_bundle(
        sealed=sealed,
        private_key=enclave_key.private_key,
        args=enclave_args(expected_key_id=response.key_id),
        fields=fields,
        now_unix=int(NOW.timestamp()) + 60,
    )
    assert bundle["key_id"] == response.key_id
    assert bundle["startup_hash"] == response.startup_hash
    assert bundle["share_epoch"] == 4
    assert response.expires_at == NOW + dt.timedelta(hours=1)

    # A different enclave key cannot open the same sealed bundle.
    with pytest.raises(EnclaveKeyError):
        open_bundle(SM2KeyPair.generate().private_key, sealed)

    # The sealed key is a working StorageKey for the Worker state machine.
    storage_key = StorageKey(
        key_id=response.key_id,
        key=bundle["storage_key"],
    )
    assert storage_key.key_id == response.key_id


def test_enclave_checks_reject_epoch_and_startup_mismatch() -> None:
    enclave_key = SM2KeyPair.generate()
    service, request = seal_once(enclave_key=enclave_key)
    response = service.seal_storage_key(request)
    sealed = bytes.fromhex(response.sealed_bundle_hex)

    with pytest.raises(enclave_worker.EnclaveWorkerRejected):
        enclave_worker._check_bundle(
            sealed=sealed,
            private_key=enclave_key.private_key,
            args=enclave_args(share_epoch=5),
            fields=enclave_worker._Fields(),
            now_unix=int(NOW.timestamp()) + 60,
        )

    with pytest.raises(enclave_worker.EnclaveWorkerRejected):
        enclave_worker._check_bundle(
            sealed=sealed,
            private_key=enclave_key.private_key,
            args=enclave_args(model_version="tiny-decoder"),
            fields=enclave_worker._Fields(),
            now_unix=int(NOW.timestamp()) + 60,
        )

    tampered = bytearray(sealed)
    tampered[-1] ^= 0x01
    with pytest.raises(enclave_worker.EnclaveWorkerRejected):
        enclave_worker._check_bundle(
            sealed=bytes(tampered),
            private_key=enclave_key.private_key,
            args=enclave_args(),
            fields=enclave_worker._Fields(),
            now_unix=int(NOW.timestamp()) + 60,
        )


def test_kas_rejects_replayed_challenge_and_second_seal() -> None:
    from kas.errors import ChallengeNotFound, StorageKeyRejected

    enclave_key = SM2KeyPair.generate()
    verifier = BoundVerifier("a122-test-v1", "P0", enclave_key.public_key)
    service = make_service(verifier)

    requests = []
    nonces = []
    for _ in range(2):
        challenge = service.issue_challenge(
            ChallengeRequest(role="P0", release_id="a122-test-v1")
        )
        nonces.append(bytes.fromhex(challenge.nonce))
        requests.append(
            SealedStorageKeyRequest(
                challenge_id=challenge.challenge_id,
                role="P0",
                release_id="a122-test-v1",
                share_epoch=4,
                purpose="model-store",
                enclave_public_key=enclave_key.public_key,
                dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
            )
        )

    verifier.nonce = nonces[0]
    service.seal_storage_key(requests[0])

    # A fresh challenge cannot unlock a second key release for the same epoch.
    verifier.nonce = nonces[1]
    with pytest.raises(StorageKeyRejected):
        service.seal_storage_key(requests[1])

    # A consumed challenge cannot be used again, even with a new key.
    verifier.nonce = nonces[0]
    with pytest.raises(ChallengeNotFound):
        service.seal_storage_key(requests[0])

    with pytest.raises(ChallengeNotFound):
        service.seal_storage_key(
            requests[1].model_copy(update={"challenge_id": "unknown"})
        )


def test_kas_policy_rejects_wrong_measurement() -> None:
    enclave_key = SM2KeyPair.generate()
    verifier = BoundVerifier(
        "a122-test-v1",
        "P0",
        enclave_key.public_key,
        mrenclave="99" * 32,
    )
    service = make_service(verifier)
    challenge = service.issue_challenge(
        ChallengeRequest(role="P0", release_id="a122-test-v1")
    )
    verifier.nonce = bytes.fromhex(challenge.nonce)

    request = SealedStorageKeyRequest(
        challenge_id=challenge.challenge_id,
        role="P0",
        release_id="a122-test-v1",
        share_epoch=4,
        purpose="model-store",
        enclave_public_key=enclave_key.public_key,
        dcap_quote_b64=base64.b64encode(b"test-quote").decode("ascii"),
    )
    with pytest.raises(Exception) as excinfo:
        service.seal_storage_key(request)
    assert "MRENCLAVE" in str(excinfo.value)


def test_kas_rejects_report_data_bound_to_another_key() -> None:
    enclave_key = SM2KeyPair.generate()
    service, request = seal_once(enclave_key=enclave_key)
    swapped = request.model_copy(
        update={"enclave_public_key": SM2KeyPair.generate().public_key}
    )
    from kas.errors import AttestationRejected

    with pytest.raises(AttestationRejected):
        service.seal_storage_key(swapped)


def test_sealed_release_is_exposed_over_http() -> None:
    enclave_key = SM2KeyPair.generate()
    service, request = seal_once(enclave_key=enclave_key)
    client = TestClient(create_app(service))
    response = client.post(
        "/v1/release-storage-key-sealed",
        json=request.model_dump(mode="json"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["bundle_bytes"] == 128
    assert len(body["sealed_bundle_hex"]) >= 256

    replay = client.post(
        "/v1/release-storage-key-sealed",
        json=request.model_dump(mode="json"),
    )
    assert replay.status_code == 404

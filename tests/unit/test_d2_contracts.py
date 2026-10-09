from __future__ import annotations

import pytest

from contracts import validate_contract
from kas.audit import AuditEvent


def test_audit_event_accepts_only_redacted_fields() -> None:
    event = AuditEvent(
        session_hash="11" * 32,
        ticket_id="22" * 16,
        release_id="a122-test-v1",
        measurement="33" * 32,
        result_code="OK",
        bytes=512,
        elapsed_ms=12.5,
    )
    assert event.to_dict() == {
        "session_hash": "11" * 32,
        "ticket_id": "22" * 16,
        "release_id": "a122-test-v1",
        "measurement": "33" * 32,
        "result_code": "OK",
        "bytes": 512,
        "elapsed_ms": 12.5,
    }
    validate_contract("audit_event", event.to_dict())


def test_audit_event_rejects_prompt_or_share_fields() -> None:
    value = {
        "session_hash": "11" * 32,
        "ticket_id": "22" * 16,
        "release_id": "a122-test-v1",
        "measurement": "33" * 32,
        "result_code": "OK",
        "bytes": 512,
        "elapsed_ms": 12.5,
        "prompt": "must not be logged",
    }
    with pytest.raises(ValueError, match="Additional"):
        validate_contract("audit_event", value)


def test_frame_aad_schema_rejects_extra_sensitive_fields() -> None:
    value = {
        "protocol_version": "a122-gm-session-v1",
        "session_id": "11" * 32,
        "epoch": 7,
        "counter": 1,
        "sender": "C",
        "receiver": "P0",
        "model_manifest_hash": "22" * 32,
        "request_hash": "33" * 32,
        "message_type": "Request",
        "prompt": "must not be authenticated as plaintext metadata",
    }
    with pytest.raises(ValueError, match="Additional"):
        validate_contract("business_frame_aad", value)

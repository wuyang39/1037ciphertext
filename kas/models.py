"""HTTP and service models for the minimum KAS API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


NodeRole = Literal["P0", "P1", "P2"]


class ProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class ChallengeRequest(ProtocolModel):
    role: NodeRole
    release_id: str = Field(min_length=3, max_length=128)


class ChallengeResponse(ProtocolModel):
    challenge_id: str
    nonce: str
    expires_at: datetime


class AttestRequest(ProtocolModel):
    challenge_id: str
    role: NodeRole
    release_id: str = Field(min_length=3, max_length=128)
    dcap_quote_b64: str = Field(min_length=1)
    csr_pem: str = Field(min_length=1)


class AttestationResponse(ProtocolModel):
    node_certificate_pem: str
    ca_bundle_pem: str
    lease_id: str
    expires_at: datetime


class IssueJobTicketRequest(ProtocolModel):
    session_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    node_role: NodeRole
    release_id: str = Field(min_length=3, max_length=128)
    model_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    precision_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    share_epoch: int = Field(ge=0)
    length_bound: int = Field(ge=1)
    max_new_tokens: int = Field(ge=1)
    client_ephemeral_pub: str = Field(pattern=r"^[0-9a-f]{128}$")


class JobTicketResponse(ProtocolModel):
    ticket_id: str
    session_id: str
    node_role: NodeRole
    release_id: str
    model_manifest_hash: str
    precision_plan_hash: str
    share_epoch: int
    length_bound: int
    max_new_tokens: int
    client_ephemeral_pub: str
    expiry: str = Field(min_length=20, max_length=64)
    counter: int
    KAS_signature: str


class TicketPublicKeyResponse(ProtocolModel):
    public_key: str


class ConsumeTicketRequest(ProtocolModel):
    ticket_id: str = Field(min_length=16, max_length=64)
    enclave_lease_id: str = Field(min_length=1)
    session_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    counter: int = Field(ge=1, le=4294967295)


class ConsumeTicketResponse(ProtocolModel):
    status: Literal["accepted"]

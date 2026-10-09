"""HTTP and service models for the minimum KAS API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


NodeRole = Literal["P0", "P1", "P2"]


class ChallengeRequest(BaseModel):
    role: NodeRole
    release_id: str = Field(min_length=3, max_length=128)


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_at: datetime


class AttestRequest(BaseModel):
    challenge_id: str
    role: NodeRole
    release_id: str = Field(min_length=3, max_length=128)
    dcap_quote_b64: str = Field(min_length=1)
    csr_pem: str = Field(min_length=1)


class AttestationResponse(BaseModel):
    node_certificate_pem: str
    ca_bundle_pem: str
    lease_id: str
    expires_at: datetime

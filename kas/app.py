"""FastAPI surface for the minimum KAS service."""

from __future__ import annotations

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from .errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
    LeaseRejected,
    PolicyRejected,
    TicketAlreadyConsumed,
    TicketBindingRejected,
    TicketExpired,
    TicketNotFound,
    StorageKeyRejected,
)
from .models import (
    AttestRequest,
    AttestationResponse,
    ChallengeRequest,
    ChallengeResponse,
    ConsumeTicketRequest,
    ConsumeTicketResponse,
    IssueJobTicketRequest,
    JobTicketResponse,
    ReleaseStorageKeyRequest,
    ReleaseStorageKeyResponse,
    TicketPublicKeyResponse,
)
from .service import KASService
from .settings import KASSettings, build_service


def create_app(service: KASService | None = None) -> FastAPI:
    """Create the KAS app, failing closed when production settings are absent."""
    kas = service if service is not None else build_service(KASSettings.from_env())
    app = FastAPI(title="A1-22 KAS", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/challenge",
        response_model=ChallengeResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def challenge(request: ChallengeRequest) -> ChallengeResponse:
        return kas.issue_challenge(request)

    @app.post("/v1/attest", response_model=AttestationResponse)
    def attest(request: AttestRequest) -> AttestationResponse:
        return kas.attest(request)

    @app.post("/v1/issue-job-ticket", response_model=JobTicketResponse)
    def issue_job_ticket(
        request: IssueJobTicketRequest,
    ) -> JobTicketResponse:
        return kas.issue_job_ticket(request)

    @app.post("/v1/consume-ticket", response_model=ConsumeTicketResponse)
    def consume_ticket(
        request: ConsumeTicketRequest,
    ) -> ConsumeTicketResponse:
        return kas.consume_ticket(request)

    @app.get("/v1/ticket-public-key", response_model=TicketPublicKeyResponse)
    def ticket_public_key() -> TicketPublicKeyResponse:
        return kas.ticket_public_key()

    @app.post(
        "/v1/release-storage-key",
        response_model=ReleaseStorageKeyResponse,
    )
    def release_storage_key(
        request: ReleaseStorageKeyRequest,
    ) -> ReleaseStorageKeyResponse:
        return kas.release_storage_key(request)

    @app.exception_handler(ChallengeNotFound)
    def challenge_not_found(_request, exc: ChallengeNotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ChallengeExpired)
    def challenge_expired(_request, exc: ChallengeExpired):
        return JSONResponse(status_code=410, content={"detail": str(exc)})

    @app.exception_handler(AttestationRejected)
    @app.exception_handler(PolicyRejected)
    @app.exception_handler(TicketBindingRejected)
    @app.exception_handler(LeaseRejected)
    def rejected(_request, exc: Exception):
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TicketNotFound)
    def ticket_not_found(_request, exc: TicketNotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(TicketExpired)
    def ticket_expired(_request, exc: TicketExpired):
        return JSONResponse(status_code=410, content={"detail": str(exc)})

    @app.exception_handler(TicketAlreadyConsumed)
    def ticket_consumed(_request, exc: TicketAlreadyConsumed):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(StorageKeyRejected)
    def storage_key_rejected(_request, exc: StorageKeyRejected):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    return app

"""FastAPI surface for the minimum KAS service."""

from __future__ import annotations

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from .errors import (
    AttestationRejected,
    ChallengeExpired,
    ChallengeNotFound,
    PolicyRejected,
)
from .models import (
    AttestRequest,
    AttestationResponse,
    ChallengeRequest,
    ChallengeResponse,
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

    @app.exception_handler(ChallengeNotFound)
    def challenge_not_found(_request, exc: ChallengeNotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ChallengeExpired)
    def challenge_expired(_request, exc: ChallengeExpired):
        return JSONResponse(status_code=410, content={"detail": str(exc)})

    @app.exception_handler(AttestationRejected)
    @app.exception_handler(PolicyRejected)
    def rejected(_request, exc: Exception):
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    return app

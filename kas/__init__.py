"""Key Authorization Service for attestation-gated enclaves."""

from .service import KASService, QuoteVerifier

__all__ = ["KASService", "QuoteVerifier"]

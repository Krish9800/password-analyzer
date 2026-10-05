"""Pydantic schemas for the REST API."""

from pydantic import BaseModel, Field

from password_analyzer.services.analyzer_service import MAX_PASSWORD_LENGTH


class AnalyzeRequest(BaseModel):
    """Request payload for password evaluation."""

    password: str = Field(
        default="",
        max_length=MAX_PASSWORD_LENGTH,
        description="Plaintext password to analyze. Never persisted or logged.",
    )


class HealthResponse(BaseModel):
    """Service health and privacy metadata."""

    status: str
    version: str
    persistence_policy: str

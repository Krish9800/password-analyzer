"""REST API endpoints for password analysis and health checks."""

from fastapi import APIRouter, HTTPException, status

import password_analyzer
from password_analyzer.api.schemas import AnalyzeRequest, HealthResponse
from password_analyzer.models.result import PasswordAnalysisResult
from password_analyzer.services.analyzer_service import PasswordAnalyzerService

router = APIRouter(prefix="/api/v1", tags=["Analysis"])
service = PasswordAnalyzerService()


@router.post(
    "/analyze",
    response_model=PasswordAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Evaluate password security attributes",
    description=(
        "Analyzes password entropy, character diversity, patterns, dictionary leaks, "
        "and offline crack time without persisting or transmitting credentials."
    ),
)
async def analyze_password_endpoint(payload: AnalyzeRequest) -> PasswordAnalysisResult:
    """Analyze submitted password locally."""
    try:
        return service.analyze(payload.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Service health and privacy policy check",
)
async def health_check() -> HealthResponse:
    """Return service health and security model assurances."""
    return HealthResponse(
        status="healthy",
        version=password_analyzer.__version__,
        persistence_policy="ZERO_STORAGE_LOCAL_IN_MEMORY",
    )

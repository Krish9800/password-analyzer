"""Security tests verifying that credentials are never leaked into logs, models, or outputs."""

import logging

from fastapi.testclient import TestClient

from password_analyzer.api.main import app
from password_analyzer.services.analyzer_service import PasswordAnalyzerService

client = TestClient(app)


def test_result_model_omits_raw_password() -> None:
    """Verifies that PasswordAnalysisResult model never stores the plaintext credential."""
    service = PasswordAnalyzerService()
    secret_canary = "CanaryTestCredential_987!@#"

    result = service.analyze(secret_canary)
    serialized = result.model_dump_json()

    # The raw password must never be stored in model attributes or serialized output
    assert secret_canary not in serialized
    assert not hasattr(result, "password")


def test_api_logging_never_captures_password(caplog) -> None:
    """Verifies that API request processing does not log submitted passwords."""
    secret_canary = "SuperSecretCanaryValue_XYZ789!"
    with caplog.at_level(logging.DEBUG):
        response = client.post("/api/v1/analyze", json={"password": secret_canary})

    assert response.status_code == 200

    # Ensure canary is absent from all log records
    for record in caplog.records:
        assert secret_canary not in record.message


def test_error_responses_omit_submitted_content() -> None:
    """Malformed or invalid requests should never echo the submitted input."""
    service = PasswordAnalyzerService()
    secret_canary = "OversizedSecretCanary_" + ("A" * 600)

    try:
        service.analyze(secret_canary)
    except ValueError as e:
        error_msg = str(e)
        assert secret_canary not in error_msg

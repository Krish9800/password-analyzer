"""Integration tests for the REST API and Dashboard."""

from fastapi.testclient import TestClient

from password_analyzer.api.main import app

client = TestClient(app)


def test_api_root_dashboard() -> None:
    """Dashboard HTML is served successfully at root."""
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Password Intelligence Analyzer" in res.text
    assert "ZERO PERSISTENCE" in res.text


def test_api_health_endpoints() -> None:
    """Health endpoints provide version and privacy guarantees."""
    res_v1 = client.get("/api/v1/health")
    assert res_v1.status_code == 200
    data_v1 = res_v1.json()
    assert data_v1["status"] == "healthy"
    assert data_v1["persistence_policy"] == "ZERO_STORAGE_LOCAL_IN_MEMORY"

    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "healthy"


def test_api_analyze_valid_credential() -> None:
    """POST /api/v1/analyze returns complete intelligence report."""
    test_pwd = "Secure#Password#2026!"
    res = client.post("/api/v1/analyze", json={"password": test_pwd})
    assert res.status_code == 200
    data = res.json()
    assert "score_breakdown" in data
    assert "entropy_analysis" in data
    assert "pattern_findings" in data
    assert "offline_estimates" in data
    assert "recommendations" in data
    assert data["score_breakdown"]["final_score"] > 0
    # Crucial security guarantee: password is not returned in response
    assert test_pwd not in res.text


def test_api_analyze_empty_input() -> None:
    """Empty password returns valid report with 0 score."""
    res = client.post("/api/v1/analyze", json={"password": ""})
    assert res.status_code == 200
    data = res.json()
    assert data["score_breakdown"]["final_score"] == 0


def test_api_analyze_oversized_input() -> None:
    """Exceeding maximum allowed length triggers 422 Unprocessable Entity."""
    oversized = "P" * 600
    res = client.post("/api/v1/analyze", json={"password": oversized})
    assert res.status_code == 422


def test_api_defensive_security_headers() -> None:
    """API responses include strict privacy and security headers."""
    res = client.get("/api/v1/health")
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert "no-store" in res.headers["cache-control"]

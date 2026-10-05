"""Security tests verifying ReDoS and Algorithmic Complexity DoS mitigations."""

import time

from password_analyzer.services.analyzer_service import PasswordAnalyzerService

service = PasswordAnalyzerService()


def test_linear_time_pathological_repetition() -> None:
    """Verifies that pathological repeated patterns execute within milliseconds without ReDoS."""
    pathological_input = "a" * 512
    start_time = time.perf_counter()
    res = service.analyze(pathological_input)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 0.25  # Must complete in well under 250 milliseconds
    assert res.score_breakdown.final_score < 20


def test_linear_time_pathological_sequences() -> None:
    """Verifies that repetitive sequences execute in linear time."""
    pathological_input = "0123456789" * 51  # 510 chars
    start_time = time.perf_counter()
    res = service.analyze(pathological_input)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 0.25
    assert res.charset_analysis.total_length == 510

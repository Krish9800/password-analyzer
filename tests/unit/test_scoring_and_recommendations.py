"""Unit tests for Phase 3 scoring, recommendations, and master service."""

import pytest

from password_analyzer.models.result import StrengthCategory
from password_analyzer.services.analyzer_service import (
    MAX_PASSWORD_LENGTH,
    PasswordAnalyzerService,
)


@pytest.fixture
def service() -> PasswordAnalyzerService:
    """Fixture providing PasswordAnalyzerService instance."""
    return PasswordAnalyzerService()


def test_service_empty_input(service: PasswordAnalyzerService) -> None:
    """Empty string produces 0 score and VERY_WEAK classification."""
    res = service.analyze("")
    assert res.score_breakdown.final_score == 0
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK
    assert res.entropy_analysis.effective_entropy_bits == 0.0
    assert any("Empty Password" in d.name for d in res.score_breakdown.deductions)


def test_service_common_breached_password(service: PasswordAnalyzerService) -> None:
    """Top common password receives low score and critical recommendation."""
    res = service.analyze("123456")
    assert res.score_breakdown.final_score < 20
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK
    assert any("Common Breached Password" in d.name for d in res.score_breakdown.deductions)
    assert any(r.id == "REC-BREACH-01" for r in res.recommendations)


def test_service_leetspeak_password(service: PasswordAnalyzerService) -> None:
    """Leetspeak mutation receives itemized deduction."""
    res = service.analyze("P@ssw0rd123!")
    assert any("Leetspeak" in d.name for d in res.score_breakdown.deductions)
    assert any(r.id == "REC-LEET-01" for r in res.recommendations)


def test_service_strong_passphrase(service: PasswordAnalyzerService) -> None:
    """Long multi-word passphrase receives length bonuses."""
    res = service.analyze("correct-horse-battery-staple-2026")
    assert res.score_breakdown.final_score >= 70
    assert res.score_breakdown.category in (
        StrengthCategory.STRONG,
        StrengthCategory.VERY_STRONG,
    )
    assert any("Passphrase Scale" in b.name for b in res.score_breakdown.bonuses)


def test_service_high_entropy_random(service: PasswordAnalyzerService) -> None:
    """Diverse randomized password achieves top score."""
    res = service.analyze("kX9#mQ2$vL8!zW1&pY")
    assert res.score_breakdown.final_score >= 80
    assert res.score_breakdown.category == StrengthCategory.VERY_STRONG
    assert res.entropy_analysis.effective_entropy_bits > 70.0
    assert len(res.pattern_findings) == 0


def test_service_input_length_boundary(service: PasswordAnalyzerService) -> None:
    """Inputs exceeding maximum allowed length raise ValueError."""
    oversized = "A" * (MAX_PASSWORD_LENGTH + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        service.analyze(oversized)


def test_service_explainability_ledger(service: PasswordAnalyzerService) -> None:
    """Every score adjustment includes name, points, and human-readable reason."""
    res = service.analyze("weak123")
    assert len(res.score_breakdown.deductions) > 0
    for ded in res.score_breakdown.deductions:
        assert ded.name
        assert ded.points > 0.0
        assert ded.reason

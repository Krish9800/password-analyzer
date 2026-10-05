"""Unit tests for boundary conditions, Unicode, spaces, and edge cases."""

from password_analyzer.models.analysis import PatternType
from password_analyzer.models.result import StrengthCategory
from password_analyzer.services.analyzer_service import PasswordAnalyzerService

service = PasswordAnalyzerService()


def test_edge_case_single_character() -> None:
    """Single character password receives very weak score."""
    res = service.analyze("a")
    assert res.charset_analysis.total_length == 1
    assert res.score_breakdown.final_score < 10
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK


def test_edge_case_two_characters() -> None:
    """Two character password receives very weak score."""
    res = service.analyze("1a")
    assert res.charset_analysis.total_length == 2
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK


def test_edge_case_pure_whitespace() -> None:
    """Password made purely of spaces."""
    res = service.analyze("     ")
    assert res.charset_analysis.whitespace_count == 5
    assert res.charset_analysis.lowercase_count == 0
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK


def test_edge_case_mixed_spaces_and_words() -> None:
    """Passphrase containing natural inter-word spacing."""
    res = service.analyze("correct horse battery staple")
    assert res.charset_analysis.whitespace_count == 3
    assert res.charset_analysis.total_length == 28
    assert res.score_breakdown.final_score >= 60


def test_edge_case_unicode_multilingual() -> None:
    """Non-ASCII scripts (Cyrillic, Devanagari, Emoji)."""
    # Synthetic multi-lingual string
    sample = "пароль-सुरक्षा-🔒🔑🛡️"
    res = service.analyze(sample)
    assert res.charset_analysis.unicode_count > 0
    assert res.charset_analysis.total_length > 10
    assert any("Non-ASCII Diversity" in b.name for b in res.score_breakdown.bonuses)


def test_edge_case_long_password_boundary() -> None:
    """Accepts length up to 512 characters without slowdown."""
    # Synthetic long non-repetitive pseudo-random phrase
    words = [
        "quantum",
        "vector",
        "matrix",
        "cipher",
        "shield",
        "nexus",
        "orbit",
        "pulse",
        "beacon",
        "flux",
        "aurora",
        "zenith",
        "vortex",
        "helix",
        "prism",
        "stellar",
    ]
    long_pwd = "-".join(words * 6)[:512]
    assert len(long_pwd) == 512
    res = service.analyze(long_pwd)
    assert res.charset_analysis.total_length == 512
    assert res.score_breakdown.final_score >= 60
    assert res.score_breakdown.category in (
        StrengthCategory.STRONG,
        StrengthCategory.VERY_STRONG,
    )


def test_edge_case_all_symbols() -> None:
    """Password consisting entirely of symbols."""
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    res = service.analyze(symbols)
    assert res.charset_analysis.symbol_count == len(symbols)
    assert res.charset_analysis.digit_count == 0
    assert res.charset_analysis.lowercase_count == 0


def test_edge_case_extreme_repetition() -> None:
    """Extremely long repetitive character run."""
    extreme_rep = "A" * 150
    res = service.analyze(extreme_rep)
    assert any(p.pattern_type == PatternType.REPEATED_CHARS for p in res.pattern_findings)
    assert res.entropy_analysis.effective_entropy_bits == 0.0
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK


def test_edge_case_all_digits_sequence() -> None:
    """Full numeric wrap-around sequence."""
    seq = "12345678901234"
    res = service.analyze(seq)
    assert any(p.pattern_type == PatternType.SEQUENTIAL_NUMERIC for p in res.pattern_findings)
    assert res.score_breakdown.category == StrengthCategory.VERY_WEAK

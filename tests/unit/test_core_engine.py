"""Unit tests for Phase 2 core password analysis engines."""

from password_analyzer.core.charset import analyze_character_set
from password_analyzer.core.dictionary import analyze_dictionary, normalize_leetspeak
from password_analyzer.core.entropy import calculate_entropy
from password_analyzer.core.offline_estimation import estimate_offline_guessing, format_duration
from password_analyzer.core.patterns import (
    detect_keyboard_walks,
    detect_repeated_characters,
    detect_sequential_patterns,
    detect_substring_repetitions,
)
from password_analyzer.models.analysis import DictionaryMatchType, PatternType


def test_charset_analysis_empty() -> None:
    """Empty string yields zero counts."""
    cs = analyze_character_set("")
    assert cs.total_length == 0
    assert cs.character_pool_size == 0
    assert cs.unique_characters == 0


def test_charset_analysis_diversity() -> None:
    """Detects combination of lower, upper, digit, symbol, space, unicode."""
    # Synthetic test input
    sample = "Aa1! é"
    cs = analyze_character_set(sample)
    assert cs.total_length == 6
    assert cs.lowercase_count == 1
    assert cs.uppercase_count == 1
    assert cs.digit_count == 1
    assert cs.symbol_count == 1
    assert cs.whitespace_count == 1
    assert cs.unicode_count == 1
    assert cs.character_pool_size > (26 + 26 + 10 + 33 + 1)


def test_entropy_empty() -> None:
    """Entropy for empty input should be 0."""
    cs = analyze_character_set("")
    ent = calculate_entropy("", cs)
    assert ent.shannon_total_bits == 0.0
    assert ent.charset_space_bits == 0.0
    assert ent.effective_entropy_bits == 0.0


def test_entropy_repetition_vs_random() -> None:
    """All-identical characters have 0 Shannon entropy despite length."""
    rep_sample = "aaaaaaaa"
    cs_rep = analyze_character_set(rep_sample)
    ent_rep = calculate_entropy(rep_sample, cs_rep)
    assert ent_rep.shannon_entropy_per_char == 0.0
    assert ent_rep.effective_entropy_bits == 0.0

    rand_sample = "kX9#mQ2$vL"
    cs_rand = analyze_character_set(rand_sample)
    ent_rand = calculate_entropy(rand_sample, cs_rand)
    assert ent_rand.shannon_entropy_per_char > 3.0
    assert ent_rand.effective_entropy_bits > 30.0


def test_pattern_detection_repeated_chars() -> None:
    """Detects runs of repeated characters."""
    sample = "x1111y"
    findings = detect_repeated_characters(sample)
    assert len(findings) == 1
    assert findings[0].pattern_type == PatternType.REPEATED_CHARS
    assert findings[0].length == 4


def test_pattern_detection_substring_repeats() -> None:
    """Detects repeated block patterns."""
    sample = "testtesttest"
    findings = detect_substring_repetitions(sample)
    assert len(findings) >= 1
    assert findings[0].pattern_type == PatternType.SUBSTRING_REPEAT


def test_pattern_detection_sequences() -> None:
    """Detects numeric and alphabetic forward/reverse sequences."""
    num_sample = "pass12345end"
    num_findings = detect_sequential_patterns(num_sample)
    assert any(f.pattern_type == PatternType.SEQUENTIAL_NUMERIC for f in num_findings)

    alpha_sample = "myabcdefxyz"
    alpha_findings = detect_sequential_patterns(alpha_sample)
    assert any(f.pattern_type == PatternType.SEQUENTIAL_ALPHA for f in alpha_findings)


def test_pattern_detection_keyboard_walks() -> None:
    """Detects horizontal keyboard rows and column walks."""
    qwerty_sample = "testqwerty123"
    walk_findings = detect_keyboard_walks(qwerty_sample)
    assert any(f.pattern_type == PatternType.KEYBOARD_WALK for f in walk_findings)


def test_leetspeak_normalization() -> None:
    """Translates common substitutions."""
    assert normalize_leetspeak("p@ssw0rd") == "password"
    assert normalize_leetspeak("3ntr0py!") == "entropyi"


def test_dictionary_common_password_exact() -> None:
    """Detects exact matches in common breach list."""
    findings = analyze_dictionary("password")
    assert len(findings) >= 1
    assert findings[0].match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD
    assert findings[0].rank is not None


def test_dictionary_leetspeak_match() -> None:
    """Detects leetspeak mutation of common passwords."""
    findings = analyze_dictionary("P@ssw0rd")
    assert len(findings) >= 1
    assert findings[0].match_type == DictionaryMatchType.LEET_MUTATION


def test_dictionary_embedded_substring() -> None:
    """Detects embedded common root words."""
    findings = analyze_dictionary("XxAdmin999!#")
    assert len(findings) >= 1
    assert findings[0].matched_word == "admin"


def test_offline_estimation() -> None:
    """Estimates cracking time across algorithms and hardware tiers."""
    zero_est = estimate_offline_guessing(0.0)
    assert all(s.human_readable_time == "Instant (< 1 second)" for s in zero_est.scenarios)

    high_est = estimate_offline_guessing(85.0)
    fast_hash = next(s for s in high_est.scenarios if "Single Consumer GPU" in s.scenario_name)
    argon_hash = next(s for s in high_est.scenarios if "Argon2id" in s.scenario_name)

    # Argon2id takes orders of magnitude longer than MD5 on identical entropy
    assert argon_hash.estimated_seconds > fast_hash.estimated_seconds


def test_format_duration() -> None:
    """Verifies human readable duration boundaries."""
    assert format_duration(0.5) == "Instant (< 1 second)"
    assert format_duration(30) == "30 seconds"
    assert "minutes" in format_duration(120)
    assert "hours" in format_duration(7200)
    assert "days" in format_duration(100000)
    assert "years" in format_duration(100000000)

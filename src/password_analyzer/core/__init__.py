"""Core analysis engine exports."""

from password_analyzer.core.charset import analyze_character_set
from password_analyzer.core.dictionary import (
    analyze_dictionary,
    load_common_passwords,
    load_dictionary_words,
    normalize_leetspeak,
)
from password_analyzer.core.entropy import calculate_entropy
from password_analyzer.core.offline_estimation import estimate_offline_guessing
from password_analyzer.core.patterns import (
    analyze_all_patterns,
    detect_keyboard_walks,
    detect_repeated_characters,
    detect_sequential_patterns,
    detect_substring_repetitions,
)

__all__ = [
    "analyze_character_set",
    "calculate_entropy",
    "analyze_all_patterns",
    "detect_repeated_characters",
    "detect_substring_repetitions",
    "detect_sequential_patterns",
    "detect_keyboard_walks",
    "analyze_dictionary",
    "normalize_leetspeak",
    "load_common_passwords",
    "load_dictionary_words",
    "estimate_offline_guessing",
]

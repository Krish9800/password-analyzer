"""Dictionary matching and leetspeak substitution detection engine."""

from functools import lru_cache
from pathlib import Path

from password_analyzer.models.analysis import DictionaryFinding, DictionaryMatchType, Severity

# Common leetspeak translation table
LEET_MAP: dict[str, str] = {
    "@": "a",
    "4": "a",
    "8": "b",
    "(": "c",
    "3": "e",
    "9": "g",
    "!": "i",
    "1": "i",
    "|": "l",
    "0": "o",
    "5": "s",
    "$": "s",
    "7": "t",
    "+": "t",
    "2": "z",
}


def _get_wordlist_path(filename: str) -> Path:
    """Resolve wordlist path from local data directory or package resources."""
    # Try repository data dir
    data_dir = Path(__file__).resolve().parent.parent.parent.parent / "data" / "wordlists"
    file_path = data_dir / filename
    if file_path.exists():
        return file_path
    # Fallback to local package directory if installed as wheel
    pkg_data_dir = Path(__file__).resolve().parent.parent / "data" / "wordlists"
    return pkg_data_dir / filename


@lru_cache(maxsize=1)
def load_common_passwords() -> tuple[set[str], list[str]]:
    """Load common breached passwords list into memory.

    Returns:
        Tuple of (set of lowercase passwords, ordered list for rank lookup).
    """
    path = _get_wordlist_path("common_passwords.txt")
    if not path.exists():
        # Minimal built-in fallback if file is missing
        fallback = ["123456", "password", "12345678", "qwerty", "admin", "welcome", "12345"]
        return set(fallback), fallback

    with open(path, encoding="utf-8", errors="ignore") as f:
        words = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    return set(words), words


@lru_cache(maxsize=1)
def load_dictionary_words() -> set[str]:
    """Load standard dictionary vocabulary into memory."""
    path = _get_wordlist_path("dictionary_words.txt")
    if not path.exists():
        fallback = {
            "about",
            "action",
            "change",
            "computer",
            "system",
            "security",
            "summer",
            "winter",
        }
        return fallback

    with open(path, encoding="utf-8", errors="ignore") as f:
        words = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    return words


def normalize_leetspeak(text: str) -> str:
    """Convert common leetspeak substitutions to standard Latin characters."""
    normalized = []
    for char in text:
        normalized.append(LEET_MAP.get(char, char.lower()))
    return "".join(normalized)


def analyze_dictionary(password: str) -> list[DictionaryFinding]:
    """Analyze password against common breach lists, dictionary words, and leetspeak forms.

    Args:
        password: Raw password string.

    Returns:
        List of DictionaryFinding objects describing identified matches.
    """
    findings: list[DictionaryFinding] = []
    if not password:
        return findings

    pwd_lower = password.lower()
    common_set, common_list = load_common_passwords()
    dict_set = load_dictionary_words()

    # 1. Exact Common Password Match
    if pwd_lower in common_set:
        rank = common_list.index(pwd_lower) + 1 if pwd_lower in common_list else None
        findings.append(
            DictionaryFinding(
                match_type=DictionaryMatchType.EXACT_COMMON_PASSWORD,
                matched_word=pwd_lower,
                is_exact_match=True,
                rank=rank,
                severity=Severity.CRITICAL,
                description=(
                    "Direct exact match with a frequently breached password"
                    + (f" (Popularity Rank #{rank})." if rank else ".")
                ),
                entropy_penalty_bits=40.0,
            )
        )
        return findings  # If exact common password, that dominates the finding

    # 2. Leetspeak Transformation Match
    leet_normalized = normalize_leetspeak(password)
    has_substitutions = leet_normalized != pwd_lower

    if has_substitutions and leet_normalized in common_set:
        rank = common_list.index(leet_normalized) + 1 if leet_normalized in common_list else None
        findings.append(
            DictionaryFinding(
                match_type=DictionaryMatchType.LEET_MUTATION,
                matched_word=leet_normalized,
                is_exact_match=True,
                rank=rank,
                severity=Severity.HIGH,
                description=(
                    f"Password is a direct leetspeak substitution of common breached password "
                    f"'{leet_normalized}'."
                ),
                entropy_penalty_bits=28.0,
            )
        )
        return findings

    # 3. Exact Dictionary Word Match
    if pwd_lower in dict_set:
        findings.append(
            DictionaryFinding(
                match_type=DictionaryMatchType.DICTIONARY_WORD,
                matched_word=pwd_lower,
                is_exact_match=True,
                severity=Severity.HIGH,
                description=f"Direct match with standard dictionary word '{pwd_lower}'.",
                entropy_penalty_bits=22.0,
            )
        )
        return findings

    # 4. Leetspeak of Dictionary Word
    if has_substitutions and leet_normalized in dict_set:
        findings.append(
            DictionaryFinding(
                match_type=DictionaryMatchType.LEET_MUTATION,
                matched_word=leet_normalized,
                is_exact_match=True,
                severity=Severity.MEDIUM,
                description=f"Leetspeak substitution of dictionary word '{leet_normalized}'.",
                entropy_penalty_bits=18.0,
            )
        )
        return findings

    # 5. Substring Common Password / Dictionary Word Detection
    # Scan for embedded words of length >= 4
    for candidate in common_set:
        if len(candidate) >= 4 and candidate in pwd_lower:
            findings.append(
                DictionaryFinding(
                    match_type=DictionaryMatchType.SUBSTRING_COMMON_PASSWORD,
                    matched_word=candidate,
                    is_exact_match=False,
                    severity=Severity.MEDIUM,
                    description=f"Contains common password fragment '{candidate}' as a substring.",
                    entropy_penalty_bits=12.0,
                )
            )
            break  # Record top substring match

    # If no common password substring, check dictionary words
    if not findings:
        # Check against dictionary set, prioritizing longer stems
        sorted_dict = sorted([w for w in dict_set if len(w) >= 4], key=len, reverse=True)
        for word in sorted_dict:
            if word in pwd_lower:
                findings.append(
                    DictionaryFinding(
                        match_type=DictionaryMatchType.DICTIONARY_WORD,
                        matched_word=word,
                        is_exact_match=False,
                        severity=Severity.LOW,
                        description=f"Contains embedded dictionary root word '{word}'.",
                        entropy_penalty_bits=8.0,
                    )
                )
                break

    return findings

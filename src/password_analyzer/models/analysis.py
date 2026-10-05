"""Data models for password intelligence analysis."""

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severity ratings for detected password weaknesses."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PatternType(StrEnum):
    """Categorization of structural password patterns."""

    REPEATED_CHARS = "REPEATED_CHARS"
    SUBSTRING_REPEAT = "SUBSTRING_REPEAT"
    SEQUENTIAL_ALPHA = "SEQUENTIAL_ALPHA"
    SEQUENTIAL_NUMERIC = "SEQUENTIAL_NUMERIC"
    KEYBOARD_WALK = "KEYBOARD_WALK"
    LEETSPEAK_SUBSTITUTION = "LEETSPEAK_SUBSTITUTION"


class DictionaryMatchType(StrEnum):
    """Categorization of dictionary or breach list matches."""

    EXACT_COMMON_PASSWORD = "EXACT_COMMON_PASSWORD"  # nosec B105
    SUBSTRING_COMMON_PASSWORD = "SUBSTRING_COMMON_PASSWORD"  # nosec B105
    DICTIONARY_WORD = "DICTIONARY_WORD"
    LEET_MUTATION = "LEET_MUTATION"


class CharacterSetAnalysis(BaseModel):
    """Analysis of character sets and length composition."""

    total_length: int = Field(ge=0, description="Total number of characters")
    unique_characters: int = Field(ge=0, description="Count of distinct characters")
    lowercase_count: int = Field(ge=0, description="Number of lowercase Latin characters")
    uppercase_count: int = Field(ge=0, description="Number of uppercase Latin characters")
    digit_count: int = Field(ge=0, description="Number of numeric digits")
    symbol_count: int = Field(ge=0, description="Number of punctuation and symbol characters")
    whitespace_count: int = Field(ge=0, description="Number of space/whitespace characters")
    unicode_count: int = Field(ge=0, description="Number of non-ASCII Unicode characters")
    character_pool_size: int = Field(ge=0, description="Theoretical character set space size")


class EntropyAnalysis(BaseModel):
    """Information-theoretic and combinatorial entropy measurements."""

    shannon_entropy_per_char: float = Field(
        ge=0.0, description="Shannon entropy in bits per character"
    )
    shannon_total_bits: float = Field(ge=0.0, description="Total Shannon entropy (H * length)")
    charset_space_bits: float = Field(
        ge=0.0, description="Combinatorial space entropy: L * log2(|S|)"
    )
    effective_entropy_bits: float = Field(
        ge=0.0, description="Effective entropy adjusted for detected patterns"
    )
    explanation: str = Field(description="Educational explanation of the calculated entropy")


class PatternFinding(BaseModel):
    """Details of a single detected structural or spatial pattern."""

    pattern_type: PatternType
    matched_pattern: str = Field(description="Redacted or representative pattern match")
    start_index: int = Field(ge=0)
    end_index: int = Field(ge=0)
    length: int = Field(ge=1)
    severity: Severity
    description: str
    entropy_penalty_bits: float = Field(
        ge=0.0, description="Estimated search space reduction in bits"
    )


class DictionaryFinding(BaseModel):
    """Details of common wordlist or dictionary matches."""

    match_type: DictionaryMatchType
    matched_word: str
    is_exact_match: bool
    rank: int | None = Field(
        default=None, description="Popularity rank if within common breached list"
    )
    severity: Severity
    description: str
    entropy_penalty_bits: float = Field(ge=0.0)


class CrackScenario(BaseModel):
    """Single scenario estimating resistance against a specific attack vector."""

    scenario_name: str
    attack_category: str = Field(
        description="e.g. Offline Fast Hash, Offline Slow KDF, Online Throttled"
    )
    hash_rate_description: str
    hash_rate_per_sec: float
    estimated_seconds: float
    human_readable_time: str
    attacker_hardware: str


class OfflineGuessingEstimate(BaseModel):
    """Comparative analysis of resistance across multiple attack scenarios."""

    scenarios: list[CrackScenario]
    disclaimer: str = Field(
        default=(
            "Estimated crack durations are mathematical models based on average search spaces "
            "(50% search depth) under specific hardware benchmarks. They do not constitute "
            "absolute security guarantees. Real-world compromise depends on breached lists, "
            "targeted social engineering, password reuse, hashing parameters, and "
            "distributed attacker infrastructure."
        )
    )

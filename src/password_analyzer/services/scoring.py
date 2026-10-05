"""Explainable scoring engine translating password attributes into transparent scores."""

from password_analyzer.models.analysis import (
    CharacterSetAnalysis,
    DictionaryFinding,
    DictionaryMatchType,
    EntropyAnalysis,
    PatternFinding,
    PatternType,
)
from password_analyzer.models.result import ScoreAdjustment, ScoreBreakdown, StrengthCategory


def calculate_score(
    charset: CharacterSetAnalysis,
    entropy: EntropyAnalysis,
    pattern_findings: list[PatternFinding],
    dictionary_findings: list[DictionaryFinding],
) -> ScoreBreakdown:
    """Compute an explainable score (0-100) with full itemized bonus and deduction ledger.

    Args:
        charset: Character set composition metrics.
        entropy: Entropy analysis metrics.
        pattern_findings: Structural patterns detected.
        dictionary_findings: Wordlist and breach matches.

    Returns:
        ScoreBreakdown with itemized adjustments and classification.
    """
    length = charset.total_length
    if length == 0:
        return ScoreBreakdown(
            base_score=0.0,
            entropy_contribution=0.0,
            bonuses=[],
            deductions=[
                ScoreAdjustment(
                    name="Empty Password",
                    points=0.0,
                    reason="Input contains no characters.",
                )
            ],
            raw_score=0.0,
            final_score=0,
            category=StrengthCategory.VERY_WEAK,
        )

    bonuses: list[ScoreAdjustment] = []
    deductions: list[ScoreAdjustment] = []

    # 1. Base Score: Length (max 35) + Character Diversity (max 15)
    length_points = min(35.0, length * 2.5)

    # Count character classes
    classes_present = 0
    if charset.lowercase_count > 0:
        classes_present += 1
    if charset.uppercase_count > 0:
        classes_present += 1
    if charset.digit_count > 0:
        classes_present += 1
    if charset.symbol_count > 0:
        classes_present += 1

    diversity_points = 0.0
    if classes_present == 4:
        diversity_points = 15.0
    elif classes_present == 3:
        diversity_points = 10.0
    elif classes_present == 2:
        diversity_points = 5.0

    if charset.unique_characters <= 1:
        base_score = min(5.0, length_points)
    else:
        base_score = min(50.0, length_points + diversity_points)

    # 2. Entropy Contribution (max 30 pts)
    # 85 bits of effective entropy provides the full 30 points
    entropy_contribution = min(30.0, max(0.0, entropy.effective_entropy_bits * 0.35))

    # 3. Explicit Bonuses
    has_substantive_entropy = entropy.effective_entropy_bits > 5.0 and charset.unique_characters > 2

    if has_substantive_entropy:
        if length >= 16:
            bonuses.append(
                ScoreAdjustment(
                    name="Length Resilience (>= 16 chars)",
                    points=10.0,
                    reason="Password length of 16+ provides a large combinatorial search barrier.",
                )
            )
        elif length >= 12:
            bonuses.append(
                ScoreAdjustment(
                    name="Adequate Length (>= 12 chars)",
                    points=5.0,
                    reason="Meets recommended 12-character baseline for general authentication.",
                )
            )

        if length >= 20:
            bonuses.append(
                ScoreAdjustment(
                    name="Passphrase Scale (>= 20 chars)",
                    points=5.0,
                    reason="Exceptional length characteristic of multi-word passphrases.",
                )
            )

    if charset.unicode_count > 0:
        bonuses.append(
            ScoreAdjustment(
                name="Non-ASCII Diversity",
                points=5.0,
                reason="Inclusion of Unicode characters expands brute-force search space.",
            )
        )

    if length >= 12 and not pattern_findings and not dictionary_findings:
        bonuses.append(
            ScoreAdjustment(
                name="Pattern Free",
                points=5.0,
                reason="No structural repetition, sequences, or dictionary stems discovered.",
            )
        )

    # 4. Itemized Deductions
    # Length penalties
    if length < 8:
        deductions.append(
            ScoreAdjustment(
                name="Critical Short Length (< 8 chars)",
                points=35.0,
                reason="Passwords under 8 characters can be trivially brute-forced offline.",
            )
        )
    elif length < 12:
        deductions.append(
            ScoreAdjustment(
                name="Sub-optimal Length (< 12 chars)",
                points=10.0,
                reason="Lengths between 8 and 11 offer reduced resistance to modern offline rigs.",
            )
        )

    # Single character class penalty
    if classes_present == 1 and charset.unicode_count == 0:
        deductions.append(
            ScoreAdjustment(
                name="Single Character Class",
                points=15.0,
                reason="Restricting to only one character set drastically reduces pool space.",
            )
        )

    # Dictionary findings deductions
    for df in dictionary_findings:
        if df.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD:
            deductions.append(
                ScoreAdjustment(
                    name="Common Breached Password Match",
                    points=60.0,
                    reason="Direct match to high-frequency leaked credential.",
                )
            )
        elif df.match_type == DictionaryMatchType.LEET_MUTATION:
            deductions.append(
                ScoreAdjustment(
                    name="Leetspeak Common Password Mutation",
                    points=40.0,
                    reason="Standard automated rule-based cracking tools invert leetspeak.",
                )
            )
        elif df.match_type == DictionaryMatchType.DICTIONARY_WORD:
            deductions.append(
                ScoreAdjustment(
                    name="Standard Dictionary Word Match",
                    points=35.0 if df.is_exact_match else 15.0,
                    reason=(
                        "Dictionary word used"
                        + (" directly." if df.is_exact_match else " as an embedded root.")
                    ),
                )
            )
        elif df.match_type == DictionaryMatchType.SUBSTRING_COMMON_PASSWORD:
            deductions.append(
                ScoreAdjustment(
                    name="Common Password Substring",
                    points=20.0,
                    reason="Contains a known common password fragment.",
                )
            )

    # Structural pattern deductions
    seen_pattern_types: set[PatternType] = set()
    for pf in pattern_findings:
        if pf.pattern_type in seen_pattern_types:
            continue
        seen_pattern_types.add(pf.pattern_type)

        if pf.pattern_type == PatternType.REPEATED_CHARS:
            deductions.append(
                ScoreAdjustment(
                    name="Repeated Characters",
                    points=15.0,
                    reason="Consecutive identical characters artificially inflate length.",
                )
            )
        elif pf.pattern_type == PatternType.SUBSTRING_REPEAT:
            deductions.append(
                ScoreAdjustment(
                    name="Repeated Substring Pattern",
                    points=15.0,
                    reason="Repeating structural blocks reduce unique information density.",
                )
            )
        elif pf.pattern_type in (PatternType.SEQUENTIAL_NUMERIC, PatternType.SEQUENTIAL_ALPHA):
            deductions.append(
                ScoreAdjustment(
                    name="Sequential Sequence Run",
                    points=15.0,
                    reason="Alphabetic or numeric progression is easily traversed by smart masks.",
                )
            )
        elif pf.pattern_type == PatternType.KEYBOARD_WALK:
            deductions.append(
                ScoreAdjustment(
                    name="Physical Keyboard Walk",
                    points=20.0,
                    reason="Spatial key progressions are standard rules in cracking engines.",
                )
            )

    # 5. Aggregate Score Calculation
    total_bonuses = sum(b.points for b in bonuses)
    total_deductions = sum(d.points for d in deductions)
    raw_score = base_score + entropy_contribution + total_bonuses - total_deductions
    final_score = int(max(0, min(100, round(raw_score))))

    # 6. Qualitative Category Mapping
    if final_score < 20:
        category = StrengthCategory.VERY_WEAK
    elif final_score < 40:
        category = StrengthCategory.WEAK
    elif final_score < 60:
        category = StrengthCategory.MODERATE
    elif final_score < 80:
        category = StrengthCategory.STRONG
    else:
        category = StrengthCategory.VERY_STRONG

    return ScoreBreakdown(
        base_score=round(base_score, 2),
        entropy_contribution=round(entropy_contribution, 2),
        bonuses=bonuses,
        deductions=deductions,
        raw_score=round(raw_score, 2),
        final_score=final_score,
        category=category,
    )

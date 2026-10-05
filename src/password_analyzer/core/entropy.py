"""Entropy calculation engine for password security evaluation."""

import collections
import math

from password_analyzer.models.analysis import CharacterSetAnalysis, EntropyAnalysis


def calculate_entropy(
    password: str,
    charset: CharacterSetAnalysis,
    penalty_bits: float = 0.0,
) -> EntropyAnalysis:
    """Calculate Shannon entropy, theoretical pool space entropy, and effective entropy.

    Shannon entropy measures the information density per character based on symbol frequency:
        H = - sum(p_i * log2(p_i))
    Total Shannon bits = H * L

    Combinatorial / Pool-space entropy represents theoretical search space:
        E_pool = L * log2(PoolSize)

    Effective entropy accounts for discovered structural patterns, dictionary stems,
    and frequency biases that reduce an attacker's search space:
        E_effective = max(0.0, min(E_pool, H * L) - penalties)

    Args:
        password: Raw password input.
        charset: CharacterSetAnalysis output for the password.
        penalty_bits: Total entropy discount from pattern and dictionary detections.

    Returns:
        EntropyAnalysis object with calculated metrics and educational explanation.
    """
    length = len(password)
    if length == 0 or charset.character_pool_size == 0:
        return EntropyAnalysis(
            shannon_entropy_per_char=0.0,
            shannon_total_bits=0.0,
            charset_space_bits=0.0,
            effective_entropy_bits=0.0,
            explanation="Empty input contains zero information entropy.",
        )

    # Calculate Shannon Entropy
    char_counts = collections.Counter(password)
    shannon_h = 0.0
    for count in char_counts.values():
        prob = count / length
        shannon_h -= prob * math.log2(prob)

    shannon_total = shannon_h * length

    # Calculate Combinatorial / Charset Space Entropy
    pool_size = max(1, charset.character_pool_size)
    charset_space = length * math.log2(pool_size)

    # Determine Baseline Effective Entropy
    # If Shannon total is less than pool space (e.g., "aaaaaaaa", where H=0),
    # the true search space cannot exceed Shannon total.
    effective_base = min(charset_space, shannon_total) if shannon_total > 0 else 0.0

    # Apply penalty deductions from structural patterns / dictionary words
    effective = max(0.0, effective_base - penalty_bits)

    explanation = (
        f"Password utilizes {length} characters across a pool size of {pool_size} symbols. "
        f"Theoretical space is {charset_space:.1f} bits, with Shannon density of "
        f"{shannon_h:.2f} bits/char ({shannon_total:.1f} bits total). "
    )
    if penalty_bits > 0.0:
        explanation += (
            f"Detected structural weaknesses/stems reduced effective entropy by "
            f"{penalty_bits:.1f} bits to {effective:.1f} bits."
        )
    else:
        explanation += f"Effective entropy is estimated at {effective:.1f} bits."

    return EntropyAnalysis(
        shannon_entropy_per_char=round(shannon_h, 3),
        shannon_total_bits=round(shannon_total, 2),
        charset_space_bits=round(charset_space, 2),
        effective_entropy_bits=round(effective, 2),
        explanation=explanation,
    )

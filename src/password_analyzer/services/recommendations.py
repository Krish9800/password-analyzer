"""Defensive security recommendations engine aligned with NIST SP 800-63B."""

from password_analyzer.models.analysis import (
    CharacterSetAnalysis,
    DictionaryFinding,
    DictionaryMatchType,
    EntropyAnalysis,
    PatternFinding,
    PatternType,
    Severity,
)
from password_analyzer.models.result import Recommendation, ScoreBreakdown, StrengthCategory


def generate_recommendations(
    charset: CharacterSetAnalysis,
    entropy: EntropyAnalysis,
    pattern_findings: list[PatternFinding],
    dictionary_findings: list[DictionaryFinding],
    score: ScoreBreakdown,
) -> list[Recommendation]:
    """Generate prioritized, actionable defensive recommendations.

    Args:
        charset: Character set composition metrics.
        entropy: Entropy analysis metrics.
        pattern_findings: Detected structural patterns.
        dictionary_findings: Detected dictionary and breach matches.
        score: Computed score breakdown.

    Returns:
        List of prioritized Recommendation objects.
    """
    recs: list[Recommendation] = []
    length = charset.total_length

    # 1. Critical Breached Credential Warning
    for df in dictionary_findings:
        if df.match_type == DictionaryMatchType.EXACT_COMMON_PASSWORD:
            recs.append(
                Recommendation(
                    id="REC-BREACH-01",
                    title="Known Breached Password — Immediate Replacement Required",
                    severity=Severity.CRITICAL,
                    guidance=(
                        "This password exists in widely distributed public breach dumps "
                        "and top attacker wordlists. It will be cracked in milliseconds "
                        "during automated credential stuffing. Replace immediately."
                    ),
                )
            )
            break

    # 2. Critical Length Warnings
    if length < 8:
        recs.append(
            Recommendation(
                id="REC-LEN-01",
                title="Critical Short Length — Vulnerable to Full Brute Force",
                severity=Severity.CRITICAL,
                guidance=(
                    "Passwords shorter than 8 characters can be completely exhausted across all "
                    "alphanumeric combinations in minutes on modern GPU clusters. "
                    "Increase length to at least 15+ characters."
                ),
            )
        )
    elif length < 12:
        recs.append(
            Recommendation(
                id="REC-LEN-02",
                title="Sub-optimal Length — Increase Search Space",
                severity=Severity.HIGH,
                guidance=(
                    "Length is the primary deterrent against brute-force attacks. "
                    "Aim for at least 14-16 characters, or consider a 4-word randomized "
                    "passphrase (e.g. 'correct-horse-battery-staple')."
                ),
            )
        )

    # 3. Low Effective Entropy Warning
    if entropy.effective_entropy_bits < 35.0 and length >= 8:
        recs.append(
            Recommendation(
                id="REC-ENT-01",
                title="Low Information Entropy — Predictable Composition",
                severity=Severity.HIGH,
                guidance=(
                    f"Effective search space is only {entropy.effective_entropy_bits:.1f} bits. "
                    "Predictable words or repetitive structures allow targeted mask attacks "
                    "to bypass length protections."
                ),
            )
        )

    # 4. Leetspeak Warning
    for df in dictionary_findings:
        if df.match_type == DictionaryMatchType.LEET_MUTATION:
            recs.append(
                Recommendation(
                    id="REC-LEET-01",
                    title="Predictable Leetspeak Substitutions Detected",
                    severity=Severity.HIGH,
                    guidance=(
                        "Substituting letters with symbols (e.g., '@' for 'a', '0' for 'o') "
                        "does not provide meaningful protection. Cracking tools apply automated "
                        "mutation rules that reverse these substitutions instantly."
                    ),
                )
            )
            break

    # 5. Pattern and Keyboard Walk Warnings
    pattern_types = {pf.pattern_type for pf in pattern_findings}
    if PatternType.KEYBOARD_WALK in pattern_types:
        recs.append(
            Recommendation(
                id="REC-PAT-01",
                title="Eliminate Keyboard Walks and Spatial Crutches",
                severity=Severity.MEDIUM,
                guidance=(
                    "Keyboard patterns (e.g., 'qwerty', 'asdfgh', '1qaz') are prioritized in "
                    "specialized rule-based attacks. Avoid relying on physical keyboard layouts."
                ),
            )
        )

    if (
        PatternType.SEQUENTIAL_NUMERIC in pattern_types
        or PatternType.SEQUENTIAL_ALPHA in pattern_types
    ):
        recs.append(
            Recommendation(
                id="REC-PAT-02",
                title="Remove Sequential Characters",
                severity=Severity.MEDIUM,
                guidance=(
                    "Sequences like '1234' or 'abcd' reduce entropy significantly. "
                    "Replace sequential runs with randomized components."
                ),
            )
        )

    if PatternType.REPEATED_CHARS in pattern_types or PatternType.SUBSTRING_REPEAT in pattern_types:
        recs.append(
            Recommendation(
                id="REC-PAT-03",
                title="Avoid Repetitive Character Runs and Blocks",
                severity=Severity.MEDIUM,
                guidance=(
                    "Repeating characters (e.g. 'aaaaa') or repeating blocks ('passpass') "
                    "inflates string length without adding true information entropy."
                ),
            )
        )

    # 6. Character Pool Diversity
    classes_count = sum(
        1
        for c in [
            charset.lowercase_count,
            charset.uppercase_count,
            charset.digit_count,
            charset.symbol_count,
        ]
        if c > 0
    )
    if classes_count <= 2 and length < 20:
        recs.append(
            Recommendation(
                id="REC-DIV-01",
                title="Broaden Character Set or Substantially Increase Length",
                severity=Severity.LOW,
                guidance=(
                    "Unless using a long passphrase (20+ characters), mix uppercase, "
                    "lowercase, digits, and special characters to maximize theoretical space."
                ),
            )
        )

    # 7. Architectural Best Practice Recommendations
    if score.category in (StrengthCategory.STRONG, StrengthCategory.VERY_STRONG):
        recs.append(
            Recommendation(
                id="REC-ARCH-01",
                title="Adopt a Dedicated Password Manager",
                severity=Severity.INFO,
                guidance=(
                    "Maintain strong, unique passwords across every service using an audited "
                    "password manager (e.g., Bitwarden, 1Password, or KeePassXC)."
                ),
            )
        )

    recs.append(
        Recommendation(
            id="REC-ARCH-02",
            title="Enforce Multi-Factor Authentication (MFA)",
            severity=Severity.INFO,
            guidance=(
                "Even high-entropy passwords can be phished or stolen via malware. "
                "Always enable hardware security keys (FIDO2/WebAuthn) or TOTP authenticator apps."
            ),
        )
    )

    return recs

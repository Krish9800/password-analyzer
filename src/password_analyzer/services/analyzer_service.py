"""Master orchestration service for password intelligence analysis."""

from password_analyzer.core.charset import analyze_character_set
from password_analyzer.core.dictionary import analyze_dictionary
from password_analyzer.core.entropy import calculate_entropy
from password_analyzer.core.offline_estimation import estimate_offline_guessing
from password_analyzer.core.patterns import analyze_all_patterns
from password_analyzer.models.result import PasswordAnalysisResult
from password_analyzer.services.recommendations import generate_recommendations
from password_analyzer.services.scoring import calculate_score

MAX_PASSWORD_LENGTH = 512


class PasswordAnalyzerService:
    """Service orchestrating multi-vector password intelligence analysis."""

    def analyze(self, password: str) -> PasswordAnalysisResult:
        """Execute full local defensive analysis on the provided password string.

        Args:
            password: Plaintext password string to evaluate.

        Returns:
            PasswordAnalysisResult report.

        Raises:
            ValueError: If input exceeds safe maximum length.
        """
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(
                f"Password length ({len(password)}) exceeds maximum allowed "
                f"limit of {MAX_PASSWORD_LENGTH} characters."
            )

        # 1. Character set and composition analysis
        charset = analyze_character_set(password)

        # 2. Structural pattern detection (repetitions, sequences, walks)
        pattern_findings = analyze_all_patterns(password)

        # 3. Wordlist, dictionary, and leetspeak analysis
        dictionary_findings = analyze_dictionary(password)

        # 4. Aggregate search space entropy penalties
        pattern_penalty = sum(p.entropy_penalty_bits for p in pattern_findings)
        dict_penalty = sum(d.entropy_penalty_bits for d in dictionary_findings)
        total_penalty = round(pattern_penalty + dict_penalty, 2)

        # 5. Information-theoretic and effective entropy calculation
        entropy = calculate_entropy(password, charset, penalty_bits=total_penalty)

        # 6. Attacker-model offline guessing estimation
        offline_estimates = estimate_offline_guessing(entropy.effective_entropy_bits)

        # 7. Explainable scoring model
        score_breakdown = calculate_score(
            charset=charset,
            entropy=entropy,
            pattern_findings=pattern_findings,
            dictionary_findings=dictionary_findings,
        )

        # 8. Defensive recommendation generation
        recommendations = generate_recommendations(
            charset=charset,
            entropy=entropy,
            pattern_findings=pattern_findings,
            dictionary_findings=dictionary_findings,
            score=score_breakdown,
        )

        # 9. Concise executive summary
        summary = (
            f"Password evaluated as {score_breakdown.category.value} "
            f"(Score: {score_breakdown.final_score}/100) with "
            f"{entropy.effective_entropy_bits:.1f} bits of effective entropy. "
        )
        if pattern_findings or dictionary_findings:
            flaws_count = len(pattern_findings) + len(dictionary_findings)
            summary += f"Identified {flaws_count} structural or dictionary weaknesses."
        else:
            summary += "No common structural weaknesses or dictionary matches identified."

        return PasswordAnalysisResult(
            score_breakdown=score_breakdown,
            charset_analysis=charset,
            entropy_analysis=entropy,
            pattern_findings=pattern_findings,
            dictionary_findings=dictionary_findings,
            offline_estimates=offline_estimates,
            recommendations=recommendations,
            summary=summary,
        )

"""Data models for comprehensive password analysis results, scoring, and recommendations."""

from enum import StrEnum

from pydantic import BaseModel, Field

from password_analyzer.models.analysis import (
    CharacterSetAnalysis,
    DictionaryFinding,
    EntropyAnalysis,
    OfflineGuessingEstimate,
    PatternFinding,
    Severity,
)


class StrengthCategory(StrEnum):
    """Qualitative classification of password strength."""

    VERY_WEAK = "VERY_WEAK"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"


class ScoreAdjustment(BaseModel):
    """Itemized scoring adjustment (bonus or deduction) for explainability."""

    name: str
    points: float
    reason: str


class ScoreBreakdown(BaseModel):
    """Transparent and explainable scoring model."""

    base_score: float = Field(
        ge=0.0, le=50.0, description="Baseline score from length & composition"
    )
    entropy_contribution: float = Field(
        ge=0.0, le=35.0, description="Points from effective entropy"
    )
    bonuses: list[ScoreAdjustment] = Field(default_factory=list)
    deductions: list[ScoreAdjustment] = Field(default_factory=list)
    raw_score: float = Field(description="Unclamped calculated score")
    final_score: int = Field(ge=0, le=100, description="Normalized score bounded between 0 and 100")
    category: StrengthCategory
    methodology: str = Field(
        default=(
            "Explainable heuristic model combining effective character set space, "
            "information entropy, structural pattern penalties, and dictionary discounts. "
            "This score is an educational defensive indicator, not an absolute guarantee."
        )
    )


class Recommendation(BaseModel):
    """Actionable remediation guidance."""

    id: str
    title: str
    severity: Severity
    guidance: str


class PasswordAnalysisResult(BaseModel):
    """Aggregated analysis report."""

    score_breakdown: ScoreBreakdown
    charset_analysis: CharacterSetAnalysis
    entropy_analysis: EntropyAnalysis
    pattern_findings: list[PatternFinding] = Field(default_factory=list)
    dictionary_findings: list[DictionaryFinding] = Field(default_factory=list)
    offline_estimates: OfflineGuessingEstimate
    recommendations: list[Recommendation] = Field(default_factory=list)
    summary: str
    privacy_notice: str = Field(
        default="No password data is intentionally persisted, logged, or transmitted over network."
    )

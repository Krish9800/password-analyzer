"""Rich terminal formatting helpers for CLI presentation."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from password_analyzer.models.analysis import Severity
from password_analyzer.models.result import PasswordAnalysisResult, StrengthCategory

console = Console()

CATEGORY_COLORS = {
    StrengthCategory.VERY_WEAK: "bold red",
    StrengthCategory.WEAK: "bold bright_red",
    StrengthCategory.MODERATE: "bold yellow",
    StrengthCategory.STRONG: "bold green",
    StrengthCategory.VERY_STRONG: "bold bright_green",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold bright_red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def render_analysis_report(result: PasswordAnalysisResult, show_offline: bool = True) -> None:
    """Render a comprehensive, colorized terminal security report."""
    # 1. Privacy Banner
    console.print(
        Panel(
            Text(
                "🔒 PRIVACY GUARANTEE: Zero Credential Persistence\n"
                "This password was analyzed purely in local volatile memory. "
                "No data has been saved, logged, or transmitted across any network.",
                style="bold cyan",
            ),
            title="Defensive Password Intelligence Analyzer",
            border_style="cyan",
        )
    )

    # 2. Strength & Summary Overview
    cat_color = CATEGORY_COLORS.get(result.score_breakdown.category, "white")
    score_text = Text()
    score_text.append(
        f"Strength Rating: {result.score_breakdown.category.value}\n", style=cat_color
    )
    score_text.append(f"Security Score:  {result.score_breakdown.final_score}/100\n", style="bold")
    score_text.append(
        f"Effective Entropy: {result.entropy_analysis.effective_entropy_bits:.1f} bits\n"
    )
    score_text.append(
        f"Length & Pool:   {result.charset_analysis.total_length} characters "
        f"(Pool: {result.charset_analysis.character_pool_size})\n"
    )
    score_text.append(f"Summary:         {result.summary}")

    console.print(Panel(score_text, title="Evaluation Overview", border_style=cat_color))

    # 3. Explainable Scoring Ledger Table
    score_table = Table(title="Explainable Scoring Ledger", header_style="bold magenta")
    score_table.add_column("Factor", style="bold")
    score_table.add_column("Type", justify="center")
    score_table.add_column("Points", justify="right")
    score_table.add_column("Explanation")

    score_table.add_row(
        "Base Composition",
        "Base",
        f"+{result.score_breakdown.base_score:.1f}",
        "Length and character class diversity baseline",
    )
    score_table.add_row(
        "Effective Entropy",
        "Base",
        f"+{result.score_breakdown.entropy_contribution:.1f}",
        "Proportional contribution from pattern-discounted search space",
    )

    for bonus in result.score_breakdown.bonuses:
        score_table.add_row(
            bonus.name,
            "[green]BONUS[/green]",
            f"+{bonus.points:.1f}",
            bonus.reason,
        )

    for ded in result.score_breakdown.deductions:
        score_table.add_row(
            ded.name,
            "[red]DEDUCT[/red]",
            f"-{ded.points:.1f}",
            ded.reason,
        )

    score_table.add_section()
    score_table.add_row(
        "[bold]Final Calculated Score[/bold]",
        "[bold cyan]TOTAL[/bold cyan]",
        f"[bold]{result.score_breakdown.final_score}/100[/bold]",
        f"Raw: {result.score_breakdown.raw_score:.1f} pts (Clamped 0-100)",
    )
    console.print(score_table)

    # 4. Detected Weaknesses & Patterns Table
    has_flaws = result.pattern_findings or result.dictionary_findings
    if has_flaws:
        flaw_table = Table(
            title="Detected Structural & Lexical Weaknesses", header_style="bold red"
        )
        flaw_table.add_column("Weakness Category")
        flaw_table.add_column("Severity", justify="center")
        flaw_table.add_column("Entropy Penalty", justify="right")
        flaw_table.add_column("Details")

        for df in result.dictionary_findings:
            sev_color = SEVERITY_COLORS.get(df.severity, "white")
            flaw_table.add_row(
                df.match_type.value,
                f"[{sev_color}]{df.severity.value}[/{sev_color}]",
                f"-{df.entropy_penalty_bits:.1f} bits",
                df.description,
            )

        for pf in result.pattern_findings:
            sev_color = SEVERITY_COLORS.get(pf.severity, "white")
            flaw_table.add_row(
                pf.pattern_type.value,
                f"[{sev_color}]{pf.severity.value}[/{sev_color}]",
                f"-{pf.entropy_penalty_bits:.1f} bits",
                pf.description,
            )

        console.print(flaw_table)
    else:
        console.print(
            Panel(
                Text(
                    "✓ No dictionary stems, keyboard walks, or repetitions identified.",
                    style="green",
                ),
                title="Pattern Analysis",
                border_style="green",
            )
        )

    # 5. Offline Guess Resistance Table
    if show_offline:
        offline_table = Table(
            title="Estimated Offline Guessing Resistance (Mathematical Benchmarks)",
            header_style="bold yellow",
        )
        offline_table.add_column("Attack Scenario & Hardware")
        offline_table.add_column("Hash / Attack Speed", justify="center")
        offline_table.add_column("Estimated Time to Crack", justify="right", style="bold")

        for sc in result.offline_estimates.scenarios:
            offline_table.add_row(
                f"{sc.scenario_name}\n[dim]{sc.attacker_hardware}[/dim]",
                sc.hash_rate_description,
                sc.human_readable_time,
            )
        console.print(offline_table)

    # 6. Actionable Recommendations
    rec_table = Table(title="Defensive Recommendations (NIST SP 800-63B)", header_style="bold blue")
    rec_table.add_column("ID", justify="center")
    rec_table.add_column("Priority", justify="center")
    rec_table.add_column("Recommendation & Action")

    for rec in result.recommendations:
        sev_color = SEVERITY_COLORS.get(rec.severity, "white")
        rec_table.add_row(
            rec.id,
            f"[{sev_color}]{rec.severity.value}[/{sev_color}]",
            f"[bold]{rec.title}[/bold]\n{rec.guidance}",
        )
    console.print(rec_table)
    console.print()

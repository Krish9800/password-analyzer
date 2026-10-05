"""Integration tests for the Typer CLI interface."""

import json

from typer.testing import CliRunner

from password_analyzer.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """CLI provides informative help overview."""
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Password Intelligence Analyzer" in res.stdout
    assert "analyze" in res.stdout


def test_cli_version() -> None:
    """CLI version command outputs version and privacy guarantee."""
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "0.1.0" in res.stdout
    assert "Zero Persistence Guarantee" in res.stdout


def test_cli_analyze_stdin_json() -> None:
    """CLI analyzes password passed via stdin and outputs valid JSON."""
    test_input = "SampleP@ssw0rd2026!"
    res = runner.invoke(app, ["analyze", "--stdin", "--json"], input=test_input)
    assert res.exit_code == 0

    parsed = json.loads(res.stdout)
    assert "score_breakdown" in parsed
    assert "entropy_analysis" in parsed
    assert "offline_estimates" in parsed
    assert parsed["score_breakdown"]["final_score"] > 0
    # Crucial security guarantee: raw input password must not be in output
    assert test_input not in res.stdout


def test_cli_analyze_stdin_rendered() -> None:
    """CLI renders colored panels and tables without echoing password."""
    test_input = "SecretKey123!@#"
    res = runner.invoke(app, ["analyze", "--stdin"], input=test_input)
    assert res.exit_code == 0
    assert "PRIVACY GUARANTEE" in res.stdout
    assert "Explainable Scoring Ledger" in res.stdout
    assert "Estimated Offline Guessing Resistance" in res.stdout
    assert test_input not in res.stdout


def test_cli_analyze_oversized_input() -> None:
    """CLI catches oversized input gracefully with exit code 1."""
    oversized = "X" * 600
    res = runner.invoke(app, ["analyze", "--stdin"], input=oversized)
    assert res.exit_code == 1
    assert "Input Error" in res.stdout

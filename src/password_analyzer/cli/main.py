"""CLI application entrypoint for Password Intelligence Analyzer."""

import getpass
import sys
from typing import Annotated

import typer

import password_analyzer
from password_analyzer.cli.formatting import console, render_analysis_report
from password_analyzer.services.analyzer_service import PasswordAnalyzerService

app = typer.Typer(
    name="password-analyzer",
    help="Educational Defensive Password Intelligence Analyzer — Evaluates credentials locally.",
    no_args_is_help=True,
)


@app.command()
def analyze(
    stdin: Annotated[
        bool,
        typer.Option("--stdin", "-s", help="Read password directly from standard input."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output analysis result in machine-readable JSON."),
    ] = False,
    no_offline: Annotated[
        bool,
        typer.Option("--no-offline", help="Omit the offline guessing estimation table."),
    ] = False,
) -> None:
    """Analyze a password for entropy, patterns, dictionary hits, and crack resistance."""
    if stdin:
        # Read from standard input (e.g., cat file | password-analyzer analyze -s)
        password = sys.stdin.read().rstrip("\r\n")
    else:
        # Interactive masked prompt to prevent shell history and shoulder surfing
        password = getpass.getpass("Enter password to evaluate (input hidden): ")

    service = PasswordAnalyzerService()
    try:
        result = service.analyze(password)
    except ValueError as e:
        console.print(f"[bold red]Input Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    if json_output:
        sys.stdout.write(result.model_dump_json(indent=2) + "\n")
    else:
        render_analysis_report(result, show_offline=not no_offline)


@app.command()
def version() -> None:
    """Show the application version and privacy guarantee."""
    console.print(
        f"[bold cyan]Password Intelligence Analyzer[/bold cyan] v{password_analyzer.__version__}\n"
        "Security Model: Local In-Memory Analysis Only (Zero Persistence Guarantee)"
    )


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", "-h", help="API bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="API bind port")] = 8000,
) -> None:
    """Start the local REST API server."""
    import uvicorn

    console.print(
        f"[bold green]Starting Password Intelligence API server on "
        f"http://{host}:{port}[/bold green]"
    )
    uvicorn.run("password_analyzer.api.main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()

"""Loader for embedded local web dashboard HTML template."""

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_dashboard_html() -> str:
    """Load the dashboard HTML template from disk."""
    template_path = Path(__file__).resolve().parent / "templates" / "dashboard.html"
    if not template_path.exists():
        return (
            "<html><body><h1>Password Intelligence Analyzer</h1>"
            "<p>Dashboard template not found.</p></body></html>"
        )
    return template_path.read_text(encoding="utf-8")

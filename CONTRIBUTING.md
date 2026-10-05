# Contributing to Password Intelligence Analyzer

Thank you for contributing to this educational defensive security project.

## Development Workflow

1. Fork and clone the repository.
2. Create a virtual environment with Python 3.12+:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Adhere to code quality standards:
   - Ensure all code passes `ruff check .`, `black --check .`, `mypy src/`, and `bandit -r src/`.
   - Write comprehensive tests for new logic in `tests/`.
   - Verify that test cases do not use real user passwords; use synthetic strings only.
5. Submit a pull request with a clear description of changes and test outcomes.

## Description
Briefly describe the change and its rationale.

## Security & Privacy Impact
- [ ] No plaintext credentials or secrets are logged, persisted, or transmitted.
- [ ] All inputs are strictly validated and bounded.
- [ ] Added or modified algorithms operate in sub-quadratic / linear time.

## Quality Checklist
- [ ] All unit, integration, and security tests pass (`pytest`).
- [ ] Test coverage meets or exceeds 85% (`pytest --cov=password_analyzer`).
- [ ] Static type checker passes with zero issues (`mypy src/`).
- [ ] Code formatting and linter pass (`ruff check .`, `ruff format --check .`).
- [ ] Security static analysis passes with zero issues (`bandit -r src/`).
- [ ] Documentation updated if applicable.

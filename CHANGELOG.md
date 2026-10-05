# Changelog

All notable changes to the Password Intelligence Analyzer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-05

### Added
- **Core Analysis Engine:**
  - Information-theoretic Shannon entropy density and total entropy calculations.
  - Character set space and theoretical pool calculations.
  - Linear-time spatial keyboard walk detection across horizontal rows, vertical columns, and keypads.
  - Sequential numeric and alphabetic progression detection (forward and reverse).
  - Repetitive character and substring block detectors.
  - Common password breach matching and automated leetspeak substitution detection.
  - Hardware-aware offline guess resistance projections across MD5, SHA-256, bcrypt, and Argon2id.
- **Explainable Scoring Engine:**
  - Transparent 0–100 heuristic scoring model with itemized bonus and deduction ledger.
  - Qualitative categorization into `VERY_WEAK`, `WEAK`, `MODERATE`, `STRONG`, `VERY_STRONG`.
- **Defensive Recommendations:**
  - NIST SP 800-63B aligned actionable guidance covering passphrases, length over complexity, and MFA adoption.
- **User Interfaces:**
  - Interactive terminal CLI powered by Typer and Rich with masked input and raw JSON output options.
  - RESTful API powered by FastAPI with loopback CORS and defensive HTTP security headers.
  - Embedded local HTML/CSS/JS visual dashboard served at root endpoint.
- **DevSecOps & Testing:**
  - Comprehensive test suite achieving 96% coverage across unit, integration, edge cases, and security leakage tests.
  - Multi-stage hardened Dockerfile running as non-root user `appuser` (UID 10001).
  - GitHub Actions CI pipeline executing Ruff, Black, Mypy, Bandit SAST, and Pytest coverage gates.
- **Documentation:**
  - Complete `README.md` with threat model, privacy guarantees, limitations, and quickstart guides.
  - In-depth architectural documentation (`docs/architecture.md`).
  - STRIDE threat model documentation (`docs/threat_model.md`).
  - Mathematical scoring methodology (`docs/scoring_methodology.md`).
  - Defensive security review and vulnerability assessment (`docs/security_review.md`).

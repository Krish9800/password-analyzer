# Password Intelligence Analyzer

> **Educational Defensive Security Project (Cybersecurity Portfolio — Project 01)**
> A production-inspired, privacy-preserving credential evaluation engine analyzing password entropy, combinatorial space, character-set diversity, sequential and keyboard patterns, common dictionary leaks, and estimated resistance against offline guessing models.

---

## 🔒 Privacy & Security Guarantee

> [!IMPORTANT]
> **Zero Credential Persistence Policy:**
> - No password data is intentionally persisted.
> - Submitted passwords are never written to disk, database, or logs.
> - Passwords are processed strictly in local memory and purged immediately after analysis.
> - No remote telemetry, analytics, or external API calls are made.
> - Estimated offline guess resistances are educational models under specific assumptions, not absolute guarantees.

---

## Overview

Modern authentication security requires understanding credential strength beyond simplistic regex rules (e.g., "must contain 1 number and 1 symbol"). Attackers do not guess passwords character-by-character; they use probabilistic dictionary attacks, rule-based mutations (leetspeak, prefix/suffix additions), and specialized hardware (GPUs/FPGAs/ASICs) to execute billions of hashes per second against dumped hashes.

The **Password Intelligence Analyzer** evaluates passwords locally against real-world attacker techniques, providing:
1. **Accurate Information-Theoretic Entropy:** Shannon entropy, charset-space theoretical entropy, and dictionary-adjusted effective entropy.
2. **Multi-Vector Pattern Detection:** Repeated characters, alphabetical sequences, numeric runs, and physical keyboard walks (QWERTY layout).
3. **Dictionary & Leetspeak Weakness Detection:** Identification of known common passwords, root word stems, and common substitution mutations.
4. **Hardware-Aware Offline Guessing Models:** Clear time-to-crack estimations across hashing algorithms (e.g., MD5/SHA-256 vs. bcrypt vs. Argon2id) and attacker tiers (consumer GPU vs. multi-GPU cluster).
5. **Explainable Scoring & Defense Guidance:** Transparent penalty/bonus breakdown and actionable security recommendations.

---

## Architecture

The project is structured into cleanly isolated, single-responsibility modules:

```
password-intelligence-analyzer/
├── src/
│   └── password_analyzer/
│       ├── config/          # Central settings, constants, and thresholds
│       ├── core/            # Entropy, pattern detection, dictionary matching, crack estimators
│       ├── models/          # Pydantic data schemas for analysis results and findings
│       ├── services/        # Orchestration layer coordinating analyzers and scoring
│       ├── api/             # FastAPI REST endpoints with zero-log middleware
│       ├── cli/             # Interactive CLI using Typer and Rich
│       └── utils/           # String hygiene, timing-safe checks, and zeroization helpers
├── tests/
│   ├── unit/                # Unit tests for individual analysis engines
│   ├── integration/         # API and CLI end-to-end integration tests
│   └── security/            # Privacy leaks, logging verification, and edge case fuzzing
├── docs/
│   ├── architecture.md      # Comprehensive architecture documentation
│   └── threat_model.md      # STRIDE threat model & risk analysis
├── data/
│   └── wordlists/           # Common passwords and dictionary files
└── pyproject.toml           # Modern package configuration
```

---

## Features

- **Entropy Engine:** Calculates both raw Shannon entropy and charset-space entropy ($L \cdot \log_2(|S|)$) along with effective pattern-discounted entropy.
- **Pattern Matcher:**
  - Repeated sequences (e.g., `aaaa`, `abcabc`).
  - Sequential runs (e.g., `123456`, `abcdef`, `fedcba`).
  - Keyboard walks (e.g., `qwerty`, `asdfgh`, `zxcvbn`).
  - Common leetspeak substitutions (e.g., `@` $\to$ `a`, `0` $\to$ `o`, `3` $\to$ `e`, `$` $\to$ `s`).
- **Offline Guess Resistance:**
  - Fast unkeyed hashes (MD5, SHA-256).
  - Slow memory-hard / work-factor hashes (bcrypt cost 12, Argon2id).
  - Online throttled attack scenario (10 attempts/minute).
- **Explainable Scoring:** A baseline score (0–100) dynamically constructed from length, charset variety, entropy, with transparent itemized penalties.
- **Defensive Recommendations:** Actionable NIST SP 800-63B compliant guidance.
- **Dual Interfaces:** Interactive terminal CLI and local REST API.

---

## Installation

### Prerequisites
- Python 3.12+
- Git

### Setup
```bash
# Clone and enter the repository
cd password-intelligence-analyzer

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package in editable mode with development tools
pip install -e ".[dev]"
```

---

## Usage

### 1. Interactive CLI
```bash
# Interactive prompt (password is hidden during entry)
password-analyzer analyze

# Pass directly via standard input (safe for script pipelines without exposing to bash history)
echo -n "CorrectHorseBatteryStaple!" | password-analyzer analyze --stdin
```

### 2. REST API & Local Web Dashboard
```bash
# Start local API server on 127.0.0.1:8000
password-analyzer serve --port 8000

# Submit a password for evaluation via REST
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "SamplePassword123!"}'

# Open visual web dashboard in browser
# Navigate to: http://127.0.0.1:8000/
```

---

## Detailed Documentation

- **[System Architecture](docs/architecture.md):** Modular component layout, data lifecycle, and zero-persistence boundaries.
- **[STRIDE Threat Model](docs/threat_model.md):** Assets, threat actors, attack surface, and security controls.
- **[Scoring Methodology & Mathematics](docs/scoring_methodology.md):** Information-theoretic entropy formulas, pool sizes, and penalty matrices.
- **[Defensive Security Review](docs/security_review.md):** White-box security audit, CWE mappings, and ReDoS verification.

---

## Security & Privacy Model

1. **Local Processing Only:** All evaluations occur entirely within local process memory. No outbound network requests are initiated.
2. **Ephemeral Memory:** Passwords are not cached, saved, or indexed.
3. **Sanitized Logs:** Logging configurations explicitly filter sensitive fields. Neither CLI output nor API request logs output raw passwords.
4. **Input Boundary Enforcement:** Inputs are bounded (maximum length 512 characters) to mitigate regex/algorithmic complexity DoS (ReDoS).

---

## Threat Model Summary (STRIDE)

| Threat Type | Potential Vector | Mitigation in Analyzer |
| :--- | :--- | :--- |
| **Spoofing** | Unauthorized access to local analysis | Analyzer runs as local user tool without elevated privileges |
| **Tampering** | Modification of dictionary/rule files | Internal integrity checks on packaged reference sets |
| **Repudiation** | Ambiguity in evaluation results | Deterministic, explainable scoring criteria |
| **Information Disclosure** | Credential leakage in logs or crash dumps | Custom logging filters, masked CLI input, zero log persistence |
| **Denial of Service** | Extremely large password inputs / ReDoS | Strict string length limits (max 512 chars) & linear-time pattern matching |
| **Elevation of Privilege** | Code execution via tainted input | Pure Python logic, no shell execution (`shell=False`), non-root container |

---

## Limitations

- **Not an Absolute Guarantee:** Password security is systemic. A password evaluated as "Very Strong" can still be compromised via phishing, infostealer malware, session hijacking, or credential reuse if breached elsewhere.
- **Offline Estimation Heuristics:** Guess times depend on attacker budgets, custom ASIC availability, and hash algorithm implementations.
- **Synthetic Lexicon:** Dictionary matching uses curated offline wordlists and does not guarantee coverage of every niche language or slang.

---

## Testing

```bash
# Run unit, integration, and security tests with coverage
pytest --cov=password_analyzer --cov-report=term-missing

# Run code style and lint checks
ruff check .
black --check .

# Run static type checking
mypy src/

# Run security static analysis
bandit -r src/
```

---

## Development Roadmap

- [x] **Phase 1:** Architecture & repository foundation
- [x] **Phase 2:** Core password-analysis engine (Entropy, Patterns, Dictionary, Guess Estimations)
- [x] **Phase 3:** Scoring and recommendations engine
- [x] **Phase 4:** CLI implementation (Typer + Rich)
- [x] **Phase 5:** REST API implementation (FastAPI) & Local Web Dashboard
- [x] **Phase 6:** Comprehensive test suite (96% coverage)
- [x] **Phase 7:** In-depth security review & CWE vulnerability audit
- [x] **Phase 8:** Detailed documentation & architecture deep dive
- [ ] **Phase 9:** DevSecOps, Docker & CI/CD pipeline
- [ ] **Phase 10:** Final GitHub release preparation

---

## Responsible & Ethical Use

This software is developed strictly for defensive, educational, and audit purposes. It is intended to help developers, administrators, and users understand credential vulnerabilities and implement robust authentication policies.

# Password Intelligence Analyzer (`password-analyzer`)

Enterprise Password Intelligence, Shannon Entropy Evaluator, Combinatorial Crack-Time Modeler, NIST SP 800-63B Policy Verifier, and HaveIBeenPwned k-Anonymity Integration.

[![CI Pipeline](https://github.com/Krish9800/password-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/password-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Standards: NIST SP 800-63B](https://img.shields.io/badge/Standards-NIST%20SP%20800--63B-blueviolet.svg)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![Privacy: k-Anonymity](https://img.shields.io/badge/Privacy-k--Anonymity%20API-green.svg)](https://haveibeenpwned.com/API/v3#PwnedPasswords)

---

## Overview & Problem Statement

Weak, reused, and compromised passwords remain the root cause of credential-stuffing breaches. Legacy password policies that mandate arbitrary special characters or frequent expiration frequently encourage predictable patterns (e.g. `Password123!`), while modern standards (NIST SP 800-63B) advocate for length, entropy, and checking against known breach corpuses.

**Password Intelligence Analyzer** is a privacy-preserving credential evaluation engine. It computes mathematical Shannon entropy, detects keyboard walk patterns, checks compliance with NIST SP 800-63B, models offline crack times against multi-GPU clusters, queries the HaveIBeenPwned API via privacy-preserving **k-Anonymity**, and provides an interactive local web dashboard.

---

## Architecture & Data Flow

```mermaid
flowchart TD
    CandidatePassword[Candidate Password] --> Anonymizer[k-Anonymity SHA-1 Hasher]

    subgraph Privacy-Preserving Breach Check
        Anonymizer --> Prefix[Extract 5-Char Hash Prefix]
        Prefix --> HIBP[HIBP Pwned Passwords API Query]
        HIBP --> SuffixMatcher[Local Suffix Hash Matcher]
        SuffixMatcher --> BreachStatus[Breach Frequency Count]
    end

    subgraph Mathematical & Pattern Analysis
        CandidatePassword --> EntropyEngine[Shannon & Metric Entropy Calculator]
        CandidatePassword --> CharsetAnalysis[Character Diversity & Length Evaluator]
        CandidatePassword --> PatternDetector[Keyboard Walk & Sequence Detector]
        CandidatePassword --> DictCheck[Common Wordlist & Leet-Speak Matcher]
    end

    subgraph Synthesis & Estimation
        EntropyEngine --> Synthesizer[Security Policy & Crack Time Modeler]
        CharsetAnalysis --> Synthesizer
        PatternDetector --> Synthesizer
        DictCheck --> Synthesizer
        BreachStatus --> Synthesizer

        Synthesizer --> NIST[NIST SP 800-63B Compliance Verdict]
        Synthesizer --> CrackTime[Offline Attack Resistance Model: Hashcat / GPU]
        Synthesizer --> Score[Composite Strength Score: 0 to 100]
    end

    subgraph Interfaces
        Score --> CLI[Typer CLI / Rich Terminal]
        Score --> REST[FastAPI REST API / Local Web UI]
    end
```

---

## Verified Features

- **Mathematical Entropy Calculation:** Computes true Shannon entropy and metric entropy based on character set pools and information theory.
- **Pattern & Heuristic Detection:** Identifies sequential runs (`123456`, `abcdef`), keyboard walks (`qwerty`, `asdfgh`), repeated characters (`aaaaa`), and common leet-speak substitutions (`p@ssw0rd`).
- **NIST SP 800-63B Verification:** Validates against modern guidelines (minimum length, absence of truncated spaces, no forced character composition rules).
- **k-Anonymity Breach Checks:** Safely queries HaveIBeenPwned by submitting only the first 5 characters of the SHA-1 hash; the plain password never leaves the machine.
- **Offline Crack-Time Estimation:** Calculates estimated brute-force resistance across single CPU, consumer GPU, and enterprise multi-GPU cracking clusters.
- **Dual Interface:** Typer CLI with terminal formatting, plus an embedded FastAPI service with an interactive local web dashboard.

---

## Technology Stack

- **Runtime:** Python 3.12+
- **HTTP Client:** HTTPX (for k-Anonymity API queries)
- **Data Models:** Pydantic v2
- **CLI Framework:** Typer & Rich
- **API & UI Framework:** FastAPI & Jinja2 HTML templates
- **Testing:** Pytest, Ruff, Mypy, Bandit

---

## Requirements & Installation

```bash
# Clone the repository
git clone https://github.com/Krish9800/password-analyzer.git
cd password-analyzer

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .
```

---

## Verified Usage Examples

### 1. Command-Line Interface (CLI)

```bash
# Analyze a candidate password for strength and entropy
password-analyzer analyze "CorrectHorseBatteryStaple!"

# Analyze with breach database check enabled
password-analyzer analyze "P@ssw0rd123" --check-breaches

# Check CLI version
password-analyzer version
```

### 2. Local Web Dashboard & REST API

```bash
# Launch the local web dashboard and REST API
password-analyzer serve --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser to access the local interactive evaluation UI, or explore OpenAPI documentation at `http://127.0.0.1:8000/docs`:
- `GET /` — Local web evaluation interface
- `POST /api/v1/analyze` — Programmatic credential analysis endpoint
- `GET /health` — Service health status

---

## Testing & Quality Gates

```bash
# Run unit and entropy calculation tests
pytest --cov=password_analyzer --cov-report=term-missing

# Linting and static analysis
ruff check .
ruff format --check .
mypy src/password_analyzer
```

---

## Security Model & Privacy Guarantees

- **k-Anonymity Architecture:** When checking breach databases, the full password is never sent over the wire. Only a 5-character SHA-1 prefix is transmitted, and matching is completed locally.
- **Zero Disk Persistence:** Analyzed passwords are evaluated strictly in transient memory and are never logged, persisted to disk, or stored in history files.
- **Local Isolation:** The web dashboard runs on localhost without tracking cookies, external CDN scripts, or third-party telemetry.

---

## Limitations & Known Issues

- **Offline Mode:** When network access is disabled, k-Anonymity breach checking is skipped and analysis relies on local dictionary and heuristic evaluation.
- **Custom Corporate Dictionaries:** Incorporating internal organization-specific wordlists requires passing a custom dictionary file path.

---

## License & Responsible Use

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> [!NOTE]
> Designed for security researchers, authentication system designers, and credential auditing.

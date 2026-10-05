# Architecture Documentation — Password Intelligence Analyzer

## 1. System Overview

The **Password Intelligence Analyzer** is an educational, defensive security system designed to evaluate password quality and vulnerability against real-world attacker tradecraft without compromising credential confidentiality.

Conventional password validation relies on static composition rules (e.g., minimum 8 characters, requiring mixed case and symbols). In practice, attackers exploit known patterns, dictionary frequencies, leetspeak mutations, and massive parallel offline cracking rigs.

This project implements an **explainable, component-based evaluation engine** prioritizing:
- Zero data persistence or external network transmission.
- Multi-vector algorithmic analysis (entropy, patterns, dictionary, offline guess estimation).
- Decoupled interfaces (CLI, REST API) backed by a core service layer.

---

## 2. Component Architecture

```
                  +----------------------------------------------+
                  |               User Interfaces                |
                  |     +----------------+  +-----------------+  |
                  |     | Typer/Rich CLI |  | FastAPI REST API|  |
                  +-----+-------+--------+--+--------+--------+--+
                                |                    |
                                +---------+----------+
                                          |
                                          v
                  +----------------------------------------------+
                  |               Service Layer                  |
                  |       (AnalyzerService Orchestrator)         |
                  +-----------------------+----------------------+
                                          |
        +------------------+--------------+-------------+------------------+
        |                  |                            |                  |
        v                  v                            v                  v
+---------------+  +---------------+            +---------------+  +---------------+
| Entropy Engine|  | Pattern Engine|            | Dict Engine   |  | Guess Model   |
| - Shannon     |  | - Repeats     |            | - Bloom/Set   |  | - MD5/SHA256  |
| - Combinatorial| | - Sequences   |            | - Mutations   |  | - bcrypt      |
| - Effective   |  | - Keyb walks  |            | - Substrings  |  | - Argon2id    |
+-------+-------+  +-------+-------+            +-------+-------+  +-------+-------+
        |                  |                            |                  |
        +------------------+--------------+-------------+------------------+
                                          |
                                          v
                  +----------------------------------------------+
                  |            Scoring & Recommendations         |
                  | - Transparent deduction/bonus breakdown      |
                  | - NIST SP 800-63B aligned defense guidance   |
                  +----------------------------------------------+
```

### Module Responsibilities:

1. **`src/password_analyzer/models/`**
   - Pure Pydantic data schemas defining inputs, metrics, findings, and evaluation reports.
   - Strict typing and immutable result structures.

2. **`src/password_analyzer/core/`**
   - **`entropy.py`**: Calculates Shannon entropy, raw combinatorial space $\log_2(|S|^L)$, and pattern-discounted effective entropy.
   - **`patterns.py`**: High-performance linear scan algorithms for consecutive identical characters, sequential alphabetic/numeric runs, and spatial keyboard walks (QWERTY layout).
   - **`dictionary.py`**: In-memory lookup against common leaked passwords, common English dictionary roots, and inverse-leetspeak transforms.
   - **`offline_estimation.py`**: Attacker-model based time-to-crack projections across hardware profiles (single consumer GPU, 8-GPU rig, distributed cluster) and hashing cost functions (MD5, SHA-256, bcrypt cost 12, Argon2id).

3. **`src/password_analyzer/services/`**
   - **`scoring.py`**: Computes normalized score (0–100) and qualitative category (Very Weak, Weak, Moderate, Strong, Very Strong) with a complete audit log of deductions and bonuses.
   - **`recommendations.py`**: Produces context-specific remediation instructions based on identified flaws.
   - **`analyzer_service.py`**: Unified entrypoint aggregating results from all core engines into a single `PasswordAnalysisResult`.

4. **`src/password_analyzer/cli/`**
   - Interactive terminal interface using Typer and Rich formatting (colorized tables, meter bars, panels).
   - Direct standard input support for shell pipelines.
   - Hidden password prompts ensuring credentials are not printed in terminal history.

5. **`src/password_analyzer/api/`**
   - Lightweight FastAPI server providing RESTful endpoints.
   - Middleware enforcing strict payload limits and zero logging of request bodies.

---

## 3. Data Flow & Security Invariant

1. **Input Reception:**
   - CLI: Received via `getpass.getpass()` or piped `sys.stdin`.
   - API: Received via JSON payload `{"password": "..."}`.
2. **Analysis Execution:**
   - Raw string is passed directly to `AnalyzerService.analyze(password)`.
   - Engines extract metrics (length, charset counts, pattern matches, dictionary flags).
3. **Report Generation:**
   - Derived metrics and descriptive findings are packaged into `PasswordAnalysisResult`.
   - The original password string is **never** attached to the result model.
4. **Output Display:**
   - Only metrics, categories, explanations, and recommendations are returned to the caller.
   - The memory reference to the raw password is left to immediate garbage collection.

---

## 4. Scoring Model Specification

The scoring engine operates on an **explainable 100-point scale**:
- **Baseline (Length & Charset Diversity):** Up to 50 points based on effective length and presence of lowercase, uppercase, digits, and symbols.
- **Entropy Contribution:** Up to 30 points proportional to effective entropy.
- **Bonus Factors:** Up to 20 points for length $\ge 16$ and absence of detected patterns.
- **Itemized Deductions:**
  - Common password match: -40 to -60 points.
  - Dictionary word / root match: -20 to -35 points.
  - Sequential run ($\ge 3$ characters): -10 to -20 points.
  - Keyboard walk ($\ge 4$ characters): -15 to -25 points.
  - Excessive repetition: -15 to -30 points.
- The score is clamped between 0 and 100 and mapped to:
  - 0–19: `Very Weak`
  - 20–39: `Weak`
  - 40–59: `Moderate`
  - 60–79: `Strong`
  - 80–100: `Very Strong`

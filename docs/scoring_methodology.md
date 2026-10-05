# Scoring Methodology & Cryptographic Mathematics

## 1. Objective & Philosophy

Traditional password meters rely on simplistic regex checks (e.g. "contains uppercase, lowercase, digit, and symbol"). This leads to bad security behavior: users pick predictable words with trivial substitutions (e.g. `Password123!`), which meet the regex requirements but are easily cracked by automated dictionary rules.

The **Password Intelligence Analyzer** implements an **explainable, threat-informed scoring methodology** designed to reflect actual attacker capabilities.

> [!NOTE]
> **Defensive Indicator Principle:** No heuristic score can provide a mathematically absolute guarantee against compromise. Security depends on hashing parameters, breached database exposure, salting, rate limiting, and attacker budget. This model provides an educational defensive indicator.

---

## 2. Mathematical Foundations

### 2.1 Character Pool Size ($S$)
Theoretical search space depends on the character classes present in the credential:
$$S = \sum_{c \in \text{Classes Present}} |\text{Class}|$$
- Lowercase Latin: 26 symbols
- Uppercase Latin: 26 symbols
- Numeric Digits: 10 symbols
- Punctuation & Symbols: 33 symbols
- Whitespace: 1 symbol
- Unicode additions: Dynamically sized based on unique Unicode blocks ($S \ge 100$)

### 2.2 Combinatorial Search Space Entropy
For a password of length $L$ selected uniformly at random from pool size $S$, the theoretical search space in bits is:
$$E_{\text{charset}} = L \cdot \log_2(S)$$

### 2.3 Information-Theoretic Shannon Entropy
To measure the true informational density per character and detect trivial repetitions (e.g., `aaaaaa`):
$$H = -\sum_{i=1}^{k} P(x_i) \cdot \log_2 P(x_i)$$
Where $P(x_i)$ is the empirical probability of character $x_i$ appearing in the string.
Total Shannon bits:
$$E_{\text{shannon}} = H \cdot L$$
For an all-identical string `aaaaaa`, $H = 0.0$ bits/char, yielding $E_{\text{shannon}} = 0.0$ bits regardless of length.

### 2.4 Effective Entropy ($E_{\text{eff}}$)
Attackers do not brute force characters independently; they use rule-based dictionaries, mask attacks, and Markov models. Discovered structural patterns reduce the true search space:
$$E_{\text{eff}} = \max\left(0, \min(E_{\text{charset}}, E_{\text{shannon}}) - \sum \text{Penalties}\right)$$

---

## 3. Structural & Lexical Penalty Ledger

| Weakness Category | Detection Criteria | Entropy Penalty | Score Deduction | Attacker Exploitation Vector |
| :--- | :--- | :--- | :--- | :--- |
| **Exact Common Password** | Match in top breached list | -40.0 bits | -60 pts | Precomputed rainbow tables, top wordlist checks (first 100 attempts). |
| **Leetspeak Mutation** | Inverted leetspeak matches common word | -28.0 bits | -40 pts | Automated Hashcat rules (e.g., `best64.rule`, `d3ad0ne.rule`). |
| **Dictionary Root Word** | Match against standard English stem | -22.0 bits | -35 pts | Standard dictionary attacks and wordlist combinators. |
| **Common Substring** | Embedded common word $\ge 4$ chars | -14.0 bits | -15 to -20 pts | Hybrid mask attacks (e.g., `?d?d?d?d` appended to dictionary words). |
| **Keyboard Walk** | Spatial row/col runs $\ge 3$ keys | -3.2 bits/key | -20 pts | Spatial keyboard walk dictionaries (`qwerty`, `asdfgh`). |
| **Sequential Sequence** | Numeric / alphabetical runs $\ge 3$ | -3.0 bits/char | -15 pts | Mask increment attacks (`123456`, `abcdef`). |
| **Repeated Characters** | Run of 3+ identical symbols | -3.5 bits/char | -15 pts | Run-length encoding masks and repeated character rules. |

---

## 4. Score Calculation Algorithm

The final score $S_{\text{final}} \in [0, 100]$ is computed as follows:

1. **Base Score (max 50 pts):**
   $$S_{\text{base}} = \min(35, L \times 2.5) + \text{Diversity Bonus}$$
   Where Diversity Bonus awards +5 (2 classes), +10 (3 classes), or +15 (4 classes). If all characters are identical ($|U| \le 1$), $S_{\text{base}}$ is capped at 5.0.

2. **Entropy Contribution (max 30 pts):**
   $$S_{\text{entropy}} = \min(30.0, E_{\text{eff}} \times 0.35)$$
   Passwords achieving $\ge 85$ bits of effective entropy receive the full 30 points.

3. **Explicit Bonuses (max 20 pts):**
   - $L \ge 16$: +10 pts (Length resilience)
   - $L \ge 20$: +5 pts (Passphrase scale)
   - Non-ASCII / Unicode: +5 pts
   - Pattern-free password ($L \ge 12$): +5 pts

4. **Aggregate Deductions:**
   Sum of itemized penalties from the table above.

5. **Clamping & Categorization:**
   $$S_{\text{final}} = \max(0, \min(100, \text{round}(S_{\text{raw}})))$$

| Score Range | Category | Practical Attacker Posture |
| :---: | :---: | :--- |
| **0 – 19** | `VERY_WEAK` | Cracked in milliseconds via standard automated breach lists. |
| **20 – 39** | `WEAK` | Cracked in seconds/minutes on single GPU via rule-based wordlists. |
| **40 – 59** | `MODERATE` | Vulnerable to mask/hybrid GPU attacks within hours/days. |
| **60 – 79** | `STRONG` | Resistant to offline GPU attacks; requires targeted dictionary attacks. |
| **80 – 100** | `VERY_STRONG` | Computationally infeasible to brute force offline under modern hardware. |

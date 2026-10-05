# Threat Model (STRIDE) — Password Intelligence Analyzer

## 1. Overview

The Password Intelligence Analyzer processes sensitive credential material in order to evaluate its security posture. Because the input consists of plaintext credentials, the system itself presents a high-value target if compromised.

This document details the threat landscape, assumptions, threat actors, STRIDE analysis, and residual risks.

---

## 2. System Boundaries & Assets

### Protected Assets:
1. **Plaintext Password Inputs (Primary Asset):** Must never be disclosed, logged, persisted, or exfiltrated.
2. **Analysis Output:** While aggregated strength scores are not secrets, detailed pattern descriptions could theoretically give hints to an attacker if intercepted on an insecure channel.
3. **Application Host Stability:** Local system resources must not be starved by algorithmic complexity or maliciously oversized inputs.

### Trust Boundaries:
- **Boundary 1 (User / Host Machine):** The boundary between the operator executing the tool and the local OS environment.
- **Boundary 2 (Network Boundary - API mode):** The boundary between API consumers and the local FastAPI listening port (defaults to loopback `127.0.0.1`).

---

## 3. Threat Actors

1. **Local Malicious Process / Snooper:**
   - Capabilities: Inspects disk files, log streams, environment variables, or `/proc` process argument lists.
   - Objective: Steal passwords submitted by users.
2. **Network Interceptor (Man-in-the-Middle):**
   - Capabilities: Intercepts network traffic if the API is bound to `0.0.0.0` or used across an unencrypted transport.
3. **Malicious Input Submitter (DoS Attacker):**
   - Capabilities: Submits pathological inputs (megabyte-length strings, regex bomb sequences) to cause ReDoS or process crashes.

---

## 4. STRIDE Analysis

| Threat Category | Description / Attack Scenario | Security Controls / Mitigations |
| :--- | :--- | :--- |
| **Spoofing** | An adversary impersonates the local API service to capture submitted passwords. | 1. API binds to `127.0.0.1` by default.<br>2. Clear guidance to enforce TLS reverse-proxy if exposed beyond loopback. |
| **Tampering** | An attacker modifies the packaged dictionary files or scoring tables to make weak passwords appear strong. | 1. Package resources are packaged as immutable read-only assets.<br>2. Wordlist hash checks on initialization. |
| **Repudiation** | Ambiguity regarding why a password scored poorly or strongly. | 1. Full explainable audit trace with itemized deductions and bonuses.<br>2. Explicit documented formulas for entropy and crack time. |
| **Information Disclosure** | Plaintext passwords leak through log files, stdout/stderr, stack traces, or terminal history. | 1. **Masked input:** CLI uses `getpass` or stdin streaming.<br>2. **Zero password echoing:** Passwords are never echoed back in responses or CLI output.<br>3. **Zero credential logging:** Logging frameworks filter out sensitive request bodies.<br>4. **Clean exception handling:** Uncaught exceptions omit input values from tracebacks. |
| **Denial of Service** | Pathological inputs cause extreme CPU / memory utilization (ReDoS or memory exhaustion). | 1. Input length limit enforced (maximum 512 characters).<br>2. Deterministic $O(N)$ string pattern algorithms instead of exponential backtracking regexes. |
| **Elevation of Privilege** | An attacker gains root access or code execution via input injection. | 1. Pure Python computation with zero shell execution (`shell=False`).<br>2. Dockerfile runs as an unprivileged dedicated user (`appuser`, non-root UID 10001). |

---

## 5. Residual Risk & Out-of-Scope Items

- **Compromised Host OS:** If the host machine has kernel-level malware, keyloggers, or memory dump tools (e.g. `gdb`, `/dev/mem`), in-memory strings cannot be completely protected in Python due to interpreter memory management.
- **Physical Shoulder Surfing:** Mitigated in CLI by using terminal echo masking (`getpass`).

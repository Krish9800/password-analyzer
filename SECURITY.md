# Security Policy

## Reporting Security Issues

We take the security of this project seriously. If you discover a vulnerability or security issue within the Password Intelligence Analyzer, please report it responsibly.

### Reporting Procedure
Please **do not** report security vulnerabilities via public GitHub issues. Instead, submit a security advisory via GitHub or contact the maintainers with:
- A description of the issue.
- Steps to reproduce or proof-of-concept.
- Potential impact and threat vector.

## Core Security & Privacy Guarantees

1. **No Credential Persistence:**
   Under no circumstances does this application store, persist, log, transmit, or cache submitted passwords.
2. **Local Processing:**
   All cryptographic, pattern, and dictionary evaluations are performed purely within local process memory.
3. **No External Network Dependencies:**
   No network requests are dispatched during password evaluation.
4. **Log Sanitization:**
   Standard logging handlers filter out sensitive arguments to prevent unintended exposure in system journals or logging collectors.

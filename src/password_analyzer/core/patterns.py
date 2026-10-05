"""Pattern detection engine: repeated, sequential, and keyboard spatial patterns."""

from password_analyzer.models.analysis import PatternFinding, PatternType, Severity

# Keyboard layout models for walk detection
KEYBOARD_ROWS = [
    "`1234567890-=",
    "~!@#$%^&*()_+",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

KEYBOARD_COLS = [
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/",
    "!QAZ",
    "@WSX",
    "#EDC",
    "$RFV",
    "%TGB",
    "^YHN",
    "&UJM",
    "*IK<",
    "(OL>",
    ")P:?",
]

KEYPAD_RUNS = [
    "789",
    "456",
    "123",  # Rows
    "741",
    "852",
    "963",  # Cols
    "159",
    "753",  # Diagonals
]


def detect_repeated_characters(password: str) -> list[PatternFinding]:
    """Detect consecutive identical characters (e.g. 'aaaa', '1111').

    Identifies runs of 3 or more identical characters in linear time.
    """
    findings: list[PatternFinding] = []
    if len(password) < 3:
        return findings

    i = 0
    while i < len(password):
        char = password[i]
        run_len = 1
        while i + run_len < len(password) and password[i + run_len] == char:
            run_len += 1

        if run_len >= 3:
            severity = Severity.HIGH if run_len >= 5 else Severity.MEDIUM
            penalty = round(run_len * 3.5, 2)
            findings.append(
                PatternFinding(
                    pattern_type=PatternType.REPEATED_CHARS,
                    matched_pattern=f"'{char}' repeated {run_len} times",
                    start_index=i,
                    end_index=i + run_len,
                    length=run_len,
                    severity=severity,
                    description=(
                        f"Consecutive identical character '{char}' repeated {run_len} times."
                    ),
                    entropy_penalty_bits=penalty,
                )
            )
            i += run_len
        else:
            i += 1

    return findings


def detect_substring_repetitions(password: str) -> list[PatternFinding]:
    """Detect repetitive substrings/blocks (e.g. 'abcabc', 'passpass')."""
    findings: list[PatternFinding] = []
    length = len(password)
    if length < 4:
        return findings

    # Look for repeating blocks up to length 16 in linear time
    max_block_len = min(16, length // 2)
    for block_len in range(2, max_block_len + 1):
        start = 0
        while start <= length - 2 * block_len:
            block = password[start : start + block_len]
            if len(set(block)) == 1:
                start += 1
                continue
            repeats = 1
            idx = start + block_len
            while idx + block_len <= length and password[idx : idx + block_len] == block:
                repeats += 1
                idx += block_len

            if repeats >= 2:
                total_len = repeats * block_len
                penalty = round(total_len * 2.5, 2)
                findings.append(
                    PatternFinding(
                        pattern_type=PatternType.SUBSTRING_REPEAT,
                        matched_pattern=f"Block of {block_len} chars repeated {repeats} times",
                        start_index=start,
                        end_index=start + total_len,
                        length=total_len,
                        severity=Severity.HIGH if repeats > 2 else Severity.MEDIUM,
                        description=(
                            f"Repeated block pattern of length {block_len} repeated "
                            f"{repeats} times consecutively."
                        ),
                        entropy_penalty_bits=penalty,
                    )
                )
                return findings
            start += 1

    return findings


def detect_sequential_patterns(password: str) -> list[PatternFinding]:
    """Detect alphabetic and numeric sequential progressions in linear time."""
    findings: list[PatternFinding] = []
    length = len(password)
    if length < 3:
        return findings

    # Numeric sequence detection
    i = 0
    while i < length - 2:
        if password[i].isdigit():
            asc_len = 1
            desc_len = 1
            while (
                i + asc_len < length
                and password[i + asc_len].isdigit()
                and int(password[i + asc_len]) == (int(password[i + asc_len - 1]) + 1) % 10
            ):
                asc_len += 1

            while (
                i + desc_len < length
                and password[i + desc_len].isdigit()
                and int(password[i + desc_len]) == (int(password[i + desc_len - 1]) - 1) % 10
            ):
                desc_len += 1

            run_len = max(asc_len, desc_len)
            if run_len >= 3:
                direction = "ascending" if asc_len >= desc_len else "descending"
                severity = Severity.HIGH if run_len >= 5 else Severity.MEDIUM
                penalty = round(run_len * 3.0, 2)
                findings.append(
                    PatternFinding(
                        pattern_type=PatternType.SEQUENTIAL_NUMERIC,
                        matched_pattern=f"Numeric {direction} sequence of {run_len} digits",
                        start_index=i,
                        end_index=i + run_len,
                        length=run_len,
                        severity=severity,
                        description=(
                            f"Sequential {direction} numeric sequence spanning {run_len} digits."
                        ),
                        entropy_penalty_bits=penalty,
                    )
                )
                i += run_len
                continue
        i += 1

    # Alphabetic sequence detection
    lower_pwd = password.lower()
    j = 0
    while j < length - 2:
        if lower_pwd[j].isalpha():
            asc_len = 1
            desc_len = 1
            while (
                j + asc_len < length
                and lower_pwd[j + asc_len].isalpha()
                and ord(lower_pwd[j + asc_len]) == ord(lower_pwd[j + asc_len - 1]) + 1
            ):
                asc_len += 1

            while (
                j + desc_len < length
                and lower_pwd[j + desc_len].isalpha()
                and ord(lower_pwd[j + desc_len]) == ord(lower_pwd[j + desc_len - 1]) - 1
            ):
                desc_len += 1

            run_len = max(asc_len, desc_len)
            if run_len >= 3:
                direction = "ascending" if asc_len >= desc_len else "descending"
                severity = Severity.HIGH if run_len >= 5 else Severity.MEDIUM
                penalty = round(run_len * 3.0, 2)
                findings.append(
                    PatternFinding(
                        pattern_type=PatternType.SEQUENTIAL_ALPHA,
                        matched_pattern=f"Alphabetic {direction} sequence of {run_len} chars",
                        start_index=j,
                        end_index=j + run_len,
                        length=run_len,
                        severity=severity,
                        description=(
                            f"Sequential {direction} alphabetical sequence "
                            f"spanning {run_len} letters."
                        ),
                        entropy_penalty_bits=penalty,
                    )
                )
                j += run_len
                continue
        j += 1

    return findings


def detect_keyboard_walks(password: str) -> list[PatternFinding]:
    """Detect spatial keyboard walks along rows, columns, and keypads in linear time."""
    findings: list[PatternFinding] = []
    length = len(password)
    if length < 3:
        return findings

    lower_pwd = password.lower()
    all_walk_paths = (
        KEYBOARD_ROWS
        + [r[::-1] for r in KEYBOARD_ROWS]
        + [c.lower() for c in KEYBOARD_COLS]
        + [c.lower()[::-1] for c in KEYBOARD_COLS]
        + KEYPAD_RUNS
    )

    i = 0
    while i < length - 2:
        best_run = 0
        prefix = lower_pwd[i : i + 3]
        for path in all_walk_paths:
            if prefix in path:
                run_len = 3
                while i + run_len <= length and lower_pwd[i : i + run_len] in path:
                    run_len += 1
                run_len -= 1
                if run_len > best_run:
                    best_run = run_len

        if best_run >= 3:
            penalty = round(best_run * 3.2, 2)
            findings.append(
                PatternFinding(
                    pattern_type=PatternType.KEYBOARD_WALK,
                    matched_pattern=f"Keyboard walk ({best_run} keys)",
                    start_index=i,
                    end_index=i + best_run,
                    length=best_run,
                    severity=Severity.HIGH if best_run >= 4 else Severity.MEDIUM,
                    description=f"Spatial keyboard layout walk of {best_run} keys.",
                    entropy_penalty_bits=penalty,
                )
            )
            i += best_run
        else:
            i += 1

    return findings


def analyze_all_patterns(password: str) -> list[PatternFinding]:
    """Execute all pattern analysis engines and return aggregated findings."""
    all_findings: list[PatternFinding] = []
    all_findings.extend(detect_repeated_characters(password))
    all_findings.extend(detect_substring_repetitions(password))
    all_findings.extend(detect_sequential_patterns(password))
    all_findings.extend(detect_keyboard_walks(password))
    return all_findings

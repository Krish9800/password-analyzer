"""Character set and composition analyzer."""

import string

from password_analyzer.models.analysis import CharacterSetAnalysis


def analyze_character_set(password: str) -> CharacterSetAnalysis:
    """Analyze character diversity, length, and theoretical pool space size.

    Args:
        password: Raw password string.

    Returns:
        CharacterSetAnalysis with detailed counts and pool size.
    """
    total_len = len(password)
    if total_len == 0:
        return CharacterSetAnalysis(
            total_length=0,
            unique_characters=0,
            lowercase_count=0,
            uppercase_count=0,
            digit_count=0,
            symbol_count=0,
            whitespace_count=0,
            unicode_count=0,
            character_pool_size=0,
        )

    unique_chars = len(set(password))
    lower_cnt = 0
    upper_cnt = 0
    digit_cnt = 0
    symbol_cnt = 0
    space_cnt = 0
    unicode_cnt = 0

    has_lower = False
    has_upper = False
    has_digit = False
    has_symbol = False
    has_space = False
    has_unicode = False

    punctuation_set = set(string.punctuation)

    for char in password:
        if char in string.ascii_lowercase:
            lower_cnt += 1
            has_lower = True
        elif char in string.ascii_uppercase:
            upper_cnt += 1
            has_upper = True
        elif char in string.digits:
            digit_cnt += 1
            has_digit = True
        elif char in punctuation_set:
            symbol_cnt += 1
            has_symbol = True
        elif char.isspace():
            space_cnt += 1
            has_space = True
        elif ord(char) > 127:
            unicode_cnt += 1
            has_unicode = True
        else:
            # Fallback for other printable or non-standard ASCII symbols
            symbol_cnt += 1
            has_symbol = True

    # Compute theoretical pool size based on character classes present
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 33
    if has_space:
        pool_size += 1
    if has_unicode:
        # Approximate common unicode block size contribution
        pool_size += max(100, unicode_cnt * 20)

    return CharacterSetAnalysis(
        total_length=total_len,
        unique_characters=unique_chars,
        lowercase_count=lower_cnt,
        uppercase_count=upper_cnt,
        digit_count=digit_cnt,
        symbol_count=symbol_cnt,
        whitespace_count=space_cnt,
        unicode_count=unicode_cnt,
        character_pool_size=pool_size,
    )

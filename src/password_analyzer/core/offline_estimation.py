"""Offline password guessing resistance estimation engine."""

import math
from typing import TypedDict

from password_analyzer.models.analysis import CrackScenario, OfflineGuessingEstimate


class BenchmarkScenarioDef(TypedDict):
    """Schema for offline benchmark attack definitions."""

    name: str
    category: str
    hardware: str
    rate_desc: str
    rate_per_sec: float


# Benchmark attack rates in guesses per second based on standard Hashcat / John the Ripper metrics
BENCHMARK_SCENARIOS: list[BenchmarkScenarioDef] = [
    {
        "name": "Fast Hash (MD5 / NTLM) — Single Consumer GPU",
        "category": "Offline Unsalted / Fast Hash",
        "hardware": "NVIDIA RTX 4090 (Single GPU)",
        "rate_desc": "100 Billion guesses/sec (100 GH/s)",
        "rate_per_sec": 1.0e11,
    },
    {
        "name": "Fast Hash (MD5 / NTLM) — 8-GPU Cracking Cluster",
        "category": "Offline Unsalted / Fast Hash",
        "hardware": "8x NVIDIA RTX 4090 Dedicated Rig",
        "rate_desc": "1 Trillion guesses/sec (1 TH/s)",
        "rate_per_sec": 1.0e12,
    },
    {
        "name": "Standard Cryptographic Hash (SHA-256) — Consumer GPU",
        "category": "Offline Fast Cryptographic Hash",
        "hardware": "NVIDIA RTX 4090 (Single GPU)",
        "rate_desc": "10 Billion guesses/sec (10 GH/s)",
        "rate_per_sec": 1.0e10,
    },
    {
        "name": "Slow Key Derivation (bcrypt, cost=12) — GPU Assisted",
        "category": "Offline Slow KDF (Recommended Baseline)",
        "hardware": "Modern Dedicated GPU Cluster",
        "rate_desc": "10,000 hashes/sec (10 kH/s)",
        "rate_per_sec": 10000.0,
    },
    {
        "name": "Memory-Hard KDF (Argon2id, 64MB RAM) — Modern Server",
        "category": "Offline Modern Memory-Hard KDF",
        "hardware": "High-End Multicore CPU / Server",
        "rate_desc": "2,000 hashes/sec (2 kH/s)",
        "rate_per_sec": 2000.0,
    },
    {
        "name": "Online Throttled Attack (Web Service)",
        "category": "Online Protected Login Surface",
        "hardware": "Distributed Botnet (Rate-limited to 100 req/hr)",
        "rate_desc": "100 attempts / hour (~0.027/sec)",
        "rate_per_sec": 100.0 / 3600.0,
    },
]


def format_duration(seconds: float) -> str:
    """Convert a duration in seconds into clear human-readable time."""
    if seconds <= 0:
        return "Instant (< 1 second)"
    if seconds < 1:
        return "Instant (< 1 second)"
    if seconds < 60:
        return f"{math.ceil(seconds)} seconds"
    if seconds < 3600:
        mins = round(seconds / 60, 1)
        return f"{mins} minutes"
    if seconds < 86400:
        hrs = round(seconds / 3600, 1)
        return f"{hrs} hours"
    if seconds < 2592000:  # 30 days
        days = round(seconds / 86400, 1)
        return f"{days} days"
    if seconds < 31536000:  # 365 days
        months = round(seconds / 2592000, 1)
        return f"{months} months"
    if seconds < 3153600000:  # 100 years
        years = round(seconds / 31536000, 1)
        return f"{years} years"
    if seconds < 315360000000:  # 10,000 years
        centuries = round(seconds / 3153600000, 1)
        return f"{centuries} centuries"
    return "> 10,000 years (Practically Uncrackable via Brute Force)"


def estimate_offline_guessing(effective_entropy_bits: float) -> OfflineGuessingEstimate:
    """Calculate estimated crack times across standard attacker hardware profiles.

    On average, brute-force or dictionary search finds the secret after searching 50%
    of the effective search space (2^(effective_entropy_bits - 1) attempts).

    Args:
        effective_entropy_bits: Pattern-discounted effective entropy in bits.

    Returns:
        OfflineGuessingEstimate with multiple attack scenarios.
    """
    if effective_entropy_bits <= 0.0:
        # Zero entropy (empty or trivially known 1-guess credential)
        scenarios: list[CrackScenario] = []
        for b in BENCHMARK_SCENARIOS:
            scenarios.append(
                CrackScenario(
                    scenario_name=b["name"],
                    attack_category=b["category"],
                    hash_rate_description=b["rate_desc"],
                    hash_rate_per_sec=b["rate_per_sec"],
                    estimated_seconds=0.0,
                    human_readable_time="Instant (< 1 second)",
                    attacker_hardware=b["hardware"],
                )
            )
        return OfflineGuessingEstimate(scenarios=scenarios)

    # Average attempts needed is 2^(effective_entropy - 1)
    # Use log2 to avoid integer overflow when effective_entropy_bits is large
    avg_attempts_log2 = max(0.0, effective_entropy_bits - 1.0)

    scenarios = []
    for b in BENCHMARK_SCENARIOS:
        rate = b["rate_per_sec"]
        rate_log2 = math.log2(rate)

        # Seconds = attempts / rate => log2(seconds) = log2(attempts) - log2(rate)
        sec_log2 = avg_attempts_log2 - rate_log2

        if sec_log2 > 60:
            # Over 2^60 seconds (~36 billion years)
            est_seconds = 1e20
            time_str = "> 10,000 years (Practically Uncrackable via Brute Force)"
        elif sec_log2 < -10:
            est_seconds = 0.0
            time_str = "Instant (< 1 second)"
        else:
            est_seconds = 2.0**sec_log2
            time_str = format_duration(est_seconds)

        scenarios.append(
            CrackScenario(
                scenario_name=b["name"],
                attack_category=b["category"],
                hash_rate_description=b["rate_desc"],
                hash_rate_per_sec=rate,
                estimated_seconds=round(est_seconds, 2) if est_seconds < 1e10 else est_seconds,
                human_readable_time=time_str,
                attacker_hardware=b["hardware"],
            )
        )

    return OfflineGuessingEstimate(scenarios=scenarios)

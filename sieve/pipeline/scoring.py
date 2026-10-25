"""Deterministic severity (research doc 6.3). The LLM never reads or writes these numbers.

S = min(100, 50*L/15 + w_a*A + w_v*V + w_t*T + w_c*C + w_n*N + w_r*log2(1+n))
Overrides (always critical): success after brute force from the same source; tripwire + execution/persistence.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..config import Settings

AUTH_FAIL_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login", "win_authentication_failed"}
AUTH_OK_GROUPS = {"authentication_success"}
EXEC_PERSIST_TACTICS = {"Execution", "Persistence", "Privilege Escalation"}
BAND_ORDER = ["low", "medium", "high", "critical"]


@dataclass
class ScoreInput:
    max_level: int
    agent_criticality: float
    vuln: bool
    intel: bool
    tactics: list[str]
    novelty: bool
    alert_count: int
    # ordered (timestamp-sorted) list of (groups, srcip) for override rules
    sequence: list[tuple[list[str], str | None]] = field(default_factory=list)
    tripwire: bool = False


@dataclass
class ScoreResult:
    score: float
    band: str
    breakdown: list[dict]
    overrides: list[str]


def band_for(score: float, s: Settings) -> str:
    if score >= s.bands.critical:
        return "critical"
    if score >= s.bands.high:
        return "high"
    if score >= s.bands.medium:
        return "medium"
    return "low"


def success_after_bruteforce(seq: list[tuple[list[str], str | None]], min_failures: int = 5) -> bool:
    fails: dict[str | None, int] = {}
    for groups, ip in seq:
        g = set(groups)
        if g & AUTH_FAIL_GROUPS:
            fails[ip] = fails.get(ip, 0) + 1
        elif g & AUTH_OK_GROUPS and ip and fails.get(ip, 0) >= min_failures:
            return True
    return False


def compute(inp: ScoreInput, s: Settings) -> ScoreResult:
    w = s.weights
    parts: list[tuple[str, float]] = [(f"Wazuh rule level {inp.max_level}", 50 * inp.max_level / 15)]
    if inp.agent_criticality:
        label = "critical" if inp.agent_criticality >= 1 else "normal"
        parts.append((f"Asset tagged {label}", w.asset * inp.agent_criticality))
    if inp.vuln:
        parts.append(("Unpatched related vulnerability", w.vuln))
    if inp.intel:
        parts.append(("Indicator on a threat-intel list", w.intel))
    c = min(1.0, len(set(inp.tactics)) / 4)
    if c:
        parts.append((f"Attack chain: {len(set(inp.tactics))} ATT&CK tactics", w.chain * c))
    if inp.novelty:
        parts.append(("First-seen behaviour for this entity", w.novelty))
    if inp.alert_count > 1:
        parts.append((f"Volume: {inp.alert_count} alerts", w.volume * math.log2(1 + inp.alert_count)))
    score = min(100.0, sum(p for _, p in parts))
    band = band_for(score, s)
    overrides: list[str] = []
    if success_after_bruteforce(inp.sequence):
        overrides.append("Successful login after brute force from the same source")
    if inp.tripwire and set(inp.tactics) & EXEC_PERSIST_TACTICS:
        overrides.append("Tripwire hit on an entity showing execution or persistence")
    if overrides:
        band = "critical"
    breakdown = [{"label": lbl, "points": round(p)} for lbl, p in parts]
    return ScoreResult(score=round(score, 1), band=band, breakdown=breakdown, overrides=overrides)

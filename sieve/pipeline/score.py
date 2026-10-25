"""Deterministic severity score.  The LLM NEVER touches this.

This is the only module that sets severity, band or override (ADR-001, ADR-003).

Formula (research doc §6.3):
    S = min(100, (50 * L/15) + w_a*A + w_v*V + w_t*T + w_c*C + w_n*N + w_r*log2(1+n))

C is chain progress: distinct ATT&CK tactics seen on the entity (host) in the last 24 h, divided by
4, capped at 1. When the caller does not supply the entity's tactics, the incident's own are used.

Override rules (always escalate the band to Critical; the score itself is reported unchanged so the
breakdown stays honest):
    * A successful login after a brute force from the same source on the same host.
    * Any tripwire hit on a host that also shows execution or persistence.

Bands: >=80 critical | >=60 high | >=40 medium | <40 low (configurable).
"""
from __future__ import annotations

import math
from typing import Literal

from ..config import Settings
from ..models import Incident
from .group import _chain_score, _tactics_seen, tactic_key

Band = Literal["critical", "high", "medium", "low"]
BAND_ORDER = ["low", "medium", "high", "critical"]

BRUTE_GROUPS = {"authentication_failures", "authentication_failed", "brute_force", "invalid_login",
                "win_authentication_failed"}
SUCCESS_GROUPS = {"authentication_success", "authentication_successful"}
EXEC_TACTICS = {"execution", "persistence", "privilege-escalation", "lateral-movement"}
MIN_FAILURES = 5

OVERRIDE_BRUTE = "Successful login after brute force from the same source: always critical"
OVERRIDE_TRIPWIRE = "Tripwire hit on a host showing execution or persistence: always critical"


def band_rank(band: str | None) -> int:
    return BAND_ORDER.index(band) if band in BAND_ORDER else -1


def _band(score: float, bands) -> Band:
    if score >= bands.critical:
        return "critical"
    if score >= bands.high:
        return "high"
    if score >= bands.medium:
        return "medium"
    return "low"


def success_after_bruteforce(seq: list[tuple[list[str], str | None]], min_failures: int = MIN_FAILURES) -> bool:
    """True when, in time order, a success from IP x follows at least ``min_failures`` failures from x."""
    fails: dict[str | None, int] = {}
    for groups, ip in seq:
        g = set(groups)
        if g & BRUTE_GROUPS:
            fails[ip] = fails.get(ip, 0) + 1
        elif g & SUCCESS_GROUPS and ip and fails.get(ip, 0) >= min_failures:
            return True
    return False


# Display order for chain labels. Credential access is placed before initial access because, in a
# brute-force story, guessing the password is what enables the access.
_ORDER = {t: i for i, t in enumerate([
    "reconnaissance", "resource-development", "credential-access", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment", "defense-evasion",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"])}


def _chain_label(tactics: set[str]) -> str:
    names = [t.replace("-", " ") for t in sorted(tactics, key=lambda t: (_ORDER.get(t, 99), t))]
    if len(names) <= 3:
        return "Attack chain: " + ", then ".join(names)
    return f"Attack chain: {len(names)} ATT&CK tactics"


def compute_score(
    incident: Incident,
    settings: Settings,
    novelty: bool,
    vuln_match: bool,
    intel_hit: bool,
    recent_alert_groups: list[list[str]],  # groups of all alerts in the incident
    *,
    sequence: list[tuple[list[str], str | None]] | None = None,
    entity_tactics: set[str] | list[str] | None = None,
    extra_overrides: list[tuple[str, str]] | None = None,
) -> tuple[float, Band, list[dict], list[str]]:
    """Return (score, band, breakdown_rows, override_reasons).

    ``sequence`` is the time-ordered (groups, srcip) list; when given, the brute-force override
    requires failures and success from the same source in that order. Without it (legacy callers)
    the override falls back to "both kinds of alert are in the incident".
    """
    w = settings.weights
    b = settings.bands

    max_level = max((a.level for a in incident.alerts), default=0)
    L_score = 50.0 * max_level / 15.0

    A = settings.criticality(incident.agent_name)
    V = 1.0 if vuln_match else 0.0
    T = 1.0 if intel_hit else 0.0
    tactics = {tactic_key(t) for t in entity_tactics} if entity_tactics is not None else _tactics_seen(incident)
    tactics |= _tactics_seen(incident)
    C = _chain_score(tactics)
    N = 1.0 if novelty else 0.0
    n = incident.alert_count or 1
    R = math.log2(1 + n)

    # (key, label, factor, weight): points = factor * weight. Keys let weight tuning re-score history.
    parts: list[tuple[str, str, float, float]] = [("level", f"Wazuh rule level {max_level}", L_score, 1.0)]
    if A:
        label = settings.criticality_label(incident.agent_name)
        parts.append(("asset", f"{incident.agent_name or 'Host'} is tagged {label}", A, w.asset))
    if V:
        parts.append(("vuln", "Unpatched critical or high vulnerability on this host", V, w.vuln))
    if T:
        parts.append(("intel", "Source IP on a threat-intel list", T, w.intel))
    if C:
        parts.append(("chain", _chain_label(tactics), C, w.chain))
    if N:
        parts.append(("novelty", "First-seen behaviour for this entity in 14 days", N, w.novelty))
    if n > 1:
        parts.append(("volume", f"Volume: {n} alerts", R, w.volume))

    score = min(100.0, sum(f * wt for _, _, f, wt in parts))
    band: Band = _band(score, b)

    overrides: list[str] = []
    flat = {g for gs in recent_alert_groups for g in gs}
    if sequence is not None:
        brute_then_success = success_after_bruteforce(sequence)
    else:
        brute_then_success = bool(BRUTE_GROUPS & flat) and bool(SUCCESS_GROUPS & flat)
    if brute_then_success:
        overrides.append(OVERRIDE_BRUTE)
    if incident.tripwire and (EXEC_TACTICS & tactics):
        overrides.append(OVERRIDE_TRIPWIRE)
    if overrides:
        band = "critical"

    # Severity floors (deterministic, configurable): some single events always matter.
    techniques = {t for a in incident.alerts for t in (a.mitre_ids or [])}
    crit_asset = settings.criticality_label(incident.agent_name) == "critical"
    for fl in settings.floors:
        if not fl.enabled:
            continue
        hit_level = fl.min_level is not None and max_level >= fl.min_level
        hit_tech = bool(fl.techniques) and any(t == x or t.startswith(x + ".") for t in techniques for x in fl.techniques)
        if not (hit_level or hit_tech) or (fl.critical_asset_only and not crit_asset):
            continue
        if band_rank(fl.band) > band_rank(band):
            band = fl.band
            overrides.append(f"Floor: {fl.name} is always at least {fl.band}")
    for name, fb in extra_overrides or []:
        overrides.append(f"Correlation rule: {name}")
        if band_rank(fb) > band_rank(band):
            band = fb

    breakdown = [{"key": k, "label": lbl, "factor": round(f, 4), "weight": wt, "points": round(f * wt, 1)}
                 for k, lbl, f, wt in parts]
    return round(score, 1), band, breakdown, overrides

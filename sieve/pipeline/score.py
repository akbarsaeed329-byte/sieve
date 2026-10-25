"""Deterministic severity score.  The LLM NEVER touches this.

Formula (research doc §6.3):
    S = min(100, (50 * L/15) + w_a*A + w_v*V + w_t*T + w_c*C + w_n*N + w_r*log2(1+n))

Override rules (always escalate to Critical, band clipped):
    * Successful login immediately after a brute-force from the same source on the same host.
    * Any tripwire hit on a host also showing execution or persistence tactics.

Bands: >=80 critical | >=60 high | >=40 medium | <40 low
"""
from __future__ import annotations

import math
from typing import Literal

from ..config import Settings
from ..models import Incident

Band = Literal["critical", "high", "medium", "low"]

BRUTE_GROUPS = {"authentication_failures", "authentication_failed", "brute_force"}
SUCCESS_GROUPS = {"authentication_success", "authentication_successful"}
EXEC_TACTICS = {"execution", "persistence", "privilege-escalation", "lateral-movement"}


def _band(score: float, bands) -> Band:
    if score >= bands.critical:
        return "critical"
    if score >= bands.high:
        return "high"
    if score >= bands.medium:
        return "medium"
    return "low"


def compute_score(
    incident: Incident,
    settings: Settings,
    novelty: bool,
    vuln_match: bool,
    intel_hit: bool,
    recent_alert_groups: list[list[str]],  # groups of all alerts in the incident
) -> tuple[float, Band, list[dict], list[str]]:
    """Return (score, band, breakdown_rows, override_reasons)."""
    w = settings.weights
    b = settings.bands

    # L: highest rule level across grouped alerts, normalised to 0-50
    max_level = max((a.level for a in incident.alerts), default=0)
    L_score = 50.0 * max_level / 15.0

    A = settings.criticality(incident.agent_name)
    V = 1.0 if vuln_match else 0.0
    T = 1.0 if intel_hit else 0.0

    # C: chain progress 0-1 based on distinct ATT&CK tactic span
    from .group import _chain_score, _tactics_seen
    C = _chain_score(_tactics_seen(incident))

    N = 1.0 if novelty else 0.0
    n = incident.alert_count or 1
    R = math.log2(1 + n)

    raw = (L_score + w.asset * A + w.vuln * V + w.intel * T
           + w.chain * C + w.novelty * N + w.volume * R)
    score = min(100.0, raw)

    breakdown = [
        {"label": f"Wazuh rule level {max_level}", "points": round(L_score, 1)},
        {"label": f"Asset criticality ({['test','normal','critical'][int(A*2)]})", "points": round(w.asset * A, 1)},
        {"label": "Unpatched CVE on this host", "points": round(w.vuln * V, 1)},
        {"label": "Source on threat-intel list", "points": round(w.intel * T, 1)},
        {"label": f"Attack chain progress ({len(_tactics_seen(incident))} tactics)", "points": round(w.chain * C, 1)},
        {"label": "First-seen behaviour for this entity", "points": round(w.novelty * N, 1)},
        {"label": f"Volume: {n} alerts grouped", "points": round(w.volume * R, 1)},
    ]

    # Override rules
    overrides: list[str] = []
    all_flat_groups = {g for gs in recent_alert_groups for g in gs}
    has_brute = bool(BRUTE_GROUPS & all_flat_groups)
    has_success = bool(SUCCESS_GROUPS & all_flat_groups)
    has_tripwire = incident.tripwire
    has_exec = bool(EXEC_TACTICS & set(incident.tactics or []))

    if has_brute and has_success:
        score = 100.0
        overrides.append("Successful login immediately after brute-force → always Critical")
    if has_tripwire and has_exec:
        score = 100.0
        overrides.append("Tripwire hit + execution/persistence tactic → always Critical")

    return score, _band(score, b), breakdown, overrides

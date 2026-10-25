"""Group related alerts into incidents using a sliding-window key.

Key  = (rule_id, agent_name, srcip OR user)
Window = configurable minutes, extended by each new alert, capped at max_minutes.
Incidents with overlapping entities are linked into attack chains downstream.
"""
from __future__ import annotations

from datetime import timedelta, timezone, datetime

from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Alert, Incident, utcnow
from .normalise import NormAlert

# ATT&CK tactic ordering used for chain progress scoring
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _tactics_seen(incident: Incident) -> set[str]:
    return {t.lower() for t in (incident.tactics or [])}


def _chain_score(tactics_seen: set[str]) -> float:
    """C in [0,1]: how far along the kill-chain the incident has progressed, capped at 4 steps."""
    indices = sorted(TACTIC_ORDER.index(t) for t in tactics_seen if t in TACTIC_ORDER)
    if len(indices) < 2:
        return 0.0
    span = indices[-1] - indices[0]
    return min(span / 4.0, 1.0)


def grouping_key(a: NormAlert) -> str:
    entity = a.srcip or a.user or "unknown"
    return f"{a.rule_id}|{a.agent_name or ''}|{entity}"


def find_or_create_incident(
    a: NormAlert,
    db: Session,
    settings: Settings,
    tripwire_hit: bool,
    tripwire_hits: list[dict],
) -> Incident:
    key = grouping_key(a)
    window = timedelta(minutes=settings.grouping.window_minutes)
    cap = timedelta(minutes=settings.grouping.max_minutes)
    cutoff = utcnow() - cap

    inc: Incident | None = (
        db.query(Incident)
        .filter(
            Incident.grouping_key == key,
            Incident.status.in_(["new", "acknowledged"]),
            Incident.opened_at >= cutoff,
        )
        .order_by(Incident.opened_at.desc())
        .first()
    )

    now = utcnow()
    new_tactics = list(_tactics_seen(inc) | set(a.mitre_tactics)) if inc else list(a.mitre_tactics)

    if inc is None:
        inc = Incident(
            grouping_key=key,
            title=a.description or f"Rule {a.rule_id} on {a.agent_name}",
            agent_name=a.agent_name,
            srcip=a.srcip,
            user=a.user,
            tactics=list(a.mitre_tactics),
            techniques=list(a.mitre_ids),
            alert_count=0,
            tripwire=tripwire_hit,
            tripwire_hits=tripwire_hits if tripwire_hit else [],
        )
        db.add(inc)
        db.flush()
    else:
        inc.last_seen = now
        inc.alert_count = (inc.alert_count or 0)
        inc.tactics = new_tactics
        # merge techniques deduplicated
        existing = set(inc.techniques or [])
        for t in a.mitre_ids:
            existing.add(t)
        inc.techniques = list(existing)
        if tripwire_hit:
            inc.tripwire = True
            existing_hits = list(inc.tripwire_hits or [])
            existing_hits.extend(tripwire_hits)
            inc.tripwire_hits = existing_hits

    inc.alert_count = (inc.alert_count or 0) + 1
    return inc

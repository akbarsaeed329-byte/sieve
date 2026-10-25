"""Group related alerts into incidents using a sliding-window key (research doc 6.2).

Key    = (rule_id, agent_name, srcip OR user)
Window = window_minutes after the incident's last alert, extended by each new alert, and never more
         than max_minutes after its first alert. Times are the alerts' own timestamps, so replays and
         late deliveries group exactly as live traffic would.
Chain  = when no incident has the exact key, an open incident on the same host with the same actor
         (source IP or user) inside the window is joined instead, so "brute force, then a successful
         login" is one story even though Wazuh fires different rules for the two halves.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Incident, aware
from .normalise import NormAlert, canonical_tactic

OPEN_STATUSES = ("new", "acknowledged")

# ATT&CK tactic short names in kill-chain order (kept for the coverage map and chain labels).
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def tactic_key(t: str) -> str:
    return canonical_tactic(t).lower().replace(" ", "-")


def _tactics_seen(incident: Incident) -> set[str]:
    return {tactic_key(t) for t in (incident.tactics or [])}


def _chain_score(tactics_seen: set[str]) -> float:
    """C in [0, 1]: distinct ATT&CK tactics seen on the entity, divided by 4, capped at 1 (doc 6.3)."""
    return min(len({tactic_key(t) for t in tactics_seen}) / 4.0, 1.0)


def actor(a: NormAlert) -> str:
    return a.srcip or (f"user:{a.user}" if a.user else "unknown")


def grouping_key(a: NormAlert) -> str:
    return f"{a.rule_id}|{a.agent_name or ''}|{actor(a)}"


def key_actor(key: str) -> str:
    parts = key.split("|", 2)
    return parts[2] if len(parts) == 3 else ""


def open_candidates(db: Session, a: NormAlert) -> list[Incident]:
    return (db.query(Incident)
            .filter(Incident.status.in_(OPEN_STATUSES), Incident.agent_name == a.agent_name)
            .order_by(Incident.last_seen.desc())
            .limit(200).all())


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
    ts = a.timestamp

    def fits(i: Incident) -> bool:
        last, first = aware(i.last_seen), aware(i.first_seen)
        return ts - last <= window and ts - first <= cap and first - ts <= window

    candidates = open_candidates(db, a)
    inc = next((i for i in candidates if i.grouping_key == key and fits(i)), None)
    if inc is None and actor(a) != "unknown":
        inc = next((i for i in candidates if key_actor(i.grouping_key) == actor(a) and fits(i)), None)

    if inc is None:
        inc = Incident(
            grouping_key=key,
            title=(a.description or f"Rule {a.rule_id} on {a.agent_name}")[:300],
            agent_name=a.agent_name,
            agent_id=a.agent_id,
            srcip=a.srcip,
            user=a.user,
            tactics=sorted(set(a.mitre_tactics)),
            techniques=sorted(set(a.mitre_ids)),
            alert_count=0,
            first_seen=ts, last_seen=ts, opened_at=ts,
            tripwire=tripwire_hit,
            tripwire_hits=list(tripwire_hits) if tripwire_hit else [],
            breakdown=[], overrides=[], context_notes=[],
        )
        db.add(inc)
        db.flush()
    else:
        inc.last_seen = max(aware(inc.last_seen), ts)
        inc.first_seen = min(aware(inc.first_seen), ts)
        inc.tactics = sorted(set(inc.tactics or []) | set(a.mitre_tactics))
        inc.techniques = sorted(set(inc.techniques or []) | set(a.mitre_ids))
        inc.srcip = inc.srcip or a.srcip
        inc.user = inc.user or a.user
        inc.agent_id = inc.agent_id or a.agent_id
        if tripwire_hit:
            inc.tripwire = True
            inc.tripwire_hits = list(inc.tripwire_hits or []) + list(tripwire_hits)

    inc.alert_count = (inc.alert_count or 0) + 1
    return inc

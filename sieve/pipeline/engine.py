"""Orchestrates the deterministic pipeline for one raw alert (research doc 6.1).

ingest(queue) -> normalise -> tripwire -> filter -> group -> score/enrich -> (notify + LLM, done by worker)
Idempotent: a wazuh_id seen before is skipped, so at-least-once delivery never duplicates incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Alert, Baseline, Incident, Suppression
from . import playbooks
from .filter import suppression_reason
from .normalise import normalise
from .scoring import AUTH_OK_GROUPS, BAND_ORDER, ScoreInput, compute, success_after_bruteforce
from .tripwire import scan

OPEN = ("new", "acknowledged")


def aware(d: datetime) -> datetime:
    """SQLite returns naive datetimes; everything in Sieve is UTC."""
    return d if d.tzinfo else d.replace(tzinfo=UTC)
NOVELTY_DAYS = 14


@dataclass
class Result:
    outcome: str                 # duplicate | suppressed | grouped
    incident_id: int | None = None
    should_notify: bool = False
    band: str | None = None


def _actor(srcip: str | None, user: str | None) -> str:
    return srcip or (f"user:{user}" if user else "-")


def _novel(db: Session, a, now) -> bool:
    """First-seen check: successful logins of user@host from an IP not seen in NOVELTY_DAYS."""
    if not (set(a.groups) & AUTH_OK_GROUPS and a.user and a.srcip):
        return False
    entity, feature = f"user:{a.user}@{a.agent_name}", f"srcip:{a.srcip}"
    row = db.scalar(select(Baseline).where(Baseline.entity == entity, Baseline.feature == feature))
    if row is None:
        db.add(Baseline(entity=entity, feature=feature, first_seen=now, last_seen=now))
        return True
    novel = (now - aware(row.last_seen)) > timedelta(days=NOVELTY_DAYS)
    row.last_seen = now
    return novel


def _title(inc: Incident, alerts: list[Alert], overrides: list[str]) -> str:
    if any("brute force" in o for o in overrides):
        return "Brute force, then a successful login"
    top = max(alerts, key=lambda x: x.level)
    return top.description.strip().rstrip(".")[:200] or f"Rule {top.rule_id}"


def facts(inc: Incident) -> list[dict]:
    """Deterministic, evidence-linked summary. Always available, even with no AI."""
    out: list[dict] = []
    fails = [a for a in inc.alerts if "authentication_failed" in a.groups]
    oks = [a for a in inc.alerts if AUTH_OK_GROUPS & set(a.groups)]
    if fails:
        secs = int((aware(fails[-1].timestamp) - aware(fails[0].timestamp)).total_seconds())
        out.append({"text": f"{len(fails)} failed logins from {fails[0].srcip or 'one source'} "
                            f"in {secs} seconds on {inc.agent_name}.",
                    "evidence": [f"alert:{fails[0].id}", f"alert:{fails[-1].id}"]})
    if oks:
        out.append({"text": f"Then a successful login as {oks[0].user} from {oks[0].srcip}.",
                    "evidence": [f"alert:{oks[0].id}"]})
    if not out:
        top = max(inc.alerts, key=lambda x: x.level)
        out.append({"text": f"{inc.alert_count} alert(s) of '{top.description}' on {inc.agent_name}.",
                    "evidence": [f"alert:{top.id}"]})
    for b in inc.breakdown:
        if b["label"].startswith("Indicator on a threat-intel"):
            out.append({"text": f"{inc.srcip} is on a configured threat-intel list.", "evidence": ["context:intel"]})
        if b["label"].startswith("First-seen"):
            out.append({"text": "This is first-seen behaviour for this account in the last 14 days.",
                        "evidence": ["context:baseline"]})
    if inc.tripwire:
        fields = sorted({h["field"] for h in inc.tripwire_hits})
        out.append({"text": f"Instruction-like text was found in {', '.join(fields)}; it was treated as data.",
                    "evidence": ["context:tripwire"]})
    return out


def process(db: Session, raw: dict, s: Settings) -> Result:
    a = normalise(raw)
    if db.scalar(select(Alert.id).where(Alert.wazuh_id == a.wazuh_id)) or \
       db.scalar(select(Suppression.id).where(Suppression.wazuh_id == a.wazuh_id)):
        return Result("duplicate")

    tw = scan(a.untrusted, s.tripwire_threshold)
    reason = suppression_reason(a, s, tw.triggered)
    actor = _actor(a.srcip, a.user)
    if reason and reason.startswith("below minimum"):
        # Context beats level: a low-level event (e.g. a successful login) that continues an open
        # incident from the same source on the same host is kept, so chains like
        # "brute force, then success" are never broken by the level filter.
        open_same = db.scalars(select(Incident).where(Incident.status.in_(OPEN),
                                                      Incident.agent_name == a.agent_name)).all()
        if any(i.grouping_key.split("|", 2)[2] == actor for i in open_same):
            reason = None
    if reason:
        db.add(Suppression(wazuh_id=a.wazuh_id, rule_id=a.rule_id, description=a.description, reason=reason))
        db.commit()
        return Result("suppressed")

    key = f"{a.rule_id}|{a.agent_name}|{actor}"
    window = timedelta(minutes=s.grouping.window_minutes)
    cap = timedelta(minutes=s.grouping.max_minutes)
    candidates = db.scalars(
        select(Incident).where(Incident.status.in_(OPEN), Incident.agent_name == a.agent_name)
        .order_by(Incident.last_seen.desc())).all()

    def fits(i: Incident) -> bool:
        last = aware(i.last_seen)
        first = aware(i.first_seen)
        return a.timestamp - last <= window and a.timestamp - first <= cap

    inc = next((i for i in candidates if i.grouping_key == key and fits(i)), None)
    if inc is None:  # chain link: same host and same actor, different rule
        inc = next((i for i in candidates if i.grouping_key.split("|", 2)[2] == actor and fits(i)), None)
    if inc is None:
        inc = Incident(grouping_key=key, title=a.description[:200], agent_name=a.agent_name, srcip=a.srcip,
                       user=a.user, first_seen=a.timestamp, last_seen=a.timestamp, opened_at=a.timestamp,
                       breakdown=[], overrides=[], tactics=[], techniques=[], tripwire_hits=[])
        db.add(inc)
        db.flush()

    alert = Alert(wazuh_id=a.wazuh_id, rule_id=a.rule_id, level=a.level, description=a.description,
                  agent_name=a.agent_name, srcip=a.srcip, user=a.user, groups=a.groups, mitre_ids=a.mitre_ids,
                  mitre_tactics=a.mitre_tactics, timestamp=a.timestamp, untrusted=a.untrusted,
                  full_log=a.full_log, raw=raw, incident_id=inc.id)
    db.add(alert)
    novel = _novel(db, a, a.timestamp)
    db.flush()
    db.refresh(inc)

    alerts = inc.alerts
    inc.alert_count = len(alerts)
    inc.last_seen = max(aware(inc.last_seen), a.timestamp)
    inc.tactics = sorted({t for x in alerts for t in x.mitre_tactics})
    inc.techniques = sorted({t for x in alerts for t in x.mitre_ids})
    inc.user = inc.user or a.user
    if tw.triggered:
        inc.tripwire = True
        inc.tripwire_hits = (inc.tripwire_hits or []) + [{**h, "alert_id": alert.id} for h in tw.hits]
    prior_novel = any(b["label"].startswith("First-seen") for b in (inc.breakdown or []))
    res = compute(ScoreInput(
        max_level=max(x.level for x in alerts),
        agent_criticality=s.criticality(inc.agent_name),
        vuln=False,  # TODO(phase 1): Wazuh vulnerability-detector lookup per agent
        intel=bool(inc.srcip and inc.srcip in s.intel.blocklist_ips),
        tactics=inc.tactics, novelty=novel or prior_novel, alert_count=inc.alert_count,
        sequence=[(x.groups, x.srcip) for x in sorted(alerts, key=lambda x: aware(x.timestamp))],
        tripwire=inc.tripwire), s)
    inc.score, inc.band, inc.breakdown, inc.overrides = res.score, res.band, res.breakdown, res.overrides
    inc.title = _title(inc, alerts, res.overrides)
    inc.playbook = playbooks.choose({g for x in alerts for g in x.groups}, set(inc.techniques))
    db.commit()

    rank = BAND_ORDER.index
    should = rank(inc.band) >= rank(s.notify.min_band) or inc.tripwire
    already = inc.notified_band is not None and rank(inc.notified_band) >= rank(inc.band)
    return Result("grouped", inc.id, should and not already, inc.band)


__all__ = ["Result", "facts", "process", "success_after_bruteforce"]

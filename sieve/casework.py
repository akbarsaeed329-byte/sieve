"""Case management helpers: SLA, exceptions, maintenance windows, false-positive feedback, noisy rules.

Research basis: analysts want verdicts to tune future detection ("feedback loop with SLA"), approved-
exception handling, clear ownership, and escalation when nobody picks an incident up.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlalchemy import func, select

from .config import Settings
from .models import Alert, AlertException, Incident, MaintenanceWindow, Suppression, aware, utcnow


def sla_minutes(settings: Settings, band: str) -> int:
    return int(getattr(settings.sla, band, settings.sla.low))


def set_sla(inc: Incident, settings: Settings) -> None:
    """SLA starts when the incident opens; it tightens if the band rises."""
    due = aware(inc.opened_at) + timedelta(minutes=sla_minutes(settings, inc.band))
    if inc.sla_due is None or due < aware(inc.sla_due):
        inc.sla_due = due


def matching_exception(db, na, now=None) -> AlertException | None:
    now = now or utcnow()
    rows = db.scalars(select(AlertException).where(AlertException.active.is_(True))).all()
    for x in rows:
        if x.expires_at and aware(x.expires_at) < now:
            continue
        checks = [(x.rule_id, na.rule_id), (x.agent_name, na.agent_name), (x.srcip, na.srcip), (x.user, na.user)]
        if not any(v for v, _ in checks):
            continue  # an exception with no scope would hide everything: never matches
        if all(v is None or v == actual for v, actual in checks):
            return x
    return None


def active_maintenance(db, agent_name: str | None, at) -> MaintenanceWindow | None:
    rows = db.scalars(select(MaintenanceWindow).where(MaintenanceWindow.starts_at <= at,
                                                      MaintenanceWindow.ends_at >= at)).all()
    return next((m for m in rows if m.agent_name in ("*", agent_name)), None)


def suggest_exception(inc: Incident) -> dict:
    """The narrowest exception that would have prevented this false positive."""
    rules = Counter(a.rule_id for a in inc.alerts)
    rule = rules.most_common(1)[0][0] if rules else None
    return {"rule_id": rule, "agent_name": inc.agent_name, "srcip": inc.srcip,
            "user": inc.user if not inc.srcip else None, "expires_in_days": 30,
            "explain": "Matches only this rule on this host from this source. Expires in 30 days; you can renew it."}


def noisy_rules(db, days: int = 30) -> list[dict]:
    since = utcnow() - timedelta(days=days)
    kept = dict(db.execute(select(Alert.rule_id, func.count()).where(Alert.received_at >= since)
                           .group_by(Alert.rule_id)).all())
    supp = dict(db.execute(select(Suppression.rule_id, func.count()).where(Suppression.created_at >= since)
                           .group_by(Suppression.rule_id)).all())
    fp: Counter = Counter()
    real: Counter = Counter()
    desc: dict[str, str] = {}
    for inc in db.scalars(select(Incident).where(Incident.opened_at >= since,
                                                 Incident.status.in_(("false_positive", "resolved")))):
        for r in {a.rule_id for a in inc.alerts}:
            (fp if inc.status == "false_positive" else real)[r] += 1
    for rid, d in db.execute(select(Alert.rule_id, Alert.description).where(Alert.received_at >= since)
                             .group_by(Alert.rule_id)).all():
        desc[rid] = d
    out = []
    for rid in set(kept) | set(supp) | set(fp):
        closed = fp[rid] + real[rid]
        rate = fp[rid] / closed if closed else None
        vol = kept.get(rid, 0) + supp.get(rid, 0)
        if rate is not None and rate >= 0.5 and fp[rid] >= 2:
            action = "Mostly false positives: add a scoped exception or tune the Wazuh rule."
        elif supp.get(rid, 0) > 0.9 * vol and vol > 100:
            action = "Almost always suppressed: consider disabling it in Wazuh to save processing."
        elif rate is not None and rate == 0 and real[rid] >= 2:
            action = "Reliable: incidents from this rule were real."
        else:
            action = ""
        out.append({"rule_id": rid, "description": desc.get(rid, ""), "alerts": vol, "suppressed": supp.get(rid, 0),
                    "false_positives": fp[rid], "confirmed": real[rid],
                    "fp_rate": round(rate, 2) if rate is not None else None, "suggestion": action})
    out.sort(key=lambda r: (-(r["fp_rate"] or 0), -r["alerts"]))
    return out[:100]

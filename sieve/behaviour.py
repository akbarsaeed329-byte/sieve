"""Explainable UEBA and risk-based alerting.

UEBA (adapts to your environment, explains itself in plain words):
* login hours per user: after `min_logins` successful logins, a login in an hour that holds less than
  `rare_hour_share` of that user's history is flagged ("deploy logged in at 03:00; usually 07:00-18:00").
* alert volume per host: today's count above mean + volume_sigma x stdev of the last 14 days (and above volume_min).
Findings raise the novelty term N of the score and appear as context, never as a verdict of their own.

Risk-based alerting: every kept alert adds points to its user, host and source IP, decaying with a half-life.
When an entity crosses the threshold with contributions from at least two separate incidents, one incident is
raised through the normal pipeline, listing what contributed (a single incident already tells its own story).
This catches slow attacks made of many individually harmless alerts.
"""

from __future__ import annotations

import math
import statistics
from datetime import timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from .models import BehaviourProfile, EntityRisk, aware, utcnow


def _profile(db, key: str) -> BehaviourProfile:
    p = db.get(BehaviourProfile, key)
    if p is None:
        p = BehaviourProfile(key=key, data={})
        db.add(p)
    return p


def _usual_window(hist: list[int]) -> str:
    busy = [h for h, n in enumerate(hist) if n >= max(1, 0.05 * sum(hist))]
    return f"{min(busy):02d}:00-{max(busy) + 1:02d}:00" if busy else "no clear pattern"


def login_hour(db, na, settings) -> str | None:
    if not (settings.ueba.enabled and na.user and {"authentication_success", "authentication_successful"} & set(na.groups)):
        return None
    tz = ZoneInfo(settings.profile.timezone or "UTC") if settings.profile.timezone else ZoneInfo("UTC")
    hour = aware(na.timestamp).astimezone(tz).hour
    p = _profile(db, f"login:{na.user}")
    hist = list(p.data.get("hours") or [0] * 24)
    total = sum(hist)
    finding = None
    if total >= settings.ueba.min_logins and hist[hour] / total < settings.ueba.rare_hour_share:
        finding = (
            f"Behaviour: {na.user} logged in at {hour:02d}:00, which is unusual for them "
            f"(usually {_usual_window(hist)}, from {total} past logins)."
        )
    hist[hour] += 1
    p.data, p.updated_at = {**p.data, "hours": hist}, utcnow()
    return finding


def volume_spike(db, na, settings) -> str | None:
    if not (settings.ueba.enabled and na.agent_name):
        return None
    day = aware(na.timestamp).strftime("%Y-%m-%d")
    p = _profile(db, f"volume:{na.agent_name}")
    days = dict(p.data.get("days") or {})
    days[day] = days.get(day, 0) + 1
    days = dict(sorted(days.items())[-15:])
    p.data, p.updated_at = {**p.data, "days": days}, utcnow()
    hist = [n for d, n in days.items() if d != day]
    today = days[day]
    if len(hist) < 7 or today < settings.ueba.volume_min:
        return None
    mean, sd = statistics.mean(hist), statistics.pstdev(hist) or 1.0
    if today > mean + settings.ueba.volume_sigma * sd and not p.data.get(f"flagged:{day}"):
        p.data = {**p.data, f"flagged:{day}": True}
        return f"Behaviour: {na.agent_name} produced {today} alerts today, against a usual {mean:.0f} per day."
    return None


def _decayed(r: EntityRisk, half_life_h: float) -> float:
    age_h = (utcnow() - aware(r.updated_at)).total_seconds() / 3600
    return r.points * math.pow(0.5, age_h / half_life_h)


def add_risk(db, na, inc, settings) -> list[dict]:
    """Add points for this alert; return entities that just crossed the threshold."""
    if not settings.risk.enabled:
        return []
    asset = 1.0 + settings.criticality(na.agent_name)
    pts = round((na.level / 3.0) * asset * (2.0 if inc.tripwire else 1.0), 2)
    ents = [f"host:{na.agent_name}"] if na.agent_name else []
    ents += [f"user:{na.user}"] if na.user else []
    ents += [f"ip:{na.srcip}"] if na.srcip else []
    crossed = []
    for e in ents:
        r = db.get(EntityRisk, e)
        if r is None:
            r = EntityRisk(entity=e, tenant_id=inc.tenant_id, points=0, contributors=[])
            db.add(r)
        before = _decayed(r, settings.risk.half_life_hours) if r.points else 0.0
        r.points, r.updated_at = before + pts, utcnow()
        r.contributors = [
            *(r.contributors or [])[-24:],
            {
                "rule": na.rule_id,
                "desc": (na.description or "")[:80],
                "points": pts,
                "incident": inc.id,
                "at": utcnow().isoformat(),
            },
        ]
        cool = not r.last_alerted_at or utcnow() - aware(r.last_alerted_at) > timedelta(hours=settings.risk.cooldown_hours)
        spread = len({x.get("incident") for x in r.contributors if x.get("incident")}) >= 2
        if before < settings.risk.threshold <= r.points and cool and spread:
            r.last_alerted_at = utcnow()
            crossed.append(
                {
                    "entity": e,
                    "points": round(r.points, 1),
                    "contributors": list(r.contributors),
                    "agent_name": na.agent_name,
                    "agent_id": na.agent_id,
                }
            )
    return crossed


def risk_alert(c: dict, settings) -> dict:
    kind, _, value = c["entity"].partition(":")
    rules = sorted({x["rule"] for x in c["contributors"]})
    data = {"srcip": value} if kind == "ip" else {"dstuser": value} if kind == "user" else {}
    now = utcnow()
    return {
        "id": f"sieve-risk-{c['entity']}-{now.strftime('%Y%m%d%H%M')}",
        "timestamp": now.isoformat(),
        "rule": {
            "id": "sieve-200",
            "level": 12,
            "groups": ["sieve", "risk_threshold"],
            "description": f"Risk threshold reached for {kind} {value}: {c['points']} points from "
            f"{len(c['contributors'])} alerts across {len(rules)} rules",
        },
        "agent": {"name": c["agent_name"] if kind != "host" else value, "id": c.get("agent_id") or ""},
        "data": data,
        "full_log": "Generated by Sieve risk-based alerting. Contributing rules: " + ", ".join(rules[:15]),
    }


def top_risk(db, settings, tenant_id: int | None = None, limit: int = 20) -> list[dict]:
    q = select(EntityRisk)
    if tenant_id:
        q = q.where(EntityRisk.tenant_id == tenant_id)
    rows = [(r, _decayed(r, settings.risk.half_life_hours)) for r in db.scalars(q)]
    rows = [x for x in rows if x[1] >= 1]
    rows.sort(key=lambda x: -x[1])
    return [
        {
            "entity": r.entity,
            "points": round(p, 1),
            "threshold": settings.risk.threshold,
            "contributors": (r.contributors or [])[-8:],
            "last_alerted_at": r.last_alerted_at.isoformat() if r.last_alerted_at else None,
        }
        for r, p in rows[:limit]
    ]

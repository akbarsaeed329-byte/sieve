"""Smarter triage built from what analysts asked for (docs/COMPARISON.md, v0.3):

* correlation rules ("A then B on the same entity within N minutes")
* precedents ("this happened 3 times before; all were closed as pentest by Omar")
* team routing (host globs / asset tags -> team channels and owner)
* graduated auto-close (earned per rule by analyst agreement; never for tripwire, overrides or critical)
* weight-tuning suggestions (re-score labelled history; applied only when an admin approves)
Everything here is deterministic. None of it lets a model decide anything.
"""

from __future__ import annotations

import fnmatch
from collections import Counter
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select

from .config import Route, Settings
from .models import Alert, AuditEvent, Comment, CorrelationRule, Incident, aware, utcnow
from .pipeline.score import BAND_ORDER, band_rank

# ---------------- correlation rules ----------------


def cond_matches(cond: dict, a) -> bool:
    rules = {str(r) for r in cond.get("rule_ids") or []}
    groups = set(cond.get("groups") or [])
    techs = list(cond.get("techniques") or [])
    if not (rules or groups or techs):
        return False
    ok_r = not rules or str(a.rule_id) in rules
    ok_g = not groups or bool(groups & set(a.groups or []))
    ok_t = not techs or any(t == x or t.startswith(x + ".") for t in (a.mitre_ids or []) for x in techs)
    return ok_r and ok_g and ok_t


def correlation_hits(db, a: Alert) -> list[tuple[CorrelationRule, int]]:
    """Rules whose THEN matches this alert and whose FIRST occurred earlier on the same entity."""
    out = []
    for rule in db.scalars(select(CorrelationRule).where(CorrelationRule.enabled.is_(True))).all():
        if not cond_matches(rule.then or {}, a):
            continue
        q = select(Alert).where(
            Alert.id != a.id,
            Alert.timestamp <= a.timestamp,
            Alert.timestamp >= aware(a.timestamp) - timedelta(minutes=rule.within_minutes),
        )
        for key in rule.same or []:
            v = getattr(a, key, None)
            if not v:
                q = None
                break
            q = q.where(getattr(Alert, key) == v)
        if q is None:
            continue
        earlier = [x for x in db.scalars(q.limit(2000)).all() if cond_matches(rule.first or {}, x)]
        if len(earlier) >= int((rule.first or {}).get("min_count", 1)):
            out.append((rule, len(earlier)))
    return out


def backtest_correlation(db, rule: CorrelationRule, days: int = 30) -> dict:
    since = utcnow() - timedelta(days=days)
    hits, incs = 0, set()
    for a in db.scalars(select(Alert).where(Alert.timestamp >= since).order_by(Alert.timestamp)).yield_per(500):
        if not cond_matches(rule.then or {}, a):
            continue
        q = select(Alert).where(
            Alert.id != a.id,
            Alert.timestamp <= a.timestamp,
            Alert.timestamp >= aware(a.timestamp) - timedelta(minutes=rule.within_minutes),
        )
        skip = False
        for key in rule.same or []:
            v = getattr(a, key, None)
            if not v:
                skip = True
                break
            q = q.where(getattr(Alert, key) == v)
        if skip:
            continue
        if sum(1 for x in db.scalars(q.limit(2000)) if cond_matches(rule.first or {}, x)) >= int(
            (rule.first or {}).get("min_count", 1)
        ):
            hits += 1
            if a.incident_id:
                incs.add(a.incident_id)
    return {"would_fire": hits, "incidents": sorted(incs)[:50], "days": days}


# ---------------- precedents ----------------


def precedents(db, inc: Incident, days: int = 180) -> dict:
    since = utcnow() - timedelta(days=days)
    rules = {a.rule_id for a in inc.alerts}
    conds = []
    if inc.srcip:
        conds.append(Incident.srcip == inc.srcip)
    if inc.user and inc.agent_name:
        conds.append((Incident.user == inc.user) & (Incident.agent_name == inc.agent_name))
    rows = (
        db.scalars(
            select(Incident).where(
                Incident.id != inc.id,
                Incident.opened_at >= since,
                Incident.status.in_(("resolved", "false_positive", "auto_closed")),
                or_(*conds) if conds else Incident.id < 0,
            )
        ).all()
        if conds
        else []
    )
    same_rule = db.scalars(
        select(Incident)
        .join(Alert, Alert.incident_id == Incident.id)
        .where(
            Incident.id != inc.id,
            Incident.agent_name == inc.agent_name,
            Incident.opened_at >= since,
            Incident.status.in_(("resolved", "false_positive", "auto_closed")),
            Alert.rule_id.in_(rules),
        )
        .distinct()
    ).all()
    seen: dict[int, Incident] = {i.id: i for i in [*rows, *same_rule]}
    items = []
    for i in sorted(seen.values(), key=lambda x: aware(x.opened_at), reverse=True)[:8]:
        note = db.scalars(select(Comment).where(Comment.incident_id == i.id).order_by(Comment.at.desc())).first()
        closer = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.target == f"INC-{i.id}", AuditEvent.action.in_(("incident.resolved", "incident.false_positive")))
            .order_by(AuditEvent.id.desc())
        ).first()
        why = (
            "same source IP"
            if inc.srcip and i.srcip == inc.srcip
            else "same user on this host"
            if inc.user and i.user == inc.user
            else "same rule on this host"
        )
        items.append(
            {
                "id": i.id,
                "title": i.title,
                "band": i.band,
                "status": i.status,
                "opened_at": aware(i.opened_at).isoformat(),
                "closed_by": closer.actor if closer else None,
                "note": note.body[:240] if note else None,
                "match": why,
            }
        )
    c = Counter(x["status"] for x in items)
    if not items:
        headline = "First time Sieve has seen this pattern."
    else:
        parts = [f"{n} {s.replace('_', ' ')}" for s, n in c.most_common()]
        headline = f"Seen {len(items)} time{'s' if len(items) != 1 else ''} before: " + ", ".join(parts) + "."
    return {"headline": headline, "items": items}


# ---------------- routing ----------------


def routes_for(settings: Settings, inc: Incident) -> list[Route]:
    tags = set()
    for a in settings.assets:
        if a.agent_name == inc.agent_name:
            tags |= set(a.tags)
    out = []
    for r in settings.routes:
        if not r.enabled or band_rank(inc.band) < band_rank(r.min_band):
            continue
        host_ok = not r.hosts or any(fnmatch.fnmatch(inc.agent_name or "", h) for h in r.hosts)
        tag_ok = not r.tags or bool(tags & set(r.tags))
        if host_ok and tag_ok and (r.hosts or r.tags):
            out.append(r)
    return out


# ---------------- graduated auto-close ----------------


def rule_agreement(db, days: int = 90) -> dict[str, dict]:
    """Per rule: how analysts closed single-rule incidents. Basis for auto-close eligibility."""
    since = utcnow() - timedelta(days=days)
    stats: dict[str, Counter] = {}
    for inc in db.scalars(
        select(Incident).where(Incident.opened_at >= since, Incident.status.in_(("resolved", "false_positive")))
    ):
        rules = {a.rule_id for a in inc.alerts}
        if len(rules) != 1:
            continue
        r = next(iter(rules))
        stats.setdefault(r, Counter())[inc.status] += 1
    out = {}
    for r, c in stats.items():
        n = sum(c.values())
        out[r] = {
            "verdicts": n,
            "false_positive": c["false_positive"],
            "real": c["resolved"],
            "agreement": round(c["false_positive"] / n, 3) if n else 0.0,
        }
    return out


def autoclose_ok(db, settings: Settings, inc: Incident) -> str | None:
    """Return a reason string if this incident may be auto-closed, else None."""
    ac = settings.autoclose
    if not ac.enabled or inc.tripwire or inc.overrides or inc.correlations:
        return None
    if band_rank(inc.band) > band_rank(ac.max_band):
        return None
    rules = {a.rule_id for a in inc.alerts}
    if len(rules) != 1 or next(iter(rules)) not in set(ac.rules):
        return None
    st = rule_agreement(db).get(next(iter(rules)))
    if not st or st["verdicts"] < ac.min_verdicts or st["agreement"] < ac.min_agreement:
        return None  # approval alone is not enough: the rule must keep earning it
    return f"auto-closed: rule {next(iter(rules))} closed as false positive {st['false_positive']}/{st['verdicts']} times"


# ---------------- weight tuning ----------------

WEIGHT_KEYS = ("asset", "vuln", "intel", "chain", "novelty", "volume")
LABEL_KEY = [
    ("Wazuh rule level", "level"),
    ("is tagged", "asset"),
    ("vulnerab", "vuln"),
    ("threat-intel", "intel"),
    ("Attack chain", "chain"),
    ("First-seen", "novelty"),
    ("Volume", "volume"),
]


def _rows(inc: Incident, w) -> list[tuple[str, float]]:
    out = []
    for b in inc.breakdown or []:
        key = b.get("key") or next((k for frag, k in LABEL_KEY if frag in b["label"]), None)
        if not key:
            continue
        if "factor" in b:
            f = b["factor"]
        else:
            wt = 1.0 if key == "level" else getattr(w, key)
            f = b["points"] / wt if wt else 0.0
        out.append((key, f))
    return out


def _rescore(rows, weights: dict) -> float:
    return min(100.0, sum(f * (1.0 if k == "level" else weights[k]) for k, f in rows))


def suggest_weights(db, settings: Settings, days: int = 180) -> dict:
    """Coordinate search over weight multipliers that keeps every confirmed incident at its band or above
    the notify band, while pushing false positives below it. Labels: human_band if set, else the verdict."""
    since = utcnow() - timedelta(days=days)
    incs = db.scalars(
        select(Incident).where(Incident.opened_at >= since, Incident.status.in_(("resolved", "false_positive")))
    ).all()
    notify = settings.bands.model_dump()[settings.notify.min_band] if settings.notify.min_band != "low" else 0
    data = [(_rows(i, settings.weights), i.status == "resolved" and not i.overrides, bool(i.overrides)) for i in incs]
    data = [(r, real) for r, real, ov in data if r and not ov]  # overrides are fixed by rule; exclude
    if len(data) < 20:
        return {
            "enough_data": False,
            "labelled": len(data),
            "message": "Need at least 20 closed incidents (resolved or false positive) without overrides.",
        }
    cur = {k: getattr(settings.weights, k) for k in WEIGHT_KEYS}

    def evaluate(wts):
        real = [_rescore(r, wts) for r, ok in data if ok]
        fake = [_rescore(r, wts) for r, ok in data if not ok]
        tp = sum(1 for x in real if x >= notify)
        fp = sum(1 for x in fake if x >= notify)
        sep = (sum(real) / len(real) if real else 0) - (sum(fake) / len(fake) if fake else 0)
        return tp, fp, sep

    base_tp, base_fp, base_sep = evaluate(cur)
    best, (best_tp, best_fp, best_sep) = dict(cur), (base_tp, base_fp, base_sep)
    for _ in range(6):
        improved = False
        for k in WEIGHT_KEYS:
            for m in (0.5, 0.75, 1.25, 1.5, 2.0):
                trial = {**best, k: round(min(60.0, max(0.5, best[k] * m)), 2)}
                tp, fp, sep = evaluate(trial)
                # never lose a real incident; prefer fewer false positives, then wider real-vs-false separation
                if tp >= base_tp and (fp < best_fp or (fp == best_fp and sep > best_sep + 0.01)):
                    best, best_tp, best_fp, best_sep = trial, tp, fp, sep
                    improved = True
        if not improved:
            break
    changed = {k: {"from": cur[k], "to": best[k]} for k in WEIGHT_KEYS if best[k] != cur[k]}
    return {
        "enough_data": True,
        "labelled": len(data),
        "current": {"true_positives_notified": base_tp, "false_positives_notified": base_fp},
        "proposed": {"true_positives_notified": best_tp, "false_positives_notified": best_fp},
        "changes": changed,
        "weights": best,
        "message": "No change would reduce false positives without losing a real incident."
        if not changed
        else f"Would stop {base_fp - best_fp} false-positive notification(s) and keep all {base_tp} real ones.",
    }


# ---------------- profile ----------------


def outside_business_hours(settings: Settings, when: datetime) -> bool:
    p = settings.profile
    try:
        tz = ZoneInfo(p.timezone or "UTC")
        start, end = [datetime.strptime(x.strip(), "%H:%M").time() for x in p.business_hours.split("-")]
    except Exception:  # noqa: BLE001 - bad profile never breaks triage
        return False
    local = aware(when).astimezone(tz)
    return local.weekday() not in p.business_days or not (start <= local.time() <= end)


__all__ = [
    "BAND_ORDER",
    "backtest_correlation",
    "correlation_hits",
    "precedents",
    "routes_for",
    "rule_agreement",
    "autoclose_ok",
    "suggest_weights",
    "outside_business_hours",
]

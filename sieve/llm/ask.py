"""Ask Sieve: plain-English questions answered by fixed, read-only queries.

The ANSWER always comes from deterministic queries over Sieve's own data (intent + entities parsed with
regular expressions against entities Sieve already knows). An LLM, when enabled, may only write a short
summary of that answer; the summary goes through the same validation as incident summaries (numbers and
IPs must appear in the result). The model never chooses a query, a filter, or a value.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from datetime import timedelta

from sqlalchemy import func, or_, select

from ..config import Settings
from ..db import SessionLocal
from ..models import Alert, Incident, Suppression, aware, utcnow
from .client import complete_json
from .fence import task_prompt
from .validate import _IP, _numbers

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{6,}\b")
WINDOWS = [(r"\btoday\b|\b24 ?h", 1), (r"\bthis week\b|\b7 ?d|\bweek\b", 7), (r"\bthis month\b|\b30 ?d|\bmonth\b", 30)]


def _window(q: str) -> int:
    for rx, d in WINDOWS:
        if re.search(rx, q, re.I):
            return d
    return 7


def parse(q: str) -> dict:
    q = q.strip()[:500]
    days = _window(q)
    ips = []
    for m in _IP_RE.findall(q):
        try:
            ips.append(str(ipaddress.ip_address(m)))
        except ValueError:
            pass
    with SessionLocal() as db:
        hosts = [h for (h,) in db.execute(select(Alert.agent_name).distinct()).all() if h]
        users = [u for (u,) in db.execute(select(Alert.user).distinct().limit(5000)).all() if u]
    low = q.lower()
    host = next(
        (h for h in sorted(hosts, key=len, reverse=True) if re.search(rf"(?<![\w-]){re.escape(h.lower())}(?![\w-])", low)), None
    )
    user = next(
        (
            u
            for u in sorted(users, key=len, reverse=True)
            if len(u) > 2 and re.search(rf"(?<![\w-]){re.escape(u.lower())}(?![\w-])", low)
        ),
        None,
    )
    if ips:
        intent = "entity"
    elif re.search(r"noisy|noisiest|false positive|top rules?", low):
        intent = "noisy"
    elif re.search(r"suppress|hidden|filtered", low):
        intent = "suppressed"
    elif host or user:
        intent = "entity"
    elif re.search(r"open|incident|critical|high|unacknowledged|overdue", low):
        intent = "incidents"
    else:
        intent = "overview"
    return {
        "intent": intent,
        "ip": ips[0] if ips else None,
        "host": host,
        "user": user,
        "days": days,
        "band": next((b for b in ("critical", "high", "medium", "low") if b in low), None),
    }


def answer(p: dict, tenant_id: int | None = None) -> dict:
    since = utcnow() - timedelta(days=p["days"])
    with SessionLocal() as db:
        if p["intent"] == "entity":
            conds = []
            if p["ip"]:
                conds.append(Alert.srcip == p["ip"])
            if p["user"]:
                conds.append(Alert.user == p["user"])
            if p["host"] and not conds:
                conds.append(Alert.agent_name == p["host"])
            aq = select(Alert).where(or_(*conds), Alert.timestamp >= since)
            if tenant_id:
                aq = aq.where(Alert.tenant_id == tenant_id)
            alerts = db.scalars(aq.limit(5000)).all()
            incs = sorted({a.incident_id for a in alerts if a.incident_id})
            rows = db.scalars(select(Incident).where(Incident.id.in_(incs))).all() if incs else []
            by_host = Counter(a.agent_name for a in alerts)
            subject = p["ip"] or p["user"] or p["host"]
            return {
                "kind": "entity",
                "subject": subject,
                "days": p["days"],
                "alerts": len(alerts),
                "hosts": by_host.most_common(10),
                "first_seen": min((aware(a.timestamp).isoformat() for a in alerts), default=None),
                "last_seen": max((aware(a.timestamp).isoformat() for a in alerts), default=None),
                "incidents": [{"id": i.id, "title": i.title, "band": i.band, "status": i.status} for i in rows][:20],
                "query": {"field": "srcip" if p["ip"] else "user" if p["user"] else "agent_name", "value": subject},
            }
        if p["intent"] in ("noisy", "suppressed") and tenant_id:
            p = {**p, "intent": "incidents"}   # provider-level views are not shown to customers
        if p["intent"] == "noisy":
            from ..casework import noisy_rules

            return {"kind": "noisy", "days": p["days"], "rules": noisy_rules(db, p["days"])[:10]}
        if p["intent"] == "suppressed":
            rows = db.execute(
                select(Suppression.reason, func.count())
                .where(Suppression.created_at >= since)
                .group_by(Suppression.reason)
                .order_by(func.count().desc())
                .limit(10)
            ).all()
            return {"kind": "suppressed", "days": p["days"], "reasons": [{"reason": r, "count": c} for r, c in rows]}
        q = select(Incident).where(Incident.opened_at >= since)
        if tenant_id:
            q = q.where(Incident.tenant_id == tenant_id)
        if p["intent"] == "incidents":
            q = q.where(Incident.status.in_(("new", "acknowledged")))
        if p["band"]:
            q = q.where(Incident.band == p["band"])
        rows = db.scalars(q.limit(200)).all()
        return {
            "kind": "incidents",
            "days": p["days"],
            "count": len(rows),
            "by_band": dict(Counter(i.band for i in rows)),
            "incidents": [
                {"id": i.id, "title": i.title, "band": i.band, "status": i.status, "host": i.agent_name}
                for i in sorted(rows, key=lambda i: -["low", "medium", "high", "critical"].index(i.band))
            ][:20],
        }


def plain(ans: dict) -> str:
    k = ans["kind"]
    if k == "entity":
        if not ans["alerts"]:
            return f"No alerts mention {ans['subject']} in the last {ans['days']} days."
        hosts = ", ".join(f"{h} ({n})" for h, n in ans["hosts"][:3])
        return (
            f"{ans['subject']} appears in {ans['alerts']} alerts in the last {ans['days']} days, on {hosts}, "
            f"across {len(ans['incidents'])} incident(s)."
        ).replace("incident(s)", "incident" if len(ans["incidents"]) == 1 else "incidents")
    if k == "noisy":
        return "Rules ranked by false-positive rate and volume." if ans["rules"] else "Not enough verdicts yet."
    if k == "suppressed":
        return f"Top reasons alerts were suppressed in the last {ans['days']} days."
    return f"{ans['count']} matching incidents in the last {ans['days']} days."


async def ask(question: str, settings: Settings, tenant_id: int | None = None) -> dict:
    p = parse(question)
    ans = answer(p, tenant_id)
    text, source = plain(ans), "rules"
    if settings.llm.enabled:
        res = await complete_json(
            lambda cloud: task_prompt(
                "Summarise the query RESULT in at most two plain sentences for a busy IT person. Use only numbers and names "
                "that appear in the result. Do not give advice that is not supported by the result.",
                '{"summary": "<two sentences>"}',
                {"result": ans},
                {"question": question},
            ),
            settings,
            purpose="ask",
        )
        if res:
            cand = str(res.data.get("summary") or "")[:600]
            trusted = json.dumps(ans, default=str)
            nums_ok = all(n < 2 or n in _numbers(trusted) for n in _numbers(cand))
            ips_ok = all(ip in trusted for ip in _IP.findall(cand))
            if cand and nums_ok and ips_ok:
                text, source = cand, res.provider
    return {"question": question[:500], "understood": p, "answer": ans, "summary": text, "summary_source": source}

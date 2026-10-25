"""Daily digest, two versions (master prompt 3.6).

The manager version uses no jargon, no IP addresses and no ATT&CK IDs: it is for an owner or CFO.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import timedelta

from sqlalchemy import func, select

from .db import SessionLocal
from .models import Alert, Incident, Notification, Suppression, aware, utcnow

OPEN = ("new", "acknowledged")


def collect(hours: int = 24) -> dict:
    since = utcnow() - timedelta(hours=hours)
    with SessionLocal() as db:
        alerts = db.scalar(select(func.count(Alert.id)).where(Alert.received_at >= since)) or 0
        supp = db.scalar(select(func.count(Suppression.id)).where(Suppression.created_at >= since)) or 0
        recent = select(Alert.incident_id).where(Alert.received_at >= since).distinct().scalar_subquery()
        incs = db.scalars(select(Incident).where(Incident.id.in_(recent), Incident.is_selftest.is_(False))).all()
        notes = db.scalar(select(func.count(Notification.id)).where(Notification.at >= since,
                                                                   Notification.phase == "send")) or 0
        open_incs = db.scalars(select(Incident).where(Incident.status.in_(OPEN),
                                                      Incident.is_selftest.is_(False))).all()
        restored = db.scalar(select(func.count(Suppression.id)).where(Suppression.review_outcome == "restored",
                                                                      Suppression.reviewed_at >= since)) or 0
    acked = [(aware(i.acknowledged_at) - aware(i.opened_at)).total_seconds() / 60 for i in incs if i.acknowledged_at]
    needs = [i for i in incs if i.band in ("critical", "high") or i.tripwire]
    oldest = min((aware(i.opened_at) for i in open_incs), default=None)
    return {
        "hours": hours, "alerts": alerts + supp, "suppressed": supp, "incidents": len(incs),
        "by_band": dict(Counter(i.band for i in incs)), "needed_decision": len(needs), "notifications": notes,
        "mean_ack_min": round(statistics.mean(acked), 1) if acked else None,
        "top_ips": Counter(i.srcip for i in incs if i.srcip).most_common(5),
        "top_hosts": Counter(i.agent_name for i in incs if i.agent_name).most_common(5),
        "techniques": sorted({t for i in incs for t in i.techniques}),
        "oldest_open_min": int((utcnow() - oldest).total_seconds() / 60) if oldest else None,
        "open": len(open_incs), "restored": restored,
    }


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def manager_text(d: dict) -> str:
    handled = max(d["alerts"] - d["needed_decision"], 0)
    lines = [f"Your systems were probed {d['alerts']:,} times in the last {d['hours']} hours.",
             f"{handled:,} were handled automatically. {_plural(d['needed_decision'], 'event')} needed a decision."]
    if d["oldest_open_min"] is not None:
        lines.append(f"Oldest open item: {d['oldest_open_min']} minutes.")
    else:
        lines.append("Nothing is waiting for anyone right now.")
    if d["restored"]:
        lines.append(f"Your team double-checked the filters and brought back {_plural(d['restored'], 'item')}.")
    return " ".join(lines)


def technical_text(d: dict) -> str:
    bands = ", ".join(f"{k} {v}" for k, v in sorted(d["by_band"].items())) or "none"
    ips = ", ".join(f"{ip} ({n})" for ip, n in d["top_ips"]) or "none"
    hosts = ", ".join(f"{h} ({n})" for h, n in d["top_hosts"]) or "none"
    return "\n".join([
        f"Sieve digest, last {d['hours']} h",
        f"Alerts in: {d['alerts']:,} (suppressed with reasons: {d['suppressed']:,}); notifications: {d['notifications']}",
        f"Incidents by band: {bands}; open now: {d['open']}",
        f"Mean time to acknowledge: {d['mean_ack_min'] if d['mean_ack_min'] is not None else 'n/a'} min",
        f"Top source IPs: {ips}", f"Top targeted hosts: {hosts}",
        f"ATT&CK techniques seen: {', '.join(d['techniques'][:15]) or 'none'}",
        f"Suppression sample: {d['restored']} alert(s) restored by reviewers",
    ])


def build(version: str = "manager", hours: int = 24) -> dict:
    d = collect(hours)
    text = manager_text(d) if version == "manager" else technical_text(d)
    return {"version": version, "text": text, "data": d if version == "technical" else None}


async def send_digest(settings, version: str = "manager") -> dict:
    from .notify.dispatch import send_text
    return await send_text(build(version)["text"], settings, phase="digest")

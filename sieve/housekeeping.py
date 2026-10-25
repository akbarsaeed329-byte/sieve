"""Periodic jobs run by the worker: SLA escalation, data retention, Wazuh indexer pull."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import delete, select

from . import runtime
from .db import SessionLocal
from .errors import SieveError
from .models import KV, Alert, Incident, LlmCall, Suppression, aware, utcnow

log = logging.getLogger("sieve.housekeeping")


async def escalate_overdue() -> int:
    """Send one escalation message for each open, unacknowledged incident past its SLA."""
    s = runtime.current()
    if not s.sla.escalate or s.shadow_mode:
        return 0
    from .integrations.outbound import emit
    from .notify.dispatch import send_text
    now = utcnow()
    with SessionLocal() as db:
        rows = db.scalars(select(Incident).where(Incident.status == "new", Incident.escalated_at.is_(None),
                                                 Incident.sla_due.is_not(None), Incident.sla_due < now,
                                                 Incident.band.in_(("high", "critical")))).all()
        for inc in rows:
            late = int((now - aware(inc.sla_due)).total_seconds() / 60)
            when = "it has just passed its SLA" if late < 1 else f"{late} min past its SLA"
            await send_text(f"ESCALATION: INC-{inc.id:04d} {inc.title} on {inc.agent_name} ({inc.band}) has not been "
                            f"acknowledged; {when}. {s.notify.public_url.rstrip('/')}/incidents/{inc.id}",
                            s, phase="escalate")
            inc.escalated_at = now
            await emit("incident.escalated", inc, s)
        db.commit()
        return len(rows)


def purge_old() -> dict:
    s = runtime.current()
    cut = utcnow() - timedelta(days=s.retention.alerts_days)
    with SessionLocal() as db:
        a = db.execute(delete(Alert).where(Alert.received_at < cut, Alert.incident_id.is_(None))).rowcount
        sp = db.execute(delete(Suppression).where(Suppression.created_at < cut)).rowcount
        lc = db.execute(delete(LlmCall).where(LlmCall.at < utcnow() - timedelta(days=s.retention.llm_calls_days))).rowcount
        db.commit()
    return {"alerts": a, "suppressions": sp, "llm_calls": lc}


async def pull_from_indexer() -> int:
    """Pull mode: read new alerts from the Wazuh indexer, oldest first, and queue them (idempotent)."""
    s = runtime.current()
    if not (s.wazuh.pull_enabled and s.wazuh.indexer_url):
        return 0
    from .integrations.wazuh import indexer_search
    from .worker import enqueue_many
    with SessionLocal() as db:
        kv = db.get(KV, "pull.cursor")
        cursor = (kv.value or {}).get("ts") if kv else None
    since = cursor or (utcnow() - timedelta(minutes=10)).isoformat()
    body = {"size": 500, "sort": [{"timestamp": "asc"}],
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gt": since}}}]}}}
    try:
        j = await indexer_search(s, body)
    except SieveError as e:
        log.warning("indexer pull failed", extra={"code": e.code})
        return 0
    hits = (j.get("hits") or {}).get("hits") or []
    last = cursor
    batch = []
    for h in hits:
        src = h.get("_source") or {}
        src.setdefault("id", h.get("_id"))
        batch.append(src)
        last = src.get("timestamp") or last
    if batch:
        enqueue_many(batch, "pull")
    if last and last != cursor:
        with SessionLocal() as db:
            kv = db.get(KV, "pull.cursor")
            if kv:
                kv.value = {"ts": last}
            else:
                db.add(KV(key="pull.cursor", value={"ts": last}))
            db.commit()
    return len(hits)

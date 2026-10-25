"""Multi-tenancy for managed security providers.

Wazuh alerts do not carry agent-group membership, so Sieve keeps its own agent -> tenant map:
1. Wazuh API `GET /agents?select=name,group` (refreshed every 10 minutes when the manager API is configured),
2. otherwise each tenant's host patterns (globs on the agent name).
Every alert, suppression and incident is stamped with tenant_id at ingest. Users and API tokens with a
tenant_id only ever see that tenant's data; provider staff (tenant_id = None) see all tenants.
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import timedelta

from sqlalchemy import func, select

from .db import SessionLocal
from .models import AgentState, Alert, Incident, Tenant, utcnow

log = logging.getLogger("sieve.tenancy")


def resolve(db, agent_name: str | None) -> int | None:
    if not agent_name:
        return None
    st = db.get(AgentState, agent_name)
    tenants = db.scalars(select(Tenant).where(Tenant.active.is_(True))).all()
    if st and st.groups:
        for t in tenants:
            if set(t.wazuh_groups or []) & set(st.groups):
                return t.id
    for t in tenants:
        if any(fnmatch.fnmatch(agent_name, p) for p in t.host_patterns or []):
            return t.id
    return st.tenant_id if st else None


async def refresh_agent_groups(settings) -> int:
    """Pull agent -> groups from the Wazuh manager API (read-only)."""
    if not settings.wazuh.api_url:
        return 0
    from . import http
    from .integrations.wazuh import manager_token

    tok = await manager_token(settings)
    async with http.client(timeout=settings.wazuh.timeout_s, verify=settings.wazuh.verify_tls) as c:
        r = await c.get(
            f"{settings.wazuh.api_url.rstrip('/')}/agents",
            params={"select": "name,group,status,id", "limit": 100000},
            headers={"Authorization": f"Bearer {tok}"},
        )
    items = ((r.json() or {}).get("data") or {}).get("affected_items") or []
    with SessionLocal() as db:
        for it in items:
            name = it.get("name")
            if not name:
                continue
            st = db.get(AgentState, name) or AgentState(agent_name=name)
            st.groups, st.agent_id, st.status = list(it.get("group") or []), str(it.get("id") or ""), it.get("status")
            db.add(st)
        db.flush()
        for st in db.scalars(select(AgentState)):
            st.tenant_id = resolve(db, st.agent_name)
        db.commit()
    return len(items)


def cross_tenant_attackers(db, days: int = 7, min_tenants: int = 2) -> list[dict]:
    """Source IPs seen attacking more than one customer: the view providers ask for most."""
    since = utcnow() - timedelta(days=days)
    rows = db.execute(
        select(Alert.srcip, Alert.tenant_id, func.count(), func.min(Alert.timestamp), func.max(Alert.timestamp))
        .where(Alert.timestamp >= since, Alert.srcip.is_not(None), Alert.tenant_id.is_not(None))
        .group_by(Alert.srcip, Alert.tenant_id)
    ).all()
    by_ip: dict[str, list] = {}
    for ip, tid, n, first, last in rows:
        by_ip.setdefault(ip, []).append({"tenant_id": tid, "alerts": n, "first": first, "last": last})
    names = {t.id: t.name for t in db.scalars(select(Tenant))}
    out = []
    for ip, hits in by_ip.items():
        if len({h["tenant_id"] for h in hits}) < min_tenants:
            continue
        incs = db.scalars(select(Incident).where(Incident.srcip == ip, Incident.opened_at >= since)).all()
        out.append(
            {
                "srcip": ip,
                "tenants": [
                    {"id": h["tenant_id"], "name": names.get(h["tenant_id"], "?"), "alerts": h["alerts"]}
                    for h in sorted(hits, key=lambda h: -h["alerts"])
                ],
                "alerts": sum(h["alerts"] for h in hits),
                "first_seen": min(h["first"] for h in hits).isoformat(),
                "last_seen": max(h["last"] for h in hits).isoformat(),
                "incidents": [{"id": i.id, "tenant_id": i.tenant_id, "band": i.band, "status": i.status} for i in incs][:20],
            }
        )
    out.sort(key=lambda x: (-len(x["tenants"]), -x["alerts"]))
    return out


def usage(db, tenant_id: int, days: int = 30) -> dict:
    from .models import LlmCall, Notification

    since = utcnow() - timedelta(days=days)
    inc_ids = select(Incident.id).where(Incident.tenant_id == tenant_id)
    return {
        "days": days,
        "alerts": db.scalar(select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id, Alert.received_at >= since)) or 0,
        "incidents": db.scalar(
            select(func.count(Incident.id)).where(Incident.tenant_id == tenant_id, Incident.opened_at >= since)
        )
        or 0,
        "notifications": db.scalar(
            select(func.count(Notification.id)).where(Notification.incident_id.in_(inc_ids), Notification.at >= since)
        )
        or 0,
        "ai_calls": db.scalar(select(func.count(LlmCall.id)).where(LlmCall.incident_id.in_(inc_ids), LlmCall.at >= since)) or 0,
        "agents": db.scalar(select(func.count()).select_from(AgentState).where(AgentState.tenant_id == tenant_id)) or 0,
    }

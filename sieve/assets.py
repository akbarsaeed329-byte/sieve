"""Agent memory: vulnerabilities (the V term of the score) and silent log sources.

V term: research doc 6.3 defines V = 1 when the host has an unpatched, relevant vulnerability. Sieve learns
per-agent vulnerability counts from Wazuh vulnerability-detector alerts that pass through it and, when the
indexer is configured, from the vulnerability states index. V = 1 when the agent has at least one open
vulnerability at or above `vuln_min_severity`.

Silent sources: an agent that suddenly stops sending alerts is often the first sign of trouble (agent killed,
logging disabled). Sieve learns each agent's usual rhythm and raises an incident when the silence is longer
than max(min_hours, factor x usual gap).
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from .db import SessionLocal
from .models import AgentState, Alert, aware, utcnow

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def touch(db, na) -> AgentState | None:
    """Called for every alert: update last-seen and learn vulnerabilities from vulnerability-detector alerts."""
    if not na.agent_name:
        return None
    st = db.get(AgentState, na.agent_name)
    if st is None:
        st = AgentState(agent_name=na.agent_name, agent_id=na.agent_id, groups=[], vulns={})
        db.add(st)
    st.last_alert_at = max(aware(st.last_alert_at), na.timestamp) if st.last_alert_at else na.timestamp
    st.silent_since = None
    if st.agent_id is None:
        st.agent_id = na.agent_id
    v = (na.raw.get("data") or {}).get("vulnerability") if isinstance(na.raw.get("data"), dict) else None
    if isinstance(v, dict) and v.get("cve"):
        sev = str(v.get("severity", "")).lower()
        status = str(v.get("status", "Active")).lower()
        cves = dict((st.vulns or {}).get("open", {}))
        if status in ("solved", "fixed"):
            cves.pop(str(v["cve"])[:30], None)
        else:
            cves[str(v["cve"])[:30]] = sev
        st.vulns = {
            "open": dict(list(cves.items())[-500:]),
            "critical": sum(1 for x in cves.values() if x == "critical"),
            "high": sum(1 for x in cves.values() if x == "high"),
        }
        st.vulns_at = utcnow()
    return st


def vuln_match(db, agent_name: str | None, min_severity: str = "high") -> tuple[bool, dict]:
    if not agent_name:
        return False, {}
    st = db.get(AgentState, agent_name)
    v = (st.vulns if st else None) or {}
    n = v.get("critical", 0) + (v.get("high", 0) if min_severity == "high" else 0)
    return n > 0, {
        "critical": v.get("critical", 0),
        "high": v.get("high", 0),
        "cves": [c for c, s in (v.get("open") or {}).items() if SEV_RANK.get(s, 0) >= SEV_RANK[min_severity]][:5],
    }


async def pull_vulnerabilities(settings) -> int:
    """Wazuh 4.8+: read open vulnerabilities per agent from the indexer's states index."""
    if not settings.wazuh.indexer_url:
        return 0
    from . import http, secrets_store

    w = settings.wazuh
    body = {
        "size": 0,
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": 5000},
                "aggs": {
                    "sev": {"terms": {"field": "vulnerability.severity", "size": 10}},
                    "top": {
                        "top_hits": {
                            "size": 5,
                            "_source": ["vulnerability.id", "vulnerability.severity"],
                            "sort": [{"vulnerability.score.base": {"order": "desc"}}],
                        }
                    },
                },
            }
        },
    }
    async with http.client(timeout=w.timeout_s, verify=w.verify_tls) as c:
        r = await c.post(
            f"{w.indexer_url.rstrip('/')}/wazuh-states-vulnerabilities-*/_search",
            json=body,
            auth=(w.indexer_username, secrets_store.resolve(w.indexer_password_env)),
        )
    if r.status_code != 200:
        return 0
    buckets = (((r.json() or {}).get("aggregations") or {}).get("agents") or {}).get("buckets") or []
    with SessionLocal() as db:
        for b in buckets:
            st = db.get(AgentState, b["key"]) or AgentState(agent_name=b["key"], groups=[], vulns={})
            sev = {x["key"].lower(): x["doc_count"] for x in b["sev"]["buckets"]}
            top = {
                h["_source"]["vulnerability"]["id"]: str(h["_source"]["vulnerability"].get("severity", "")).lower()
                for h in b["top"]["hits"]["hits"]
            }
            st.vulns = {"open": top, "critical": sev.get("critical", 0), "high": sev.get("high", 0)}
            st.vulns_at = utcnow()
            db.add(st)
        db.commit()
    return len(buckets)


def silent_agents(settings) -> list[dict]:
    """Agents whose silence is longer than their own normal rhythm allows."""
    out = []
    now = utcnow()
    with SessionLocal() as db:
        week = now - timedelta(days=7)
        counts = dict(
            db.execute(select(Alert.agent_name, func.count()).where(Alert.received_at >= week).group_by(Alert.agent_name)).all()
        )
        for st in db.scalars(select(AgentState).where(AgentState.last_alert_at.is_not(None))):
            n = counts.get(st.agent_name, 0)
            st.alerts_7d = n
            usual_gap_h = (7 * 24 / n) if n else 24.0
            limit_h = max(settings.silence.min_hours, settings.silence.factor * usual_gap_h)
            gap_h = (now - aware(st.last_alert_at)).total_seconds() / 3600
            if n >= 5 and gap_h > limit_h:
                out.append(
                    {
                        "agent_name": st.agent_name,
                        "agent_id": st.agent_id,
                        "tenant_id": st.tenant_id,
                        "silent_hours": round(gap_h, 1),
                        "usual_gap_hours": round(usual_gap_h, 2),
                        "limit_hours": round(limit_h, 1),
                        "already_flagged": st.silent_since is not None,
                    }
                )
        db.commit()
    return out


def quiet_rules(days_recent: int = 7, days_before: int = 30) -> list[dict]:
    """Rules that fired regularly before and stopped: often a broken decoder or a disabled log source."""
    now = utcnow()
    with SessionLocal() as db:
        before = dict(
            db.execute(
                select(Alert.rule_id, func.count())
                .where(
                    Alert.received_at >= now - timedelta(days=days_before + days_recent),
                    Alert.received_at < now - timedelta(days=days_recent),
                )
                .group_by(Alert.rule_id)
            ).all()
        )
        recent = dict(
            db.execute(
                select(Alert.rule_id, func.count())
                .where(Alert.received_at >= now - timedelta(days=days_recent))
                .group_by(Alert.rule_id)
            ).all()
        )
        desc = dict(db.execute(select(Alert.rule_id, func.max(Alert.description)).group_by(Alert.rule_id)).all())
    out = [
        {
            "rule_id": r,
            "description": desc.get(r, ""),
            "per_week_before": round(n / (days_before / 7), 1),
            "last_7_days": recent.get(r, 0),
        }
        for r, n in before.items()
        if n / (days_before / 7) >= 3 and recent.get(r, 0) == 0
    ]
    return sorted(out, key=lambda x: -x["per_week_before"])

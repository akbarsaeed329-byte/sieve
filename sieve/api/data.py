"""Read models for the UI: overview stats, playbooks, suppression audit, baselines, coverage map,
entity graph, rule backtest, metrics history, shadow-mode agreement and the digest."""
from __future__ import annotations

import random
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from .. import digest, runtime
from ..auth import analyst, audit, p_admin, p_analyst, p_viewer, viewer
from ..backtest import backtest
from ..errors import BAD_REQUEST, NOT_FOUND, SieveError
from ..integrations import wazuh
from ..llm.attack import _load as attack_catalogue
from ..llm.attack import valid_technique
from ..models import (
    Alert,
    Baseline,
    Incident,
    LlmCall,
    Notification,
    Suppression,
    TestResult,
    aware,
    utcnow,
)
from ..pipeline import playbooks
from ..pipeline.score import BAND_ORDER
from ..worker import enqueue
from .common import SessionLocal, get_incident, iso, scoped

router = APIRouter(tags=["Data"])
OPEN = ("new", "acknowledged")


@router.get("/api/stats")
def stats(tenant: int | None = None, user=Depends(viewer)):
    since = utcnow() - timedelta(hours=24)
    with SessionLocal() as db:
        q_kept = select(func.count(Alert.id)).where(Alert.received_at >= since)
        kept = db.scalar(scoped(q_kept, Alert.tenant_id, user, tenant)) or 0
        supp = db.scalar(scoped(select(func.count(Suppression.id)).where(Suppression.created_at >= since),
                                Suppression.tenant_id, user, tenant)) or 0
        inc_ids = scoped(select(Incident.id), Incident.tenant_id, user, tenant)
        notes = db.scalar(select(func.count(func.distinct(Notification.incident_id))).where(
            Notification.at >= since, Notification.phase == "send", Notification.ok.is_(True),
            Notification.shadow.is_(False), Notification.incident_id.in_(inc_ids))) or 0
        need = db.scalars(scoped(select(Incident).where(Incident.status == "new", Incident.is_selftest.is_(False)).where(
            (Incident.band.in_(("critical", "high"))) | Incident.tripwire.is_(True)), Incident.tenant_id, user, tenant)).all()
        acked = db.scalars(scoped(select(Incident).where(Incident.acknowledged_at >= utcnow() - timedelta(days=7)),
                                  Incident.tenant_id, user, tenant)).all()
        open_n = db.scalar(scoped(select(func.count(Incident.id)).where(Incident.status.in_(OPEN)),
                                  Incident.tenant_id, user, tenant)) or 0
        fails = db.scalar(select(func.count(Notification.id)).where(
            Notification.at >= utcnow() - timedelta(hours=1), Notification.ok.is_(False))) or 0
    tta = [(aware(i.acknowledged_at) - aware(i.opened_at)).total_seconds() / 60 for i in acked]
    need.sort(key=lambda i: (not i.tripwire and i.band != "critical", -BAND_ORDER.index(i.band)))
    from .incidents import summary
    return {"alerts_received": kept + supp, "suppressed": supp, "notifications": notes, "open_incidents": open_n,
            "median_tta_min": round(statistics.median(tta), 1) if tta else None,
            "needs_you": [summary(i) for i in need[:5]], "channel_failures_last_hour": fails,
            "shadow_mode": runtime.current().shadow_mode}


@router.get("/api/playbooks")
def list_playbooks(user=Depends(viewer)):
    return [playbooks.render(pid, None, None, None) for pid in playbooks.ids()]


@router.get("/api/playbooks/{pb_id}")
def get_playbook(pb_id: str, user=Depends(viewer)):
    if pb_id not in playbooks.load():
        raise SieveError(NOT_FOUND, f"Playbook {pb_id} not found.", status=404)
    return playbooks.render(pb_id, None, None, None)


def iso_week(d: datetime | None = None) -> str:
    y, w, _ = (d or datetime.now(UTC)).isocalendar()
    return f"{y}-W{w:02d}"


def _sample(db) -> list[Suppression]:
    week = iso_week()
    rows = db.scalars(select(Suppression).where(Suppression.sample_week == week)).all()
    if rows:
        return list(rows)
    ids = [x for (x,) in db.execute(select(Suppression.id).where(
        Suppression.created_at >= utcnow() - timedelta(days=7), Suppression.sample_week.is_(None))).all()]
    for sid in random.SystemRandom().sample(ids, min(20, len(ids))):
        row = db.get(Suppression, sid)
        row.sampled, row.sample_week = True, week
    db.commit()
    return list(db.scalars(select(Suppression).where(Suppression.sample_week == week)).all())


@router.get("/api/suppressions")
def suppressions(sampled: bool = False, limit: int = Query(100, le=500), user=Depends(viewer)):
    from .common import tenant_of
    if tenant_of(user):   # customers see their own hidden alerts; sampling and reasons stay with the provider
        with SessionLocal() as db:
            rows = db.scalars(select(Suppression).where(Suppression.tenant_id == tenant_of(user))
                              .order_by(Suppression.id.desc()).limit(limit)).all()
            return {"total": len(rows), "week": iso_week(), "last_week_restored": 0, "by_reason": [],
                    "items": [{"id": x.id, "rule_id": x.rule_id, "level": x.level, "agent_name": x.agent_name,
                               "description": x.description, "reason": x.reason, "created_at": iso(x.created_at),
                               "outcome": x.review_outcome, "reviewed_by": x.reviewed_by, "full_log": ""} for x in rows]}
    with SessionLocal() as db:
        total = db.scalar(select(func.count(Suppression.id))) or 0
        by_reason = db.execute(select(Suppression.reason, func.count()).group_by(Suppression.reason)
                               .order_by(func.count().desc()).limit(50)).all()
        restored = dict(db.execute(select(Suppression.reason, func.count()).where(
            Suppression.review_outcome == "restored").group_by(Suppression.reason)).all())
        rows = _sample(db) if sampled else db.scalars(select(Suppression).order_by(Suppression.id.desc())
                                                       .limit(limit)).all()
        last_week = iso_week(datetime.now(UTC) - timedelta(days=7))
        lw = db.scalar(select(func.count(Suppression.id)).where(Suppression.sample_week == last_week,
                                                                Suppression.review_outcome == "restored")) or 0
        return {"total": total, "week": iso_week(), "last_week_restored": lw,
                "by_reason": [{"reason": r, "count": c, "restored": restored.get(r, 0),
                               "flagged": restored.get(r, 0) > 0} for r, c in by_reason],
                "items": [{"id": x.id, "rule_id": x.rule_id, "level": x.level, "agent_name": x.agent_name,
                           "description": x.description, "reason": x.reason, "created_at": iso(x.created_at),
                           "outcome": x.review_outcome, "reviewed_by": x.reviewed_by,
                           "full_log": str((x.raw or {}).get("full_log", ""))[:300]} for x in rows]}


class Review(BaseModel):
    outcome: Literal["noise", "restore"]


@router.post("/api/suppressions/{sid}/review")
def review(sid: int, body: Review, user=Depends(analyst)):
    with SessionLocal() as db:
        x = db.get(Suppression, sid)
        if not x or (getattr(user, "tenant_id", None) and x.tenant_id != user.tenant_id):
            raise SieveError(NOT_FOUND, "Suppressed alert not found.", status=404)
        if x.review_outcome:
            raise SieveError(BAD_REQUEST, f"Already reviewed as {x.review_outcome}.", status=409)
        x.review_outcome = "restored" if body.outcome == "restore" else "noise"
        x.reviewed_by, x.reviewed_at = user.username, utcnow()
        qid = None
        if body.outcome == "restore" and x.raw:
            qid = enqueue(x.raw, "restore", bypass_filter=True)
            x.restored_queue_id = qid
        reason = x.reason
        db.commit()
    audit(user.username, f"suppression.{x.review_outcome}", str(sid), reason=reason, queue_id=qid)
    return {"ok": True, "outcome": x.review_outcome, "requeued": qid is not None,
            "flag": f"The filter '{reason}' hid an alert a reviewer brought back." if qid else None}


@router.get("/api/baselines")
def baselines(entity: str | None = None, limit: int = Query(200, le=1000), user=Depends(p_viewer)):
    with SessionLocal() as db:
        q = select(Baseline).order_by(Baseline.last_seen.desc())
        if entity:
            q = q.where(Baseline.entity.contains(entity[:120]))
        return [{"entity": b.entity, "feature": b.feature, "first_seen": iso(b.first_seen),
                 "last_seen": iso(b.last_seen), "count": b.count} for b in db.scalars(q.limit(limit))]


@router.get("/api/coverage")
async def coverage(user=Depends(p_viewer)):
    cat = attack_catalogue()
    with SessionLocal() as db:
        seen = Counter(t for (ids,) in db.execute(select(Alert.mitre_ids)).all() for t in (ids or []))
        since = utcnow() - timedelta(days=30)
        tests: dict[str, str] = {}
        for r in db.scalars(select(TestResult).where(TestResult.at >= since).order_by(TestResult.at)):
            tests[r.technique] = r.outcome
    rules: set[str] = set()
    s = runtime.current()
    if s.wazuh.api_url:
        try:
            tok = await wazuh.manager_token(s)
            from .. import http
            async with http.client(timeout=s.wazuh.timeout_s, verify=s.wazuh.verify_tls) as c:
                r = await c.get(f"{s.wazuh.api_url.rstrip('/')}/rules", params={"limit": 10000, "select": "mitre"},
                                headers={"Authorization": f"Bearer {tok}"})
            for item in ((r.json() or {}).get("data") or {}).get("affected_items", []):
                rules |= set((item.get("mitre") or {}).get("id") or [])
        except Exception:  # noqa: BLE001 - coverage is best-effort
            pass
    rule_ids = rules | set(seen)
    cols = {t: [] for t in cat.get("tactics", [])}
    for tid, meta in cat.get("techniques", {}).items():
        if "." in tid:
            continue
        subs = [x for x in cat["techniques"] if x.startswith(tid + ".")]
        group = {tid, *subs}
        outcome = next((tests[x] for x in group if tests.get(x) == "missed"), None) or \
            next((tests[x] for x in group if x in tests), None)
        state = "missed" if outcome == "missed" else "detected" if outcome == "detected" else \
            "rule" if group & rule_ids else "none"
        for tac in meta.get("tactics", []):
            if tac in cols:
                cols[tac].append({"id": tid, "name": meta["name"], "state": state,
                                  "alerts": sum(seen.get(x, 0) for x in group)})
    for v in cols.values():
        v.sort(key=lambda x: (["missed", "detected", "rule", "none"].index(x["state"]), x["id"]))
    totals = Counter(x["state"] for v in cols.values() for x in v)
    return {"tactics": [{"name": k, "techniques": v} for k, v in cols.items()], "totals": dict(totals),
            "rule_source": "wazuh-api" if rules else "observed-alerts", "catalogue_version": cat.get("version")}


class Result(BaseModel):
    technique: str
    outcome: Literal["detected", "missed"]
    source: str = "atomic-red-team"
    detail: str = ""


@router.post("/api/coverage/results", status_code=201)
def add_result(body: Result, user=Depends(p_admin)):
    if not valid_technique(body.technique):
        raise SieveError(BAD_REQUEST, "Unknown ATT&CK technique ID.", status=422)
    with SessionLocal() as db:
        db.add(TestResult(technique=body.technique, outcome=body.outcome, source=body.source[:40],
                          detail=body.detail[:2000]))
        db.commit()
    audit(user.username, "coverage.result", body.technique, outcome=body.outcome)
    return {"ok": True}


@router.get("/api/graph")
def graph(incident_id: int | None = None, entity: str | None = None, user=Depends(viewer)):
    with SessionLocal() as db:
        if incident_id:
            i = get_incident(db, incident_id)
            t0, t1 = aware(i.first_seen) - timedelta(hours=12), aware(i.last_seen) + timedelta(hours=12)
            keys = {("ip", i.srcip), ("user", i.user), ("host", i.agent_name)} - {("ip", None), ("user", None),
                                                                                  ("host", None)}
        elif entity and ":" in entity:
            kind, val = entity.split(":", 1)
            t1 = utcnow()
            t0 = t1 - timedelta(hours=24)
            keys = {(kind, val)}
        else:
            raise SieveError(BAD_REQUEST, "Pass incident_id or entity=ip:<addr> | user:<name> | host:<name>.",
                             status=422)
        conds = []
        for kind, val in keys:
            col = {"ip": Alert.srcip, "user": Alert.user, "host": Alert.agent_name}.get(kind)
            if col is not None:
                conds.append(col == val)
        if not conds:
            raise SieveError(BAD_REQUEST, "Unknown entity type.", status=422)
        from sqlalchemy import or_
        alerts = db.scalars(scoped(select(Alert).where(or_(*conds), Alert.timestamp >= t0, Alert.timestamp <= t1),
                                   Alert.tenant_id, user).limit(5000)).all()
        nodes: dict[str, dict] = {}
        edges: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "incidents": set(), "rules": set()})

        def node(kind: str, val: str | None):
            if not val:
                return None
            nid = f"{kind}:{val}"
            n = nodes.setdefault(nid, {"id": nid, "kind": kind, "label": str(val)[:80], "alerts": 0,
                                       "focus": (kind, val) in keys, "incidents": set()})
            return n

        for a in alerts:
            ip, usr, host = node("ip", a.srcip), node("user", a.user), node("host", a.agent_name)
            proc = node("process", (a.untrusted or {}).get("data.win.eventdata.image"))
            for n in (ip, usr, host, proc):
                if n:
                    n["alerts"] += 1
                    if a.incident_id:
                        n["incidents"].add(a.incident_id)
            for src, dst, rel in ((ip, host, "connected to"), (usr, host, "acted on"), (proc, host, "ran on"),
                                  (ip, usr, "used account")):
                if src and dst:
                    e = edges[(src["id"], dst["id"], rel)]
                    e["count"] += 1
                    e["rules"].add(a.rule_id)
                    if a.incident_id:
                        e["incidents"].add(a.incident_id)
        blast = sorted({n["id"] for n in nodes.values() if n["kind"] == "host"})
        return {"window": {"from": t0.isoformat(), "to": t1.isoformat()},
                "nodes": [{**n, "incidents": sorted(n["incidents"])} for n in nodes.values()],
                "edges": [{"source": s, "target": t, "relation": r, "count": e["count"],
                           "incidents": sorted(e["incidents"]), "rules": sorted(e["rules"])[:10]}
                          for (s, t, r), e in edges.items()],
                "blast_radius_hosts": blast}


class BacktestBody(BaseModel):
    rule: str
    days: int = 30


@router.post("/api/backtest")
def run_backtest(body: BacktestBody, user=Depends(p_analyst)):
    if len(body.rule) > 20000:
        raise SieveError(BAD_REQUEST, "The rule is too long.", status=413)
    res = backtest(body.rule, max(1, min(body.days, 365)))
    audit(user.username, "rule.backtest", res["title"][:200], would_fire=res["would_fire"])
    return res


@router.get("/api/metrics/summary")
def metrics_summary(days: int = Query(14, ge=1, le=90), user=Depends(p_viewer)):
    since = (utcnow() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    labels = [(since + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)]

    def per_day(rows) -> dict[str, int]:
        c: Counter = Counter()
        for (d,) in rows:
            if d:
                c[aware(d).strftime("%Y-%m-%d")] += 1
        return c

    with SessionLocal() as db:
        kept = per_day(db.execute(select(Alert.received_at).where(Alert.received_at >= since)).all())
        supp = per_day(db.execute(select(Suppression.created_at).where(Suppression.created_at >= since)).all())
        notes = per_day(db.execute(select(Notification.at).where(
            Notification.at >= since, Notification.phase == "send", Notification.ok.is_(True),
            Notification.shadow.is_(False), Notification.channel != "console")).all())
        llm = per_day(db.execute(select(LlmCall.at).where(LlmCall.at >= since)).all())
        bands: dict[str, Counter] = {b: Counter() for b in BAND_ORDER}
        for d, b in db.execute(select(Incident.opened_at, Incident.band).where(Incident.opened_at >= since)).all():
            if b in bands:
                bands[b][aware(d).strftime("%Y-%m-%d")] += 1
        p = sorted(x for (x,) in db.execute(select(Notification.latency_ms).where(
            Notification.at >= since, Notification.phase == "send", Notification.latency_ms > 0)).all())
    alerts_in = [kept.get(d, 0) + supp.get(d, 0) for d in labels]
    return {"days": labels, "alerts_in": alerts_in, "notifications_out": [notes.get(d, 0) for d in labels],
            "incidents_by_band": {b: [bands[b].get(d, 0) for d in labels] for b in BAND_ORDER},
            "llm_calls": [llm.get(d, 0) for d in labels],
            "suppression_rate": [round(100 * supp.get(d, 0) / a, 1) if a else 0 for d, a in zip(labels, alerts_in,
                                                                                               strict=True)],
            "first_notify_ms": {"p50": p[len(p) // 2] if p else None,
                                "p95": p[max(0, int(len(p) * 0.95) - 1)] if p else None}}


def _kappa(pairs: list[tuple[str, str]]) -> float | None:
    if not pairs:
        return None
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in BAND_ORDER) / (n * n)
    return round((po - pe) / (1 - pe), 3) if pe < 1 else 1.0


@router.get("/api/shadow/agreement")
def shadow_agreement(since: str | None = None, user=Depends(p_viewer)):
    try:
        t0 = datetime.fromisoformat(since).replace(tzinfo=UTC) if since else utcnow() - timedelta(days=30)
    except ValueError as e:
        raise SieveError(BAD_REQUEST, "since must be an ISO date, e.g. 2026-10-01.", status=422) from e
    with SessionLocal() as db:
        rows = db.scalars(select(Incident).where(Incident.opened_at >= t0, Incident.human_band.is_not(None))).all()
        total = db.scalar(select(func.count(Incident.id)).where(Incident.opened_at >= t0)) or 0
    pairs = [(i.band, i.human_band) for i in rows]
    matrix = {s: {h: 0 for h in BAND_ORDER} for s in BAND_ORDER}
    for s_, h in pairs:
        matrix[s_][h] += 1
    under = [i.id for i in rows if BAND_ORDER.index(i.band) < BAND_ORDER.index(i.human_band)]
    return {"since": t0.isoformat(), "incidents": total, "labelled": len(pairs),
            "agreement": round(sum(a == b for a, b in pairs) / len(pairs), 3) if pairs else None,
            "within_one_band": round(sum(abs(BAND_ORDER.index(a) - BAND_ORDER.index(b)) <= 1
                                         for a, b in pairs) / len(pairs), 3) if pairs else None,
            "cohen_kappa": _kappa(pairs), "confusion": matrix, "sieve_lower_than_human": under,
            "shadow_mode": runtime.current().shadow_mode}


@router.get("/api/digest")
def get_digest(version: Literal["manager", "technical"] = "manager", hours: int = Query(24, ge=1, le=168),
               user=Depends(p_viewer)):
    return digest.build(version, hours)


@router.post("/api/digest/send")
async def send_digest(version: Literal["manager", "technical"] = "manager", user=Depends(p_admin)):
    res = await digest.send_digest(runtime.current(), version)
    audit(user.username, "digest.sent", version)
    return {"ok": True, "channels": res}

"""v0.3 routes: precedents, decision trace, evidence review, correlation rules, auto-close, weight tuning,
Ask Sieve, training mode, Jira two-way sync."""
from __future__ import annotations

import hmac
import random
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import runtime, secrets_store
from ..auth import audit, p_admin, p_analyst, p_viewer, viewer
from ..config import apply_update, save_override
from ..errors import AUTH_REQUIRED, BAD_REQUEST, NOT_FOUND, SieveError
from ..models import (
    AuditEvent,
    CorrelationRule,
    Explanation,
    Incident,
    LlmCall,
    Notification,
    PracticeAttempt,
    User,
)
from ..smart import backtest_correlation, precedents, rule_agreement, suggest_weights
from .common import SessionLocal, get_incident, iso

router = APIRouter(tags=["Smart"])


@router.get("/api/incidents/{inc_id}/precedents")
def get_precedents(inc_id: int, user=Depends(viewer)):
    with SessionLocal() as db:
        return precedents(db, get_incident(db, inc_id, user))


@router.post("/api/incidents/{inc_id}/evidence-viewed")
def evidence_viewed(inc_id: int, user=Depends(viewer)):
    with SessionLocal() as db:
        get_incident(db, inc_id, user)
        seen = db.scalar(select(AuditEvent.id).where(AuditEvent.action == "evidence.viewed",
                                                     AuditEvent.actor == user.username, AuditEvent.target == f"INC-{inc_id}"))
    if not seen:
        audit(user.username, "evidence.viewed", f"INC-{inc_id}")
    return {"ok": True}


@router.get("/api/incidents/{inc_id}/trace")
def decision_trace(inc_id: int, user=Depends(viewer)):
    """Everything that drove this incident's outcome, for audits: inputs, every decision, every check."""
    s = runtime.current()
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        exps = db.scalars(select(Explanation).where(Explanation.incident_id == inc_id).order_by(Explanation.created_at)).all()
        notes = db.scalars(select(Notification).where(Notification.incident_id == inc_id).order_by(Notification.at)).all()
        calls = db.scalars(select(LlmCall).where(LlmCall.incident_id == inc_id).order_by(LlmCall.at)).all()
        events = db.scalars(select(AuditEvent).where(AuditEvent.target == f"INC-{inc_id}").order_by(AuditEvent.at)).all()
        trace = {
            "incident": {"id": i.id, "title": i.title, "band": i.band, "score": i.score, "status": i.status,
                         "opened_at": iso(i.opened_at), "grouping_key": i.grouping_key},
            "severity": {"decided_by": "rules (sieve/pipeline/score.py); the AI never sets severity",
                         "breakdown": i.breakdown, "overrides": i.overrides, "correlations": i.correlations,
                         "weights": s.weights.model_dump(), "bands": s.bands.model_dump(),
                         "floors": [f.model_dump() for f in s.floors if f.enabled]},
            "inputs": [{"alert_id": a.id, "wazuh_id": a.wazuh_id, "rule_id": a.rule_id, "level": a.level,
                        "time": iso(a.timestamp), "received_at": iso(a.received_at), "validated_entities":
                        {"srcip": a.srcip, "user": a.user, "host": a.agent_name},
                        "untrusted_fields": sorted(a.untrusted or {})} for a in i.alerts],
            "tripwire": {"triggered": i.tripwire, "hits": i.tripwire_hits},
            "context": {"intel": i.intel, "novelty": i.novelty, "maintenance": i.maintenance, "notes": i.context_notes,
                        "partial_context": i.partial_context},
            "ai": [{"kind": e.kind, "provider": e.provider, "model": e.model, "prompt_sha256": e.prompt_hash,
                    "validation": e.validation, "kept_sentences": (e.summary or {}).get("summary", []),
                    "hypotheses": e.hypotheses, "checks": [{"template": st.get("template"), "count": st.get("count"),
                                                            "query": st.get("query")} for st in e.steps or []],
                    "steps_taken": e.steps_taken, "budget_hit": e.budget_hit, "at": iso(e.created_at)} for e in exps],
            "llm_calls": [{"provider": c.provider, "model": c.model, "purpose": c.purpose, "ok": c.ok, "error": c.error_code,
                           "latency_ms": c.latency_ms, "at": iso(c.at)} for c in calls],
            "notifications": [{"channel": n.channel, "phase": n.phase, "band": n.band, "ok": n.ok, "shadow": n.shadow,
                               "error": n.error, "latency_ms": n.latency_ms, "at": iso(n.at)} for n in notes],
            "human_actions": [{"at": iso(e.at), "actor": e.actor, "action": e.action, "detail": e.detail} for e in events],
        }
    if getattr(user, "username", None):
        audit(user.username, "incident.trace_exported", f"INC-{inc_id}")
    return trace


class Cond(BaseModel):
    rule_ids: list[str] = Field(default_factory=list, max_length=20)
    groups: list[str] = Field(default_factory=list, max_length=20)
    techniques: list[str] = Field(default_factory=list, max_length=20)
    min_count: int = Field(1, ge=1, le=1000)


class CorrBody(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    first: Cond
    then: Cond
    same: list[Literal["srcip", "user", "agent_name"]] = Field(default_factory=lambda: ["srcip"])
    within_minutes: int = Field(10, ge=1, le=1440)
    band: Literal["medium", "high", "critical"] = "high"
    enabled: bool = True


def _corr_out(r: CorrelationRule) -> dict:
    return {"id": r.id, "name": r.name, "first": r.first, "then": r.then, "same": r.same, "within_minutes": r.within_minutes,
            "band": r.band, "enabled": r.enabled, "hits": r.hits, "created_by": r.created_by, "created_at": iso(r.created_at)}


def _check(b: CorrBody) -> None:
    for c in (b.first, b.then):
        if not (c.rule_ids or c.groups or c.techniques):
            raise SieveError(BAD_REQUEST, "Each step needs a rule ID, a rule group or an ATT&CK technique.", status=422)
    if not b.same:
        raise SieveError(BAD_REQUEST, "Pick at least one field that must match (source IP, user or host).", status=422)


@router.get("/api/correlation-rules")
def list_corr(user=Depends(p_viewer)):
    with SessionLocal() as db:
        return [_corr_out(r) for r in db.scalars(select(CorrelationRule).order_by(CorrelationRule.id))]


@router.post("/api/correlation-rules/test")
def test_corr(b: CorrBody, user=Depends(p_analyst)):
    _check(b)
    rule = CorrelationRule(name=b.name, first=b.first.model_dump(), then=b.then.model_dump(), same=b.same,
                           within_minutes=b.within_minutes, band=b.band, created_by="test")
    with SessionLocal() as db:
        return backtest_correlation(db, rule)


@router.post("/api/correlation-rules", status_code=201)
def add_corr(b: CorrBody, user=Depends(p_admin)):
    _check(b)
    with SessionLocal() as db:
        r = CorrelationRule(name=b.name, first=b.first.model_dump(), then=b.then.model_dump(), same=b.same,
                            within_minutes=b.within_minutes, band=b.band, enabled=b.enabled, created_by=user.username)
        db.add(r)
        db.commit()
        out = _corr_out(r)
    audit(user.username, "correlation.created", b.name, rule=out)
    return out


@router.put("/api/correlation-rules/{rid}")
def edit_corr(rid: int, b: CorrBody, user=Depends(p_admin)):
    _check(b)
    with SessionLocal() as db:
        r = db.get(CorrelationRule, rid)
        if not r:
            raise SieveError(NOT_FOUND, "Rule not found.", status=404)
        before = _corr_out(r)
        r.name, r.first, r.then, r.same = b.name, b.first.model_dump(), b.then.model_dump(), b.same
        r.within_minutes, r.band, r.enabled = b.within_minutes, b.band, b.enabled
        db.commit()
        out = _corr_out(r)
    audit(user.username, "correlation.updated", b.name, before=before, after=out)
    return out


@router.delete("/api/correlation-rules/{rid}")
def del_corr(rid: int, user=Depends(p_admin)):
    with SessionLocal() as db:
        r = db.get(CorrelationRule, rid)
        if not r:
            raise SieveError(NOT_FOUND, "Rule not found.", status=404)
        r.enabled = False
        db.commit()
    audit(user.username, "correlation.disabled", f"rule#{rid}")
    return {"ok": True}


@router.get("/api/autoclose/candidates")
def autoclose_candidates(user=Depends(p_viewer)):
    s = runtime.current()
    ac = s.autoclose
    with SessionLocal() as db:
        stats = rule_agreement(db)
        desc = {}
        for r in stats:
            row = db.scalar(select(Incident.title).join(Incident.alerts).where(Incident.alerts.any(rule_id=r)).limit(1))
            desc[r] = row or ""
        closed = db.scalars(select(Incident).where(Incident.status == "auto_closed").order_by(Incident.id.desc()).limit(50)).all()
    rows = [{"rule_id": r, "title": desc.get(r, ""), **st, "approved": r in ac.rules,
             "eligible": st["verdicts"] >= ac.min_verdicts and st["agreement"] >= ac.min_agreement} for r, st in stats.items()]
    rows.sort(key=lambda x: (-x["eligible"], -x["agreement"], -x["verdicts"]))
    return {"enabled": ac.enabled, "max_band": ac.max_band, "min_verdicts": ac.min_verdicts, "min_agreement": ac.min_agreement,
            "rules": rows, "recently_auto_closed": [{"id": i.id, "title": i.title, "band": i.band, "agent_name": i.agent_name,
                                                     "at": iso(i.resolved_at)} for i in closed]}


@router.post("/api/incidents/{inc_id}/reopen-auto")
def reopen_auto(inc_id: int, user=Depends(p_analyst)):
    """Reviewer disagrees with an auto-close: reopen it and revoke auto-close for its rule."""
    s = runtime.current()
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        if i.status != "auto_closed":
            raise SieveError(BAD_REQUEST, "This incident was not auto-closed.", status=409)
        i.status, i.resolved_at = "new", None
        rules = {a.rule_id for a in i.alerts}
        db.commit()
    keep = [r for r in s.autoclose.rules if r not in rules]
    new, applied = apply_update(s, {"autoclose": {"rules": keep}})
    save_override(s, applied)
    runtime.set_current(new)
    audit(user.username, "autoclose.revoked", f"INC-{inc_id}", rules=sorted(rules))
    return {"ok": True, "revoked_rules": sorted(rules)}


@router.get("/api/tuning/weights")
def weights(user=Depends(p_viewer)):
    with SessionLocal() as db:
        return suggest_weights(db, runtime.current())


@router.post("/api/tuning/weights/apply")
def apply_weights(user=Depends(p_admin)):
    s = runtime.current()
    with SessionLocal() as db:
        sug = suggest_weights(db, s)
    if not sug.get("enough_data") or not sug.get("changes"):
        raise SieveError(BAD_REQUEST, sug.get("message", "Nothing to apply."), status=409)
    new, applied = apply_update(s, {"weights": sug["weights"]})
    save_override(s, applied)
    runtime.set_current(new)
    audit(user.username, "weights.applied", "weights", changes=sug["changes"], expected=sug["proposed"])
    return {"ok": True, "applied": sug["changes"]}


class AskBody(BaseModel):
    question: str = Field(min_length=2, max_length=500)


@router.post("/api/ask")
async def ask_route(b: AskBody, user=Depends(viewer)):
    from ..llm.ask import ask
    res = await ask(b.question, runtime.current(), tenant_id=getattr(user, "tenant_id", None))
    audit(user.username, "ask", b.question[:200])
    return res


@router.get("/api/practice/next")
def practice_next(user=Depends(viewer)):
    with SessionLocal() as db:
        done = {x for (x,) in db.execute(select(PracticeAttempt.incident_id).where(PracticeAttempt.user_id == user.id))}
        q = select(Incident).where(Incident.status.in_(("resolved", "false_positive")), Incident.is_selftest.is_(False))
        if getattr(user, "tenant_id", None):
            q = q.where(Incident.tenant_id == user.tenant_id)
        pool = [i for i in db.scalars(q.limit(2000))
                if i.id not in done]
        hard = [i for i in pool if i.band in ("high", "critical") or i.tripwire] or pool
        if not hard:
            return {"done": True}
        i = random.SystemRandom().choice(hard)
        return {"done": False, "id": i.id, "title": i.title, "host": i.agent_name, "srcip": i.srcip, "user": i.user,
                "alert_count": i.alert_count, "tripwire": i.tripwire,
                "alerts": [{"time": iso(a.timestamp), "rule_id": a.rule_id, "level": a.level, "description": a.description,
                            "full_log": a.full_log[:300]} for a in i.alerts[:30]]}


class PracticeBody(BaseModel):
    verdict: Literal["real", "false_positive"]
    band: Literal["low", "medium", "high", "critical"]


@router.post("/api/practice/{inc_id}")
def practice_answer(inc_id: int, b: PracticeBody, user=Depends(viewer)):
    if user.id < 0:
        raise SieveError(BAD_REQUEST, "Practice needs a personal account.", status=422)
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        actual = "false_positive" if i.status == "false_positive" else "real"
        target = i.human_band or i.band
        row = PracticeAttempt(user_id=user.id, incident_id=inc_id, verdict=b.verdict, band=b.band,
                              correct_verdict=b.verdict == actual, correct_band=b.band == target)
        db.add(row)
        from ..models import Comment
        notes = [{"author": c.author, "body": c.body} for c in db.scalars(select(Comment).where(Comment.incident_id == inc_id))]
        db.commit()
        tries = db.scalars(select(PracticeAttempt).where(PracticeAttempt.user_id == user.id)).all()
    return {"correct_verdict": row.correct_verdict, "correct_band": row.correct_band, "actual_verdict": actual,
            "actual_band": target, "breakdown": i.breakdown, "overrides": i.overrides, "notes": notes,
            "stats": {"attempts": len(tries), "verdict_accuracy": round(sum(t.correct_verdict for t in tries) / len(tries), 2),
                      "band_accuracy": round(sum(t.correct_band for t in tries) / len(tries), 2)}}


class TraineeBody(BaseModel):
    trainee: bool


@router.post("/api/users/{uid}/trainee")
def set_trainee(uid: int, b: TraineeBody, user=Depends(p_admin)):
    with SessionLocal() as db:
        u = db.get(User, uid)
        if not u:
            raise SieveError(NOT_FOUND, "User not found.", status=404)
        u.trainee = b.trainee
        db.commit()
    audit(user.username, "user.trainee", str(uid), trainee=b.trainee)
    return {"ok": True}


@router.post("/api/integrations/jira/webhook")
async def jira_webhook(request: Request):
    """Two-way sync: when the linked Jira issue reaches a Done status, resolve the Sieve incident."""
    secret = secrets_store.resolve("SIEVE_JIRA_WEBHOOK_SECRET")
    sent = request.query_params.get("secret") or request.headers.get("x-sieve-secret", "")
    if not secret or not hmac.compare_digest(sent.encode(), secret.encode()):
        raise SieveError(AUTH_REQUIRED, "Webhook secret missing or wrong.", status=401)
    body = await request.json()
    issue = body.get("issue") or {}
    key = str(issue.get("key") or "")
    cat = (((issue.get("fields") or {}).get("status") or {}).get("statusCategory") or {}).get("key")
    if not key or cat != "done":
        return {"ok": True, "action": "ignored"}
    with SessionLocal() as db:
        inc = next((i for i in db.scalars(select(Incident).where(Incident.status.in_(("new", "acknowledged"))))
                    if (i.ticket_ref or {}).get("jira") == key), None)
        if inc is None:
            return {"ok": True, "action": "no matching incident"}
        from ..models import utcnow
        inc.status, inc.resolved_at = "resolved", utcnow()
        inc_id = inc.id
        db.commit()
    audit(f"jira:{key}", "incident.resolved", f"INC-{inc_id}", via="jira webhook")
    return {"ok": True, "action": "resolved", "incident": inc_id}



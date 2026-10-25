"""Incident list, detail and workflow; checklist; AI actions; STIX; shadow labels; active response."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import or_, select

from .. import runtime, stix
from ..auth import admin, analyst, audit, viewer
from ..errors import AR_DISABLED, AR_NOT_CONFIRMED, BAD_REQUEST, SieveError
from ..integrations import wazuh, wazuh_response
from ..llm.attack import info as attack_info
from ..models import ChecklistTick, Explanation, Incident, utcnow
from ..pipeline import playbooks
from ..pipeline.facts import facts
from ..pipeline.score import BAND_ORDER
from .common import SessionLocal, get_incident, iso

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])
STATUSES = ("new", "acknowledged", "resolved", "false_positive")
OPEN = ("new", "acknowledged")


def summary(i: Incident) -> dict:
    return {"id": i.id, "ref": f"INC-{i.id:04d}", "title": i.title, "band": i.band, "score": round(i.score or 0),
            "status": i.status, "agent_name": i.agent_name, "srcip": i.srcip, "user": i.user,
            "alert_count": i.alert_count, "tripwire": i.tripwire, "opened_at": iso(i.opened_at),
            "last_seen": iso(i.last_seen), "acknowledged_at": iso(i.acknowledged_at), "assignee": i.assignee,
            "partial_context": i.partial_context, "is_selftest": i.is_selftest, "human_band": i.human_band}


def sort_key(i: Incident):
    return (i.status not in OPEN, -BAND_ORDER.index(i.band) if i.band in BAND_ORDER else 0,
            i.opened_at.timestamp() if i.opened_at else 0)


@router.get("")
def list_incidents(status: str = Query("all"), band: str | None = None, q: str | None = None,
                   limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), _=Depends(viewer)):
    with SessionLocal() as db:
        stmt = select(Incident)
        if status == "open":
            stmt = stmt.where(Incident.status.in_(OPEN))
        elif status == "closed":
            stmt = stmt.where(Incident.status.not_in(OPEN))
        elif status in STATUSES:
            stmt = stmt.where(Incident.status == status)
        if band in BAND_ORDER:
            stmt = stmt.where(Incident.band == band)
        if q:
            like = f"%{q[:80]}%"
            stmt = stmt.where(or_(Incident.title.ilike(like), Incident.agent_name.ilike(like),
                                  Incident.srcip.ilike(like), Incident.user.ilike(like)))
        rows = sorted(db.scalars(stmt.limit(5000)).all(), key=sort_key)
    return {"total": len(rows), "items": [summary(i) for i in rows[offset:offset + limit]]}


@router.get("/{inc_id}")
def get_detail(inc_id: int, user=Depends(viewer)):
    s = runtime.current()
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        exps = db.scalars(select(Explanation).where(Explanation.incident_id == inc_id)
                          .order_by(Explanation.created_at.desc())).all()
        ex = next((e for e in exps if e.kind == "summary"), None)
        inv = next((e for e in exps if e.kind == "investigation"), None)
        ticks = {t.step_id for t in db.scalars(select(ChecklistTick).where(
            ChecklistTick.incident_id == inc_id, ChecklistTick.user_id == user.id, ChecklistTick.checked.is_(True)))}
        pb = playbooks.render(i.playbook, i.user, i.srcip, i.agent_name)
        query = wazuh.kql(i.agent_name, i.srcip, i.user)
        alerts = list(i.alerts)
        return {**summary(i), "breakdown": i.breakdown, "overrides": i.overrides, "tactics": i.tactics,
                "techniques": [{"id": t, "name": (attack_info(t) or {}).get("name", "")} for t in i.techniques],
                "tripwire_hits": i.tripwire_hits, "facts": facts(i), "context_notes": i.context_notes,
                "intel": i.intel, "novelty": i.novelty, "playbook": pb, "checked_steps": sorted(ticks),
                "explanation": ({"provider": ex.provider, "model": ex.model, "summary": ex.summary.get("summary", []),
                                 "hypotheses": ex.summary.get("hypotheses", []), "validation": ex.validation,
                                 "created_at": iso(ex.created_at), "latency_ms": ex.latency_ms} if ex else None),
                "investigation": ({"hypotheses": inv.hypotheses, "steps": inv.steps, "steps_taken": inv.steps_taken,
                                   "budget_hit": inv.budget_hit, "provider": inv.provider,
                                   "created_at": iso(inv.created_at)} if inv else None),
                "alerts": [{"id": a.id, "ref": f"alert:{a.id}", "rule_id": a.rule_id, "level": a.level,
                            "description": a.description, "timestamp": iso(a.timestamp), "srcip": a.srcip,
                            "user": a.user, "groups": a.groups, "untrusted": a.untrusted, "full_log": a.full_log,
                            "mitre_ids": a.mitre_ids} for a in alerts[-200:]],
                "alerts_truncated": max(0, len(alerts) - 200),
                "wazuh_query": query, "wazuh_link": wazuh.dashboard_link(s, query),
                "active_response_enabled": s.allow_active_response, "resolved_at": iso(i.resolved_at)}


class Note(BaseModel):
    reason: str = ""


def _transition(inc_id: int, status: str, who: str, reason: str = "") -> dict:
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        before = i.status
        i.status = status
        now = utcnow()
        if status == "acknowledged":
            i.acknowledged_at, i.assignee = i.acknowledged_at or now, i.assignee or who
        if status in ("resolved", "false_positive"):
            i.resolved_at = now
            i.acknowledged_at = i.acknowledged_at or now
        if status == "new":
            i.resolved_at = None
        db.commit()
    audit(who, f"incident.{status}", f"INC-{inc_id}", before=before, reason=reason[:500])
    return {"ok": True, "status": status}


@router.post("/{inc_id}/acknowledge")
def acknowledge(inc_id: int, user=Depends(analyst)):
    return _transition(inc_id, "acknowledged", user.username)


@router.post("/{inc_id}/resolve")
def resolve(inc_id: int, n: Note | None = None, user=Depends(analyst)):
    return _transition(inc_id, "resolved", user.username, (n or Note()).reason)


@router.post("/{inc_id}/false-positive")
def false_positive(inc_id: int, n: Note, user=Depends(analyst)):
    if not n.reason.strip():
        raise SieveError(BAD_REQUEST, "Say why this is a false positive; the reason tunes future filtering.",
                         status=422)
    return _transition(inc_id, "false_positive", user.username, n.reason)


@router.post("/{inc_id}/reopen")
def reopen(inc_id: int, user=Depends(analyst)):
    return _transition(inc_id, "new", user.username)


class Tick(BaseModel):
    checked: bool = True


@router.post("/{inc_id}/checklist/{step_id}")
def tick(inc_id: int, step_id: str, body: Tick | None = None, user=Depends(analyst)):
    checked = (body or Tick()).checked
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        pb = playbooks.render(i.playbook, i.user, i.srcip, i.agent_name) or {"steps": []}
        if step_id not in {s["id"] for s in pb["steps"]}:
            raise SieveError(BAD_REQUEST, "That step is not in this incident's playbook.", status=422)
        row = db.scalar(select(ChecklistTick).where(ChecklistTick.incident_id == inc_id,
                                                    ChecklistTick.user_id == user.id,
                                                    ChecklistTick.step_id == step_id))
        if row is None:
            db.add(ChecklistTick(incident_id=inc_id, user_id=user.id, step_id=step_id, checked=checked))
        else:
            row.checked, row.at = checked, utcnow()
        db.commit()
    audit(user.username, "checklist.tick" if checked else "checklist.untick", f"INC-{inc_id}", step=step_id)
    return {"ok": True, "step_id": step_id, "checked": checked}


@router.post("/{inc_id}/explain")
async def explain(inc_id: int, user=Depends(analyst)):
    from ..llm.explain import explain_incident
    with SessionLocal() as db:
        get_incident(db, inc_id)
    res = await explain_incident(inc_id, runtime.current())
    audit(user.username, "incident.explain", f"INC-{inc_id}", ok=res is not None)
    return {"ok": res is not None, "explanation": res,
            "message": None if res else "No AI provider answered. Rule-based facts are still shown."}


@router.post("/{inc_id}/investigate")
async def run_investigation(inc_id: int, user=Depends(analyst)):
    from ..llm.investigate import investigate
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        if i.band != "critical":
            raise SieveError(BAD_REQUEST, "Investigation runs for critical incidents only.", status=422)
    res = await investigate(inc_id, runtime.current())
    audit(user.username, "incident.investigate", f"INC-{inc_id}")
    return {"ok": True, "investigation": res}


@router.get("/{inc_id}/stix")
def export_stix(inc_id: int, _=Depends(viewer)):
    with SessionLocal() as db:
        return stix.bundle(get_incident(db, inc_id))


class HumanBand(BaseModel):
    band: Literal["low", "medium", "high", "critical"]


@router.post("/{inc_id}/human-band")
def human_band(inc_id: int, body: HumanBand, user=Depends(analyst)):
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        before = i.human_band
        i.human_band, i.human_band_by = body.band, user.username
        db.commit()
    audit(user.username, "incident.human_band", f"INC-{inc_id}", before=before, after=body.band)
    return {"ok": True, "band": body.band}


class Confirm(BaseModel):
    confirm: bool = False


@router.post("/{inc_id}/response/{action}")
async def active_response(inc_id: int, action: Literal["firewall-drop", "disable-account"], body: Confirm,
                          user=Depends(admin)):
    s = runtime.current()
    if not s.allow_active_response:
        raise SieveError(AR_DISABLED, "Active response is disabled.", status=403)
    if body.confirm is not True:
        raise SieveError(AR_NOT_CONFIRMED, "Confirm the action to run it.", status=428)
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        agent_id, srcip, usr = i.agent_id, i.srcip, i.user
    try:
        res = await wazuh_response.run(s, action, agent_id, srcip, usr)
    except SieveError as e:
        audit(user.username, f"response.{action}.failed", f"INC-{inc_id}", approved_by=user.username,
              agent_id=agent_id, error=e.code)
        raise
    audit(user.username, f"response.{action}", f"INC-{inc_id}", approved_by=user.username, agent_id=agent_id,
          srcip=srcip if action == "firewall-drop" else None, user=usr if action == "disable-account" else None)
    return res

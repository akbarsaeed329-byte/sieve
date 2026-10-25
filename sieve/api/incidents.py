"""Incident REST endpoints."""
from __future__ import annotations
from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..auth import get_db, require_role
from ..models import AuditEvent, Explanation, Incident, utcnow

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])
_analyst = require_role("admin", "analyst")
_viewer = require_role("admin", "analyst", "viewer")


def _to_dict(inc: Incident) -> dict:
    exp = inc.explanations[-1] if inc.explanations else None
    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "band": inc.band,
        "score": round(inc.score, 1),
        "breakdown": inc.breakdown,
        "overrides": inc.overrides,
        "agent_name": inc.agent_name,
        "srcip": inc.srcip,
        "user": inc.user,
        "tactics": inc.tactics,
        "techniques": inc.techniques,
        "tripwire": inc.tripwire,
        "tripwire_hits": inc.tripwire_hits,
        "alert_count": inc.alert_count,
        "opened_at": inc.opened_at.isoformat(),
        "acknowledged_at": inc.acknowledged_at.isoformat() if inc.acknowledged_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "assignee": inc.assignee,
        "explanation": exp.summary if exp else None,
        "alerts": [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "level": a.level,
                "description": a.description,
                "timestamp": a.timestamp.isoformat(),
                "untrusted": a.untrusted,
                "groups": a.groups,
                "mitre_ids": a.mitre_ids,
            }
            for a in inc.alerts
        ],
    }


@router.get("")
def list_incidents(
    status: str | None = Query(default=None),
    band: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    _user=Depends(_viewer),
):
    q = db.query(Incident).order_by(Incident.opened_at.desc())
    if status:
        q = q.filter(Incident.status == status)
    if band:
        q = q.filter(Incident.band == band)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return {"total": total, "items": [_to_dict(i) for i in items]}


@router.get("/{iid}")
def get_incident(iid: int, db: Session = Depends(get_db), _user=Depends(_viewer)):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404, {"code": "SIEVE-API-404", "message": "Incident not found"})
    return _to_dict(inc)


@router.post("/{iid}/acknowledge")
def acknowledge(iid: int, db: Session = Depends(get_db), user=Depends(_analyst)):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404)
    inc.status = "acknowledged"
    inc.acknowledged_at = utcnow()
    inc.assignee = user.username
    db.add(AuditEvent(actor=user.username, action="acknowledge", target=f"INC-{iid}"))
    db.commit()
    return {"status": inc.status}


@router.post("/{iid}/resolve")
def resolve(iid: int, db: Session = Depends(get_db), user=Depends(_analyst)):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404)
    inc.status = "resolved"
    inc.resolved_at = utcnow()
    db.add(AuditEvent(actor=user.username, action="resolve", target=f"INC-{iid}"))
    db.commit()
    return {"status": inc.status}


@router.post("/{iid}/false-positive")
def false_positive(iid: int, db: Session = Depends(get_db), user=Depends(_analyst)):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404)
    inc.status = "false_positive"
    inc.resolved_at = utcnow()
    db.add(AuditEvent(actor=user.username, action="false_positive", target=f"INC-{iid}"))
    db.commit()
    return {"status": inc.status}

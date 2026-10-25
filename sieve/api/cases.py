"""Case management, exceptions, maintenance windows, tuning, API tokens, 2FA, and reports."""
from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .. import runtime, secrets_store, totp
from ..auth import analyst, audit, create_api_token, p_admin, p_viewer, verify_password, viewer
from ..casework import noisy_rules, suggest_exception
from ..errors import AUTH_TOTP, BAD_REQUEST, NOT_FOUND, SieveError
from ..models import (
    Alert,
    AlertException,
    ApiToken,
    Comment,
    Incident,
    MaintenanceWindow,
    Notification,
    Suppression,
    User,
    aware,
    utcnow,
)
from .common import SessionLocal, get_incident, iso, scoped, tenant_of

router = APIRouter(tags=["Cases"])


@router.get("/api/users/directory")
def directory(user=Depends(viewer)):
    with SessionLocal() as db:
        q = select(User).order_by(User.username)
        if tenant_of(user):
            q = q.where(User.tenant_id == tenant_of(user))
        return [{"username": u.username, "role": u.role} for u in db.scalars(q)]


class CommentBody(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


@router.post("/api/incidents/{inc_id}/comments", status_code=201)
def add_comment(inc_id: int, b: CommentBody, user=Depends(analyst)):
    with SessionLocal() as db:
        get_incident(db, inc_id, user)
        c = Comment(incident_id=inc_id, author=user.username, body=b.body.strip())
        db.add(c)
        db.commit()
        out = {"id": c.id, "author": c.author, "body": c.body, "at": iso(c.at)}
    audit(user.username, "incident.comment", f"INC-{inc_id}", comment_id=out["id"])
    return out


class AssignBody(BaseModel):
    assignee: str | None = None


@router.post("/api/incidents/{inc_id}/assign")
def assign(inc_id: int, b: AssignBody, user=Depends(analyst)):
    with SessionLocal() as db:
        target = db.scalar(select(User).where(User.username == b.assignee)) if b.assignee else None
        if b.assignee and (target is None or (tenant_of(user) and target.tenant_id != tenant_of(user))):
            raise SieveError(BAD_REQUEST, "No user with that name.", status=422)
        i = get_incident(db, inc_id, user)
        before, i.assignee = i.assignee, b.assignee
        db.commit()
    audit(user.username, "incident.assigned", f"INC-{inc_id}", before=before, after=b.assignee)
    return {"ok": True, "assignee": b.assignee}


class TagsBody(BaseModel):
    tags: list[str] = Field(max_length=20)


@router.post("/api/incidents/{inc_id}/tags")
def set_tags(inc_id: int, b: TagsBody, user=Depends(analyst)):
    clean = sorted({t.strip().lower()[:40] for t in b.tags if t.strip() and all(c.isalnum() or c in "-_:." for c in t.strip())})
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        before, i.tags = i.tags, clean
        db.commit()
    audit(user.username, "incident.tags", f"INC-{inc_id}", before=before, after=clean)
    return {"ok": True, "tags": clean}


class MergeBody(BaseModel):
    into: int


@router.post("/api/incidents/{inc_id}/merge")
def merge(inc_id: int, b: MergeBody, user=Depends(analyst)):
    if b.into == inc_id:
        raise SieveError(BAD_REQUEST, "An incident cannot be merged into itself.", status=422)
    with SessionLocal() as db:
        src, dst = get_incident(db, inc_id, user), get_incident(db, b.into, user)
        if src.tenant_id != dst.tenant_id:
            raise SieveError(BAD_REQUEST, "Incidents of different customers cannot be merged.", status=422)
        if src.merged_into or dst.merged_into:
            raise SieveError(BAD_REQUEST, "One of these incidents was already merged.", status=409)
        for a in list(src.alerts):
            a.incident_id = dst.id
        dst.alert_count = (dst.alert_count or 0) + (src.alert_count or 0)
        dst.first_seen = min(aware(dst.first_seen), aware(src.first_seen))
        dst.last_seen = max(aware(dst.last_seen), aware(src.last_seen))
        dst.tactics = sorted(set(dst.tactics or []) | set(src.tactics or []))
        dst.techniques = sorted(set(dst.techniques or []) | set(src.techniques or []))
        dst.tripwire = dst.tripwire or src.tripwire
        dst.tripwire_hits = list(dst.tripwire_hits or []) + list(src.tripwire_hits or [])
        src.merged_into, src.status, src.resolved_at = dst.id, "merged", utcnow()
        db.add(Comment(incident_id=dst.id, author=user.username, body=f"Merged INC-{src.id:04d} into this incident."))
        db.commit()
    audit(user.username, "incident.merged", f"INC-{inc_id}", into=b.into)
    return {"ok": True, "into": b.into}


@router.get("/api/incidents/{inc_id}/exception-suggestion")
def exception_suggestion(inc_id: int, user=Depends(analyst)):
    with SessionLocal() as db:
        return suggest_exception(get_incident(db, inc_id, user))


def _exc_out(x: AlertException) -> dict:
    expired = bool(x.expires_at and aware(x.expires_at) < utcnow())
    return {"id": x.id, "rule_id": x.rule_id, "agent_name": x.agent_name, "srcip": x.srcip, "user": x.user,
            "reason": x.reason, "created_by": x.created_by, "created_at": iso(x.created_at),
            "expires_at": iso(x.expires_at), "hits": x.hits, "active": x.active and not expired, "expired": expired,
            "from_incident": x.from_incident}


@router.get("/api/exceptions")
def list_exceptions(user=Depends(viewer)):
    with SessionLocal() as db:
        q = select(AlertException).order_by(AlertException.id.desc())
        if tenant_of(user):
            q = q.where(AlertException.tenant_id == tenant_of(user))
        return [_exc_out(x) for x in db.scalars(q)]


class ExceptionBody(BaseModel):
    rule_id: str | None = Field(None, max_length=32)
    agent_name: str | None = Field(None, max_length=200)
    srcip: str | None = Field(None, max_length=64)
    user: str | None = Field(None, max_length=200)
    reason: str = Field(min_length=3, max_length=500)
    expires_in_days: int | None = Field(30, ge=1, le=365)
    from_incident: int | None = None


@router.post("/api/exceptions", status_code=201)
def create_exception(b: ExceptionBody, user=Depends(analyst)):
    scope = [v for v in (b.rule_id, b.agent_name, b.srcip, b.user) if v]
    if not scope:
        raise SieveError(BAD_REQUEST, "An exception needs at least one of rule, host, source IP or user.", status=422)
    if not b.rule_id and len(scope) < 2:
        raise SieveError(BAD_REQUEST, "Without a rule ID, give at least two of host, source IP and user, "
                                      "so the exception stays narrow.", status=422)
    with SessionLocal() as db:
        if b.from_incident:
            get_incident(db, b.from_incident, user)
        x = AlertException(rule_id=b.rule_id, agent_name=b.agent_name, srcip=b.srcip, user=b.user,
                           reason=b.reason.strip(), created_by=user.username, from_incident=b.from_incident,
                           tenant_id=tenant_of(user),
                           expires_at=utcnow() + timedelta(days=b.expires_in_days) if b.expires_in_days else None)
        db.add(x)
        db.commit()
        out = _exc_out(x)
    keys = ("rule_id", "agent_name", "srcip", "user", "reason", "expires_at")
    audit(user.username, "exception.created", f"exception#{out['id']}", **{k: out[k] for k in keys})
    return out


@router.delete("/api/exceptions/{xid}")
def remove_exception(xid: int, user=Depends(analyst)):
    with SessionLocal() as db:
        x = db.get(AlertException, xid)
        if not x or (tenant_of(user) and x.tenant_id != tenant_of(user)):
            raise SieveError(NOT_FOUND, "Exception not found.", status=404)
        x.active = False
        db.commit()
    audit(user.username, "exception.removed", f"exception#{xid}")
    return {"ok": True}


class MaintenanceBody(BaseModel):
    agent_name: str = Field(min_length=1, max_length=200)
    starts_at: str
    ends_at: str
    reason: str = Field(min_length=3, max_length=300)


@router.get("/api/maintenance")
def list_maintenance(user=Depends(p_viewer)):
    now = utcnow()
    with SessionLocal() as db:
        return [{"id": m.id, "agent_name": m.agent_name, "starts_at": iso(m.starts_at), "ends_at": iso(m.ends_at),
                 "reason": m.reason, "created_by": m.created_by,
                 "state": "active" if aware(m.starts_at) <= now <= aware(m.ends_at) else
                 ("upcoming" if aware(m.starts_at) > now else "past")}
                for m in db.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at.desc()).limit(200))]


@router.post("/api/maintenance", status_code=201)
def add_maintenance(b: MaintenanceBody, user=Depends(p_admin)):
    from datetime import UTC, datetime
    try:
        st = datetime.fromisoformat(b.starts_at.replace("Z", "+00:00"))
        en = datetime.fromisoformat(b.ends_at.replace("Z", "+00:00"))
    except ValueError as e:
        raise SieveError(BAD_REQUEST, "Times must be ISO 8601, e.g. 2026-10-20T22:00:00Z.", status=422) from e
    st, en = (st if st.tzinfo else st.replace(tzinfo=UTC)), (en if en.tzinfo else en.replace(tzinfo=UTC))
    if en <= st or en - st > timedelta(days=7):
        raise SieveError(BAD_REQUEST, "A window must end after it starts and last at most 7 days.", status=422)
    with SessionLocal() as db:
        m = MaintenanceWindow(agent_name=b.agent_name.strip(), starts_at=st, ends_at=en, reason=b.reason.strip(),
                              created_by=user.username)
        db.add(m)
        db.commit()
        mid = m.id
    audit(user.username, "maintenance.created", f"window#{mid}", agent=b.agent_name, starts=b.starts_at, ends=b.ends_at)
    return {"ok": True, "id": mid}


@router.delete("/api/maintenance/{mid}")
def end_maintenance(mid: int, user=Depends(p_admin)):
    with SessionLocal() as db:
        m = db.get(MaintenanceWindow, mid)
        if not m:
            raise SieveError(NOT_FOUND, "Window not found.", status=404)
        m.ends_at = min(aware(m.ends_at), utcnow())
        db.commit()
    audit(user.username, "maintenance.ended", f"window#{mid}")
    return {"ok": True}


@router.get("/api/tuning/noisy-rules")
def tuning(days: int = Query(30, ge=1, le=365), user=Depends(p_viewer)):
    with SessionLocal() as db:
        return noisy_rules(db, days)


class TokenBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    expires_in_days: int | None = Field(90, ge=1, le=730)


@router.get("/api/tokens")
def list_tokens(user=Depends(p_admin)):
    with SessionLocal() as db:
        return [{"id": t.id, "name": t.name, "prefix": t.prefix, "role": t.role, "created_by": t.created_by,
                 "created_at": iso(t.created_at), "expires_at": iso(t.expires_at), "last_used_at": iso(t.last_used_at),
                 "revoked": t.revoked} for t in db.scalars(select(ApiToken).order_by(ApiToken.id.desc()))]


@router.post("/api/tokens", status_code=201)
def new_token(b: TokenBody, user=Depends(p_admin)):
    tok, row = create_api_token(b.name, b.role, user.username, b.expires_in_days)
    audit(user.username, "token.created", b.name, role=b.role, prefix=row.prefix)
    return {"token": tok, "id": row.id, "note": "Shown once. Use it as: Authorization: Bearer <token>"}


@router.delete("/api/tokens/{tid}")
def revoke_token(tid: int, user=Depends(p_admin)):
    with SessionLocal() as db:
        t = db.get(ApiToken, tid)
        if not t:
            raise SieveError(NOT_FOUND, "Token not found.", status=404)
        t.revoked = True
        db.commit()
    audit(user.username, "token.revoked", f"token#{tid}")
    return {"ok": True}


def _me(db, user) -> User:
    u = db.get(User, user.id)
    if u is None:
        raise SieveError(BAD_REQUEST, "API tokens cannot manage two-factor sign-in.", status=422)
    return u


@router.post("/api/auth/2fa/setup")
def totp_setup(user=Depends(viewer)):
    s = runtime.current()
    secret = totp.new_secret()
    with SessionLocal() as db:
        u = _me(db, user)
        if u.totp_enabled:
            raise SieveError(BAD_REQUEST, "Two-factor sign-in is already on. Turn it off first to re-enrol.", status=409)
        u.totp_secret = secrets_store._fernet(s.secret_key).encrypt(secret.encode()).decode()
        db.commit()
    return {"secret": secret, "uri": totp.uri(secret, user.username)}


class CodeBody(BaseModel):
    code: str = Field(min_length=6, max_length=8)
    password: str | None = None


@router.post("/api/auth/2fa/enable")
def totp_enable(b: CodeBody, user=Depends(viewer)):
    s = runtime.current()
    with SessionLocal() as db:
        u = _me(db, user)
        if not u.totp_secret:
            raise SieveError(BAD_REQUEST, "Start set-up first.", status=409)
        raw = secrets_store._fernet(s.secret_key).decrypt(u.totp_secret.encode()).decode()
        if not totp.verify(raw, b.code):
            raise SieveError(AUTH_TOTP, "That code did not match. Check the phone's clock and try the next code.",
                             status=422)
        u.totp_enabled = True
        db.commit()
    audit(user.username, "auth.2fa_enabled", user.username)
    return {"ok": True}


@router.post("/api/auth/2fa/disable")
def totp_disable(b: CodeBody, user=Depends(viewer)):
    s = runtime.current()
    with SessionLocal() as db:
        u = _me(db, user)
        if not (u.totp_enabled and b.password and verify_password(u.password_hash, b.password)):
            raise SieveError(AUTH_TOTP, "Give your password and a current code to turn two-factor sign-in off.", status=422)
        raw = secrets_store._fernet(s.secret_key).decrypt(u.totp_secret.encode()).decode()
        if not totp.verify(raw, b.code):
            raise SieveError(AUTH_TOTP, "That code did not match.", status=422)
        u.totp_enabled, u.totp_secret = False, None
        db.commit()
    audit(user.username, "auth.2fa_disabled", user.username)
    return {"ok": True}


@router.get("/api/reports/executive")
def executive(days: int = Query(7, ge=1, le=90), tenant: int | None = None, user=Depends(viewer)):
    from collections import Counter

    from ..models import Tenant
    since = utcnow() - timedelta(days=days)
    with SessionLocal() as db:
        q_kept = select(func.count(Alert.id)).where(Alert.received_at >= since)
        kept = db.scalar(scoped(q_kept, Alert.tenant_id, user, tenant)) or 0
        supp = db.scalar(scoped(select(func.count(Suppression.id)).where(Suppression.created_at >= since),
                                Suppression.tenant_id, user, tenant)) or 0
        incs = db.scalars(scoped(select(Incident).where(Incident.opened_at >= since, Incident.is_selftest.is_(False)),
                                 Incident.tenant_id, user, tenant)).all()
        notes = db.scalar(select(func.count(func.distinct(Notification.incident_id))).where(
            Notification.at >= since, Notification.phase == "send", Notification.ok.is_(True),
            Notification.incident_id.in_([i.id for i in incs] or [-1]))) or 0
        open_now = db.scalar(scoped(select(func.count(Incident.id)).where(Incident.status.in_(("new", "acknowledged"))),
                                    Incident.tenant_id, user, tenant)) or 0
        tid = tenant_of(user) or tenant
        trow = db.get(Tenant, tid) if tid else None
        brand = {"name": trow.name, **(trow.brand or {})} if trow else {}
    tta = sorted((aware(i.acknowledged_at) - aware(i.opened_at)).total_seconds() / 60 for i in incs if i.acknowledged_at)
    ttr = sorted((aware(i.resolved_at) - aware(i.opened_at)).total_seconds() / 3600 for i in incs
                 if i.resolved_at and i.status in ("resolved", "false_positive"))
    sla_ok = [i for i in incs if i.sla_due and i.acknowledged_at and aware(i.acknowledged_at) <= aware(i.sla_due)]
    sla_n = [i for i in incs if i.sla_due and (i.acknowledged_at or aware(i.sla_due) < utcnow())]
    med = lambda xs: round(xs[len(xs) // 2], 1) if xs else None  # noqa: E731
    return {"days": days, "alerts": kept + supp, "suppressed": supp, "incidents": len(incs),
            "by_band": dict(Counter(i.band for i in incs)), "by_status": dict(Counter(i.status for i in incs)),
            "notified_incidents": notes, "open_now": open_now, "median_ack_min": med(tta), "median_resolve_h": med(ttr),
            "sla_met_pct": round(100 * len(sla_ok) / len(sla_n), 1) if sla_n else None,
            "false_positive_pct": round(100 * sum(i.status == "false_positive" for i in incs) / len(incs), 1) if incs else None,
            "manipulation_attempts": sum(1 for i in incs if i.tripwire),
            "top_hosts": Counter(i.agent_name for i in incs if i.agent_name).most_common(5),
            "top_techniques": Counter(t for i in incs for t in i.techniques).most_common(8),
            "noise_reduction_pct": round(100 * (1 - notes / (kept + supp)), 1) if kept + supp else None,
            "brand": brand}


@router.get("/api/reports/handover")
def handover(hours: int = Query(12, ge=1, le=72), user=Depends(viewer)):
    since = utcnow() - timedelta(hours=hours)
    from .incidents import summary
    with SessionLocal() as db:
        q_open = select(Incident).where(Incident.status.in_(("new", "acknowledged")))
        open_ = db.scalars(scoped(q_open, Incident.tenant_id, user)).all()
        closed = db.scalars(scoped(select(Incident).where(Incident.resolved_at >= since), Incident.tenant_id, user)).all()
        ids = scoped(select(Incident.id), Incident.tenant_id, user)
        comments = db.scalars(select(Comment).where(Comment.at >= since, Comment.incident_id.in_(ids))
                              .order_by(Comment.at.desc()).limit(50)).all()
        ordered = sorted(open_, key=lambda i: (i.band != "critical", i.band != "high"))
        return {"hours": hours, "open": [summary(i) for i in ordered],
                "closed": [summary(i) for i in closed],
                "notes": [{"incident_id": c.incident_id, "author": c.author, "body": c.body, "at": iso(c.at)} for c in comments],
                "overdue": [summary(i) for i in open_ if i.sla_due and aware(i.sla_due) < utcnow() and i.status == "new"]}

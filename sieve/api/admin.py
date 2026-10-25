"""Admin: users and invites, runtime settings, secrets, plugins, audit log."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from .. import plugins, runtime, secrets_store
from ..auth import admin, audit, create_invite, set_role
from ..config import apply_update, public_view, save_override
from ..errors import BAD_REQUEST, SieveError
from ..models import AuditEvent, User
from .common import SessionLocal, iso

router = APIRouter(tags=["Admin"])


@router.get("/api/users")
def list_users(_=Depends(admin)):
    with SessionLocal() as db:
        return [{"id": u.id, "username": u.username, "role": u.role, "created_at": iso(u.created_at),
                 "last_login_at": iso(u.last_login_at), "locked": bool(u.locked_until)}
                for u in db.scalars(select(User).order_by(User.id))]


class InviteBody(BaseModel):
    role: Literal["viewer", "analyst", "admin"] = "analyst"


@router.post("/api/users/invite", status_code=201)
def invite(body: InviteBody, user=Depends(admin)):
    tok = create_invite(body.role, user.username)
    audit(user.username, "user.invite_created", body.role)
    base = runtime.current().notify.public_url.rstrip("/")
    return {"url": f"{base}/invite/{tok}", "role": body.role, "expires_in_hours": 72,
            "note": "Shown once. Send it privately; it works one time."}


class RoleBody(BaseModel):
    role: Literal["viewer", "analyst", "admin"]


@router.post("/api/users/{user_id}/role")
def change_role(user_id: int, body: RoleBody, user=Depends(admin)):
    u, old = set_role(user_id, body.role)
    audit(user.username, "user.role_changed", u.username, before=old, after=body.role)
    return {"ok": True, "id": u.id, "role": u.role}


def _secret_names(s) -> list[str]:
    names = [s.notify.telegram.token_env, s.notify.slack.token_env, s.notify.slack.webhook_env,
             s.notify.discord.webhook_env, s.wazuh.password_env, s.wazuh.indexer_password_env,
             s.intel.abuseipdb_key_env]
    names += [p.api_key_env for p in s.llm.providers if p.api_key_env]
    for m in plugins.REGISTRY.values():
        for f in m.secret_fields:
            n = m.settings_schema["properties"][f].get("x-secret-name")
            if n:
                names.append(n)
    return sorted({n for n in names if secrets_store.valid_name(n)})


@router.get("/api/settings")
def get_settings_view(_=Depends(admin)):
    s = runtime.current()
    return {"settings": public_view(s), "secrets": secrets_store.status(_secret_names(s), s.secret_key),
            "override_file": str(s.override_path)}


def _diff(before: dict, after: dict) -> dict:
    return {k: {"before": before.get(k), "after": after.get(k)} for k in after if before.get(k) != after.get(k)}


@router.put("/api/settings")
def put_settings(patch: dict, user=Depends(admin)):
    s = runtime.current()
    new, applied = apply_update(s, patch)
    save_override(s, applied)
    before = public_view(s)
    runtime.set_current(new)
    audit(user.username, "settings.updated", ",".join(sorted(applied)), changes=_diff(before, public_view(new)))
    return {"ok": True, "settings": public_view(new)}


class SecretBody(BaseModel):
    name: str
    value: str = ""


@router.put("/api/secrets")
def put_secret(body: SecretBody, user=Depends(admin)):
    s = runtime.current()
    if body.name not in _secret_names(s):
        raise SieveError(BAD_REQUEST, "That secret name is not used by any setting.", status=422)
    if body.value:
        secrets_store.put(body.name, body.value, s.secret_key, user.username)
    else:
        secrets_store.delete(body.name)
    audit(user.username, "secret.set" if body.value else "secret.cleared", body.name)  # never the value
    return {"ok": True, "name": body.name, "status": "stored" if body.value else "unset"}


@router.get("/api/plugins")
def list_plugins(_=Depends(admin)):
    s = runtime.current()
    out = []
    for m in plugins.REGISTRY.values():
        names = [m.settings_schema["properties"][f].get("x-secret-name") for f in m.secret_fields]
        out.append({"id": m.id, "name": m.name, "type": m.type, "version": m.version, "description": m.description,
                    "permissions": m.permissions, "settings_schema": m.settings_schema,
                    "enabled": plugins.is_enabled(s, m.id), "config": plugins.config(s, m.id),
                    "secrets": secrets_store.status([n for n in names if n], s.secret_key)})
    return out


class PluginBody(BaseModel):
    enabled: bool | None = None
    config: dict = {}
    approve_permissions: bool = False


@router.put("/api/plugins/{pid}")
def put_plugin(pid: str, body: PluginBody, user=Depends(admin)):
    s = runtime.current()
    m = plugins.get(pid)
    if body.enabled and not plugins.is_enabled(s, pid) and not body.approve_permissions:
        raise SieveError("SIEVE-PLG-428", f"Approve {m.name}'s permissions to enable it.",
                         f"It needs network access to {', '.join(m.permissions.get('network', [])) or 'nothing'}.",
                         status=428)
    cfg = {**plugins.config(s, pid), **plugins.validate_settings(m, body.config)}
    enabled = plugins.is_enabled(s, pid) if body.enabled is None else body.enabled
    new, applied = apply_update(s, {"plugins": {pid: {"enabled": enabled, "config": cfg}}})
    save_override(s, applied)
    runtime.set_current(new)
    audit(user.username, "plugin.updated", pid, enabled=enabled, permissions=m.permissions)
    return {"ok": True, "enabled": enabled, "config": cfg}


@router.get("/api/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
              action: str | None = None, _=Depends(admin)):
    with SessionLocal() as db:
        q = select(AuditEvent)
        if action:
            q = q.where(AuditEvent.action.startswith(action[:40]))
        total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = db.scalars(q.order_by(AuditEvent.id.desc()).offset(offset).limit(limit)).all()
        return {"total": total, "items": [{"id": r.id, "at": iso(r.at), "actor": r.actor, "action": r.action,
                                           "target": r.target, "detail": r.detail} for r in rows]}

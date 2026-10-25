"""First-run setup, login/logout, session info and invite acceptance."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from .. import __version__, ratelimit, runtime
from ..auth import (
    accept_invite,
    audit,
    clear_session,
    create_user,
    get_db,
    invite_info,
    issue_session,
    login,
    users_exist,
    viewer,
)
from ..errors import SETUP_DONE, SieveError

router = APIRouter(tags=["Auth"])


class Creds(BaseModel):
    username: str
    password: str
    otp: str | None = None


def _secure(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


@router.get("/api/setup/status")
def setup_status():
    return {"needs_admin": not users_exist(), "setup_done": users_exist(), "version": __version__}


@router.post("/api/setup", status_code=201)
@router.post("/api/setup/admin", status_code=201)
def first_run_setup(body: Creds, request: Request, response: Response):
    if users_exist():
        raise SieveError(SETUP_DONE, "Setup is already complete.", status=409)
    u = create_user(body.username, body.password, "admin")
    audit(u.username, "setup.admin_created", u.username)
    issue_session(response, u, runtime.current().secret_key, _secure(request))
    return {"ok": True, "username": u.username, "role": u.role}


@router.post("/api/auth/login")
def do_login(body: Creds, request: Request, response: Response, db=Depends(get_db)):
    ratelimit.check("login", request.client.host if request.client else "?")
    _, user = login(body.username[:80], body.password[:1024], db, runtime.current().secret_key, body.otp)
    issue_session(response, user, runtime.current().secret_key, _secure(request))
    return {"ok": True, "username": user.username, "role": user.role}


@router.post("/api/auth/logout")
def do_logout(response: Response, user=Depends(viewer)):
    clear_session(response)
    audit(user.username, "auth.logout", user.username)
    return {"ok": True}


@router.get("/api/auth/me")
@router.get("/api/me")
def me(user=Depends(viewer)):
    s = runtime.current()
    return {"id": user.id, "username": user.username, "role": user.role, "totp_enabled": bool(user.totp_enabled),
            "trainee": bool(getattr(user, "trainee", False)), "tenant_id": getattr(user, "tenant_id", None),
            "multi_tenant": s.multi_tenant,
            "must_enroll_2fa": bool(s.require_2fa_for_admins and user.role == "admin" and not user.totp_enabled),
            "simple_mode_default": s.simple_mode_default}


@router.get("/api/invites/{token}")
def invite_check(token: str):
    inv = invite_info(token)
    return {"ok": True, "role": inv.role, "expires_at": inv.expires_at.isoformat()}


@router.post("/api/invites/{token}/accept", status_code=201)
def invite_accept(token: str, body: Creds, request: Request, response: Response):
    u = accept_invite(token, body.username, body.password)
    audit(u.username, "user.invite_accepted", u.username, role=u.role)
    issue_session(response, u, runtime.current().secret_key, _secure(request))
    return {"ok": True, "username": u.username, "role": u.role}


@router.get("/api/auth/oidc/config")
def oidc_config():
    from ..oidc import describe
    return describe(runtime.current())


@router.get("/api/auth/oidc/start")
async def oidc_start(request: Request):
    from fastapi.responses import RedirectResponse

    from ..oidc import describe, start
    s = runtime.current()
    if not describe(s)["enabled"]:
        raise SieveError("SIEVE-SSO-404", "Single sign-on is not configured.", status=404)
    url, cookie = await start(s)
    r = RedirectResponse(url, status_code=302)
    r.set_cookie("sieve_oidc", cookie, httponly=True, samesite="lax", secure=_secure(request), max_age=600, path="/api/auth/oidc")
    return r


@router.get("/api/auth/oidc/callback")
async def oidc_callback(request: Request, code: str = "", state: str = ""):
    from fastapi.responses import RedirectResponse

    from ..oidc import callback, upsert_user
    s = runtime.current()
    claims = await callback(s, code, state, request.cookies.get("sieve_oidc"))
    u = upsert_user(s, claims)
    audit(u.username, "auth.login_sso", u.username, issuer=s.oidc.issuer)
    r = RedirectResponse("/", status_code=302)
    r.delete_cookie("sieve_oidc", path="/api/auth/oidc")
    issue_session(r, u, s.secret_key, _secure(request))
    return r

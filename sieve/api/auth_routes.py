"""First-run setup, login/logout, session info and invite acceptance."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from .. import __version__, runtime
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
    _, user = login(body.username[:80], body.password[:1024], db, runtime.current().secret_key)
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
    return {"id": user.id, "username": user.username, "role": user.role,
            "simple_mode_default": runtime.current().simple_mode_default}


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

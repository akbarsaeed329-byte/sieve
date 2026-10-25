"""Login/logout/setup routes."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..auth import get_db, hash_password, login, require_role
from ..errors import SieveError
from ..models import AuditEvent, User

router = APIRouter(tags=["Auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class SetupBody(BaseModel):
    username: str
    password: str


@router.get("/api/setup/status")
def setup_status(db: Session = Depends(get_db)):
    has_admin = db.query(User).filter(User.role == "admin").first() is not None
    return {"setup_done": has_admin}


@router.post("/api/setup", status_code=201)
def first_run_setup(body: SetupBody, db: Session = Depends(get_db)):
    if db.query(User).filter(User.role == "admin").first():
        raise HTTPException(409, {"code": "SIEVE-SETUP-409",
                                  "message": "Setup already done",
                                  "fix": "Log in with the admin account."})
    if len(body.password) < 12:
        raise HTTPException(400, {"code": "SIEVE-CFG-001",
                                  "message": "Password must be at least 12 characters"})
    user = User(username=body.username, password_hash=hash_password(body.password), role="admin")
    db.add(user)
    db.add(AuditEvent(actor=body.username, action="setup", target="admin_created"))
    db.commit()
    return {"created": True}


@router.post("/api/auth/login")
def do_login(body: LoginBody, response: Response, db: Session = Depends(get_db)):
    from ..app import get_settings
    settings = get_settings()
    try:
        token, user = login(body.username, body.password, db, settings.secret_key)
    except SieveError as e:
        raise HTTPException(status_code=e.status, detail=e.to_dict()) from e
    response.set_cookie("sieve_session", token, httponly=True,
                        samesite="strict", max_age=3600 * 8)
    return {"username": user.username, "role": user.role}


@router.post("/api/auth/logout")
def do_logout(response: Response, _user=Depends(require_role("admin", "analyst", "viewer"))):
    response.delete_cookie("sieve_session")
    return {"ok": True}


@router.get("/api/auth/me")
def me(user=Depends(require_role("admin", "analyst", "viewer"))):
    return {"username": user.username, "role": user.role}

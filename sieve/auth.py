"""Auth: Argon2id passwords, signed session cookie, CSRF, role guards, lockout, invites, audit.

* Session: HttpOnly, SameSite=Strict cookie ``sieve_session`` signed with itsdangerous (8 h).
* CSRF: double-submit. ``sieve_csrf`` (readable by the page) is an HMAC of the session token; every
  non-GET request must echo it in the ``X-Sieve-CSRF`` header.
* Lockout: 10 failures -> 30-minute lock. Roles: admin > analyst > viewer.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import timedelta

import argon2
from fastapi import Cookie, Depends, HTTPException, Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .errors import (
    AUTH_BAD_LOGIN,
    AUTH_CSRF,
    AUTH_INVITE_INVALID,
    AUTH_LAST_ADMIN,
    AUTH_LOCKED,
    AUTH_REQUIRED,
    AUTH_USER_EXISTS,
    AUTH_WEAK_PASSWORD,
    BAD_REQUEST,
    SieveError,
)
from .models import AuditEvent, Invite, User, aware, utcnow

_ph = argon2.PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
_MAX_FAIL = 10
_LOCK_MINUTES = 30
SESSION_TTL = 3600 * 8
INVITE_HOURS = 72
ROLES = ("viewer", "analyst", "admin")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
_DUMMY_HASH = _ph.hash("timing-equaliser-not-a-password")


def _signer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="sieve-session")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    try:
        return _ph.verify(hash_, password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHashError):
        return False


def check_password_strength(password: str) -> None:
    if len(password or "") < 12:
        raise SieveError(AUTH_WEAK_PASSWORD, "The password must be at least 12 characters.", status=422)


def check_username(username: str) -> str:
    u = (username or "").strip()
    if not (2 <= len(u) <= 80) or not all(c.isalnum() or c in "._-@" for c in u):
        raise SieveError(BAD_REQUEST, "Usernames are 2-80 letters, digits, dots, dashes, underscores or @.",
                         status=422)
    return u


def make_session_token(user_id: int, secret: str) -> str:
    return _signer(secret).dumps({"uid": user_id, "n": secrets.token_hex(4)})


def decode_session(token: str, secret: str) -> int:
    try:
        data = _signer(secret).loads(token, max_age=SESSION_TTL)
        return int(data["uid"])
    except (SignatureExpired, BadSignature, KeyError, TypeError, ValueError) as e:
        raise SieveError(AUTH_REQUIRED, "Session expired or invalid.", status=401) from e


def csrf_for(session_token: str, secret: str) -> str:
    return hmac.new(secret.encode(), b"csrf:" + session_token.encode(), hashlib.sha256).hexdigest()[:40]


def issue_session(response: Response, user: User, secret: str, secure: bool) -> None:
    tok = make_session_token(user.id, secret)
    response.set_cookie("sieve_session", tok, httponly=True, samesite="strict", secure=secure,
                        max_age=SESSION_TTL, path="/")
    response.set_cookie("sieve_csrf", csrf_for(tok, secret), httponly=False, samesite="strict", secure=secure,
                        max_age=SESSION_TTL, path="/")


def clear_session(response: Response) -> None:
    response.delete_cookie("sieve_session", path="/")
    response.delete_cookie("sieve_csrf", path="/")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def audit(actor: str, action: str, target: str = "", **detail) -> None:
    with SessionLocal() as db:
        db.add(AuditEvent(actor=actor[:80], action=action[:80], target=str(target)[:200], detail=detail))
        db.commit()


def _deny(status: int, code: str, message: str) -> HTTPException:
    e = SieveError(code, message, status=status)
    return HTTPException(status_code=status, detail=e.to_dict())


def require_role(*roles: str) -> Callable:
    """Dependency returning the signed-in User; 401 if not signed in, 403 if the role is not allowed,
    419 if a state-changing request lacks the CSRF header."""
    def dep(request: Request, sieve_session: str | None = Cookie(default=None),
            db: Session = Depends(get_db)) -> User:
        from . import runtime
        secret = runtime.current().secret_key
        if not sieve_session:
            raise _deny(401, AUTH_REQUIRED, "Not signed in.")
        try:
            uid = decode_session(sieve_session, secret)
        except SieveError as e:
            raise _deny(401, AUTH_REQUIRED, e.message) from e
        user = db.get(User, uid)
        if not user or (user.locked_until and aware(user.locked_until) > utcnow()):
            raise _deny(401, AUTH_REQUIRED, "Not signed in.")
        if request.method not in SAFE_METHODS:
            sent = request.headers.get("x-sieve-csrf", "")
            if not hmac.compare_digest(sent, csrf_for(sieve_session, secret)):
                raise _deny(419, AUTH_CSRF, "Missing or wrong security token.")
        if roles and user.role not in roles:
            raise _deny(403, AUTH_REQUIRED, f"This needs the {' or '.join(roles)} role.")
        return user
    return dep


viewer = require_role("admin", "analyst", "viewer")
analyst = require_role("admin", "analyst")
admin = require_role("admin")


def login(username: str, password: str, db: Session, secret: str) -> tuple[str, User]:
    user = db.scalar(select(User).where(User.username == username))
    now = utcnow()
    if user and user.locked_until and now < aware(user.locked_until):
        raise SieveError(AUTH_LOCKED, f"Account locked until {aware(user.locked_until).strftime('%H:%M UTC')}.",
                         status=423)
    ok = verify_password(user.password_hash if user else _DUMMY_HASH, password)
    if not user or not ok:
        if user:
            user.failed_logins += 1
            if user.failed_logins >= _MAX_FAIL:
                user.locked_until = now + timedelta(minutes=_LOCK_MINUTES)
                user.failed_logins = 0
        db.add(AuditEvent(actor=username[:80], action="auth.login_failed", target=username[:200]))
        db.commit()
        raise SieveError(AUTH_BAD_LOGIN, "Incorrect username or password.", status=401)
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    db.add(AuditEvent(actor=user.username, action="auth.login", target=user.username))
    db.commit()
    return make_session_token(user.id, secret), user


def users_exist() -> bool:
    with SessionLocal() as db:
        return (db.scalar(select(func.count(User.id))) or 0) > 0


def create_user(username: str, password: str, role: str) -> User:
    username = check_username(username)
    check_password_strength(password)
    if role not in ROLES:
        raise SieveError(BAD_REQUEST, f"Unknown role {role}.", status=422)
    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.username == username)):
            raise SieveError(AUTH_USER_EXISTS, "That username is taken.", status=409)
        u = User(username=username, password_hash=hash_password(password), role=role)
        db.add(u)
        db.commit()
        return u


def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def create_invite(role: str, actor: str) -> str:
    if role not in ROLES:
        raise SieveError(BAD_REQUEST, f"Unknown role {role}.", status=422)
    tok = secrets.token_urlsafe(24)
    with SessionLocal() as db:
        db.add(Invite(token_hash=_hash_token(tok), role=role, created_by=actor,
                      expires_at=utcnow() + timedelta(hours=INVITE_HOURS)))
        db.commit()
    return tok


def invite_info(tok: str) -> Invite:
    with SessionLocal() as db:
        inv = db.scalar(select(Invite).where(Invite.token_hash == _hash_token(tok)))
        if not inv or inv.used_at or aware(inv.expires_at) < utcnow():
            raise SieveError(AUTH_INVITE_INVALID, "This invite link is invalid, used or expired.", status=410)
        return inv


def accept_invite(tok: str, username: str, password: str) -> User:
    inv = invite_info(tok)
    u = create_user(username, password, inv.role)
    with SessionLocal() as db:
        row = db.get(Invite, inv.id)
        if row.used_at:  # raced
            raise SieveError(AUTH_INVITE_INVALID, "This invite link was already used.", status=410)
        row.used_at, row.used_by = utcnow(), u.username
        db.commit()
    return u


def set_role(user_id: int, role: str) -> tuple[User, str]:
    if role not in ROLES:
        raise SieveError(BAD_REQUEST, f"Unknown role {role}.", status=422)
    with SessionLocal() as db:
        u = db.get(User, user_id)
        if not u:
            raise SieveError("SIEVE-API-404", "User not found.", status=404)
        old = u.role
        if old == "admin" and role != "admin":
            admins = db.scalar(select(func.count(User.id)).where(User.role == "admin")) or 0
            if admins <= 1:
                raise SieveError(AUTH_LAST_ADMIN, "Sieve must keep at least one admin.", status=409)
        u.role = role
        db.commit()
        return u, old

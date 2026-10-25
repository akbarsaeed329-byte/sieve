"""Auth: Argon2id passwords, session cookie, role guards, account lockout.
Lockout threshold: 10 failures within 15 minutes → 30-minute lock.
"""
from __future__ import annotations
import secrets
from datetime import timedelta, timezone
from typing import Callable
import argon2
from fastapi import Cookie, Depends, HTTPException, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session
from .db import SessionLocal
from .errors import AUTH_BAD_LOGIN, AUTH_LOCKED, AUTH_REQUIRED, SieveError
from .models import AuditEvent, User, utcnow

_ph = argon2.PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
_MAX_FAIL = 10
_LOCK_MINUTES = 30
_SESSION_TTL = 3600 * 8


def _signer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="sieve-session")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    try:
        return _ph.verify(hash_, password)
    except argon2.exceptions.VerifyMismatchError:
        return False


def make_session_token(user_id: int, secret: str) -> str:
    return _signer(secret).dumps({"uid": user_id})


def decode_session(token: str, secret: str) -> int:
    try:
        data = _signer(secret).loads(token, max_age=_SESSION_TTL)
        return int(data["uid"])
    except (SignatureExpired, BadSignature, KeyError, TypeError) as e:
        raise SieveError(AUTH_REQUIRED, "Session expired or invalid",
                         "Log in again.", status=401) from e


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _current_user_id(sieve_session: str | None = Cookie(default=None),
                     secret: str = "") -> int:
    if not sieve_session:
        raise HTTPException(status_code=401, detail={"code": AUTH_REQUIRED, "message": "Not logged in"})
    try:
        return decode_session(sieve_session, secret)
    except SieveError as e:
        raise HTTPException(status_code=401, detail=e.to_dict()) from e


def require_role(*roles: str) -> Callable:
    def dep(sieve_session: str | None = Cookie(default=None),
            db: Session = Depends(get_db)) -> User:
        from .app import get_settings  # avoid circular import
        settings = get_settings()
        if not sieve_session:
            raise HTTPException(status_code=401, detail={"code": AUTH_REQUIRED})
        try:
            uid = decode_session(sieve_session, settings.secret_key)
        except SieveError as e:
            raise HTTPException(status_code=401, detail=e.to_dict()) from e
        user = db.get(User, uid)
        if not user:
            raise HTTPException(status_code=401, detail={"code": AUTH_REQUIRED})
        if roles and user.role not in roles:
            raise HTTPException(status_code=403, detail={"code": AUTH_REQUIRED,
                                                         "message": f"Requires role: {roles}"})
        return user
    return dep


def login(username: str, password: str, db: Session, secret: str) -> tuple[str, User]:
    user = db.query(User).filter(User.username == username).first()
    now = utcnow()
    if user and user.locked_until and now < user.locked_until:
        raise SieveError(AUTH_LOCKED, f"Account locked until {user.locked_until.strftime('%H:%M UTC')}",
                         "Wait for the lockout to expire.", status=423)
    if not user or not verify_password(user.password_hash, password):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= _MAX_FAIL:
                user.locked_until = now + timedelta(minutes=_LOCK_MINUTES)
                user.failed_logins = 0
            db.add(AuditEvent(actor=username, action="login_failed", target=username))
            db.commit()
        raise SieveError(AUTH_BAD_LOGIN, "Incorrect username or password",
                         "Check your credentials.", status=401)
    user.failed_logins = 0
    user.locked_until = None
    db.add(AuditEvent(actor=username, action="login", target=username))
    db.commit()
    return make_session_token(user.id, secret), user

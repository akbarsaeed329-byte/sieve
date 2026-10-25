"""OpenID Connect single sign-on (authorization code + PKCE). Works with Entra ID, Google, Okta, Keycloak.

ID tokens are verified against the provider's JWKS (RS256/ES256): issuer, audience, expiry and nonce.
Roles come from the groups claim; users are matched by the OIDC subject and created on first sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time

import jwt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from . import http, secrets_store
from .db import SessionLocal
from .errors import AUTH_REQUIRED, SieveError
from .models import User

_cache: dict[str, tuple[float, dict]] = {}


async def _get_json(url: str) -> dict:
    hit = _cache.get(url)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    async with http.client(timeout=10) as c:
        r = await c.get(url)
    if r.status_code != 200:
        raise SieveError("SIEVE-SSO-502", f"Identity provider returned HTTP {r.status_code}.", status=502)
    data = r.json()
    _cache[url] = (time.monotonic() + 3600, data)
    return data


async def discovery(issuer: str) -> dict:
    return await _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")


def _signer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="sieve-oidc")


def redirect_uri(settings) -> str:
    return settings.notify.public_url.rstrip("/") + "/api/auth/oidc/callback"


async def start(settings) -> tuple[str, str]:
    """Return (authorization URL, signed state cookie value)."""
    cfg = settings.oidc
    d = await discovery(cfg.issuer)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    from urllib.parse import urlencode

    url = (
        d["authorization_endpoint"]
        + "?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": cfg.client_id,
                "redirect_uri": redirect_uri(settings),
                "scope": "openid email profile",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
    )
    cookie = _signer(settings.secret_key).dumps({"s": state, "n": nonce, "v": verifier})
    return url, cookie


async def callback(settings, code: str, state: str, cookie: str | None) -> dict:
    cfg = settings.oidc
    try:
        st = _signer(settings.secret_key).loads(cookie or "", max_age=600)
    except BadSignature as e:
        raise SieveError(AUTH_REQUIRED, "Sign-in expired or was started elsewhere. Try again.", status=401) from e
    if not secrets.compare_digest(st["s"], state or ""):
        raise SieveError(AUTH_REQUIRED, "Sign-in state did not match. Try again.", status=401)
    d = await discovery(cfg.issuer)
    async with http.client(timeout=15) as c:
        r = await c.post(
            d["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri(settings),
                "client_id": cfg.client_id,
                "client_secret": secrets_store.resolve(cfg.client_secret_env),
                "code_verifier": st["v"],
            },
        )
    if r.status_code != 200 or "id_token" not in r.json():
        raise SieveError(AUTH_REQUIRED, "The identity provider refused the sign-in.", status=401)
    id_token = r.json()["id_token"]
    jwks = await _get_json(d["jwks_uri"])
    kid = jwt.get_unverified_header(id_token).get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise SieveError(AUTH_REQUIRED, "Unknown signing key from the identity provider.", status=401)
    try:
        claims = jwt.decode(
            id_token,
            jwt.PyJWK(key).key,
            algorithms=["RS256", "ES256", "PS256"],
            audience=cfg.client_id,
            issuer=d.get("issuer", cfg.issuer),
        )
    except jwt.PyJWTError as e:
        raise SieveError(AUTH_REQUIRED, f"ID token rejected ({type(e).__name__}).", status=401) from e
    if not secrets.compare_digest(str(claims.get("nonce", "")), st["n"]):
        raise SieveError(AUTH_REQUIRED, "ID token nonce mismatch.", status=401)
    return claims


def role_for(settings, claims: dict) -> str | None:
    cfg = settings.oidc
    groups = claims.get(cfg.groups_claim) or []
    groups = set(groups if isinstance(groups, list) else [groups])
    if groups & set(cfg.admin_groups):
        return "admin"
    if groups & set(cfg.analyst_groups):
        return "analyst"
    return None if cfg.default_role == "none" else cfg.default_role


def upsert_user(settings, claims: dict) -> User:
    role = role_for(settings, claims)
    if role is None:
        raise SieveError("SIEVE-AUTH-403", "Your account is not in a group that may use Sieve.", status=403)
    sub = f"{settings.oidc.issuer}|{claims['sub']}"[:200]
    base = (
        re.sub(r"[^A-Za-z0-9._@-]", "", str(claims.get("preferred_username") or claims.get("email") or claims["sub"]))[:60]
        or "sso-user"
    )
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.sso_subject == sub))
        if u is None:
            name, n = base, 1
            while db.scalar(select(User.id).where(User.username == name)):
                n += 1
                name = f"{base}-{n}"
            u = User(username=name, password_hash="!sso", role=role, sso_subject=sub, email=claims.get("email"))
            db.add(u)
        else:
            u.role = role  # groups at the IdP are the source of truth
        db.commit()
        db.refresh(u)
        return u


def describe(settings) -> dict:
    return {
        "enabled": bool(settings.oidc.enabled and settings.oidc.issuer and settings.oidc.client_id),
        "label": settings.oidc.button_label,
    }

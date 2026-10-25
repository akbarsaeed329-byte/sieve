"""Act from the phone: buttons in Telegram and Slack messages, on-call rotations, and Web Push.

Security:
* Telegram callbacks are accepted only with the secret token Telegram echoes in
  X-Telegram-Bot-Api-Secret-Token (set when registering the webhook).
* Slack actions are verified with the signing secret (v0 HMAC over timestamp and body, 5-minute window).
* A chat account must be linked to a Sieve user (one-time code shown in Settings > Security) before its
  buttons do anything; the action runs with that user's role and is audited under their name.
* Buttons only acknowledge or assign. Nothing a chat message can trigger touches a host.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import timedelta

from sqlalchemy import select

from . import secrets_store
from .db import SessionLocal
from .models import KV, AuditEvent, Incident, OnCall, PushSubscription, User, aware, utcnow

log = logging.getLogger("sieve.chatops")


def new_link_code(user_id: int) -> str:
    code = f"{secrets.randbelow(10**8):08d}"
    with SessionLocal() as db:
        u = db.get(User, user_id)
        u.link_code = hashlib.sha256(code.encode()).hexdigest()[:16]
        db.commit()
    return code


def _user_by_code(db, code: str) -> User | None:
    h = hashlib.sha256(code.strip().encode()).hexdigest()[:16]
    return db.scalar(select(User).where(User.link_code == h))


def act(db, user: User, action: str, inc_id: int) -> str:
    inc = db.get(Incident, inc_id)
    if inc is None:
        return "Incident not found."
    if user.tenant_id and inc.tenant_id != user.tenant_id:
        return "Incident not found."
    if user.role == "viewer":
        return "Your Sieve role cannot change incidents."
    if action == "ack":
        if inc.status == "new":
            inc.status, inc.acknowledged_at = "acknowledged", utcnow()
        inc.assignee = inc.assignee or user.username
        msg = f"INC-{inc.id:04d} acknowledged by {user.username}."
    elif action == "mine":
        inc.assignee = user.username
        if inc.status == "new":
            inc.status, inc.acknowledged_at = "acknowledged", utcnow()
        msg = f"INC-{inc.id:04d} assigned to {user.username}."
    else:
        return "Unknown action."
    db.add(AuditEvent(actor=user.username, action=f"chatops.{action}", target=f"INC-{inc.id}", detail={"via": "chat"}))
    db.commit()
    return msg


def telegram_markup(inc_id: int, url: str) -> dict:
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Acknowledge", "callback_data": f"ack:{inc_id}"},
                {"text": "🙋 Assign to me", "callback_data": f"mine:{inc_id}"},
            ],
            [{"text": "Open in Sieve", "url": url}],
        ]
    }


def handle_telegram(update: dict, settings, header_secret: str) -> dict:
    expected = secrets_store.resolve(settings.chatops.telegram_webhook_secret_env)
    if not expected or not hmac.compare_digest(header_secret or "", expected):
        return {"ok": False, "status": 401}
    with SessionLocal() as db:
        if "callback_query" in update:
            cq = update["callback_query"]
            tg_id = str((cq.get("from") or {}).get("id", ""))
            user = db.scalar(select(User).where(User.telegram_user_id == tg_id)) if tg_id else None
            if user is None:
                return {"ok": True, "reply": "Link your Telegram first: send /link <code> (Settings > Security in Sieve)."}
            action, _, inc = str(cq.get("data", "")).partition(":")
            return {"ok": True, "reply": act(db, user, action, int(inc) if inc.isdigit() else -1), "callback_id": cq.get("id")}
        msg = update.get("message") or {}
        text = str(msg.get("text", "")).strip()
        if text.startswith("/link"):
            user = _user_by_code(db, text[5:])
            if user is None:
                return {
                    "ok": True,
                    "reply": "That code is not valid. Create a new one in Sieve.",
                    "chat_id": (msg.get("chat") or {}).get("id"),
                }
            user.telegram_user_id, user.link_code = str((msg.get("from") or {}).get("id")), None
            db.add(AuditEvent(actor=user.username, action="chatops.linked", target="telegram"))
            db.commit()
            return {"ok": True, "reply": f"Linked to Sieve user {user.username}.", "chat_id": (msg.get("chat") or {}).get("id")}
    return {"ok": True}


def verify_slack(settings, ts: str, sig: str, body: bytes) -> bool:
    secret = secrets_store.resolve(settings.chatops.slack_signing_secret_env)
    try:
        if not secret or abs(time.time() - int(ts)) > 300:
            return False
    except ValueError:
        return False
    mine = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mine, sig or "")


def handle_slack(payload: dict) -> str:
    with SessionLocal() as db:
        sl_id = str((payload.get("user") or {}).get("id", ""))
        user = db.scalar(select(User).where(User.slack_user_id == sl_id)) if sl_id else None
        acts = payload.get("actions") or []
        if not acts:
            return "Nothing to do."
        value = str(acts[0].get("value", ""))
        if value.startswith("link:"):
            u = _user_by_code(db, value[5:])
            if u is None:
                return "That code is not valid."
            u.slack_user_id, u.link_code = sl_id, None
            db.commit()
            return f"Linked to Sieve user {u.username}."
        if user is None:
            return "Link your Slack account first (Settings > Security in Sieve)."
        action, _, inc = value.partition(":")
        return act(db, user, action, int(inc) if inc.isdigit() else -1)


# ---------------- on-call ----------------


def on_call_now(db, tenant_id: int | None = None) -> list[str]:
    out = []
    for r in db.scalars(select(OnCall).where(OnCall.enabled.is_(True))):
        if r.tenant_id not in (None, tenant_id) or not r.members:
            continue
        shifts = int((utcnow() - aware(r.starts_at)).total_seconds() // (r.shift_hours * 3600))
        out.append(r.members[shifts % len(r.members)])
    return out


def schedule(r: OnCall, n: int = 6) -> list[dict]:
    start = aware(r.starts_at)
    k0 = max(0, int((utcnow() - start).total_seconds() // (r.shift_hours * 3600)))
    return (
        [
            {
                "user": r.members[k % len(r.members)],
                "from": (start + timedelta(hours=k * r.shift_hours)).isoformat(),
                "to": (start + timedelta(hours=(k + 1) * r.shift_hours)).isoformat(),
            }
            for k in range(k0, k0 + n)
        ]
        if r.members
        else []
    )


# ---------------- Web Push ----------------


def vapid_keys() -> dict:
    """Generated once and kept in the KV store (private key encrypted with the secret store key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from . import runtime

    with SessionLocal() as db:
        row = db.get(KV, "vapid")
        if row:
            return row.value
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        import base64

        val = {
            "public": base64.urlsafe_b64encode(pub).decode().rstrip("="),
            "private_enc": secrets_store._fernet(runtime.current().secret_key).encrypt(pem).decode(),
        }
        db.add(KV(key="vapid", value=val))
        db.commit()
        return val


def _push(sub: PushSubscription, payload: dict) -> bool:
    from pywebpush import WebPushException, webpush

    from . import runtime

    keys = vapid_keys()
    pem = secrets_store._fernet(runtime.current().secret_key).decrypt(keys["private_enc"].encode()).decode()
    try:
        from py_vapid import Vapid

        v = Vapid.from_pem(pem.encode())
        webpush(
            {"endpoint": sub.endpoint, "keys": sub.keys},
            json.dumps(payload),
            vapid_private_key=v,
            vapid_claims={"sub": "mailto:sieve@localhost"},
            ttl=3600,
        )
        return True
    except WebPushException as e:
        if getattr(e, "response", None) is not None and e.response.status_code in (404, 410):
            with SessionLocal() as db:
                row = db.get(PushSubscription, sub.id)
                if row:
                    db.delete(row)
                    db.commit()
        return False
    except Exception:  # noqa: BLE001
        return False


async def push_users(usernames: list[str], inc: Incident, settings, reason: str = "") -> int:
    import asyncio

    if not settings.chatops.web_push or not usernames:
        return 0
    with SessionLocal() as db:
        ids = [u.id for u in db.scalars(select(User).where(User.username.in_(usernames)))]
        subs = db.scalars(select(PushSubscription).where(PushSubscription.user_id.in_(ids))).all()
    payload = {
        "title": f"{inc.band.capitalize()} · INC-{inc.id:04d}",
        "body": f"{inc.title} on {inc.agent_name}"[:180],
        "url": f"/incidents/{inc.id}",
        "tag": f"inc-{inc.id}",
        "reason": reason,
    }
    res = await asyncio.gather(*[asyncio.to_thread(_push, s, payload) for s in subs])
    return sum(res)


async def page_oncall(inc: Incident, settings, reason: str = "escalation") -> list[str]:
    with SessionLocal() as db:
        who = on_call_now(db, inc.tenant_id)
        users = db.scalars(select(User).where(User.username.in_(who))).all()
        emails = [u.email for u in users if u.email]
    await push_users(who, inc, settings, reason)
    if emails and settings.notify.email.enabled:
        from .notify.email import EmailNotifier

        n = EmailNotifier(settings)
        n.c = n.c.model_copy(update={"to": emails})
        try:
            await n.send(inc, settings.notify.public_url)
        except Exception:  # noqa: BLE001
            pass
    with SessionLocal() as db:
        db.add(AuditEvent(actor="sieve", action="oncall.paged", target=f"INC-{inc.id}", detail={"who": who, "reason": reason}))
        db.commit()
    return who

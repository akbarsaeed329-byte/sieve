"""Outbound integrations: signed webhooks (SOAR, ticketing, chat-ops), Jira issues, TheHive alerts.

Webhook body: {"event", "sent_at", "incident": {...}}. Signature: X-Sieve-Signature: sha256=<hex HMAC of the
raw body with the webhook's secret>, plus X-Sieve-Timestamp. Receivers should reject old timestamps.
Only validated entity fields are sent; untrusted log text is never included in outbound payloads.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

import httpx

from .. import http, secrets_store
from ..config import Settings
from ..db import SessionLocal
from ..models import Incident, Notification
from ..pipeline.score import band_rank

log = logging.getLogger("sieve.outbound")


def payload(inc: Incident, settings: Settings) -> dict:
    return {"id": inc.id, "ref": f"INC-{inc.id:04d}", "title": inc.title, "band": inc.band, "score": inc.score,
            "status": inc.status, "host": inc.agent_name, "srcip": inc.srcip, "user": inc.user,
            "alert_count": inc.alert_count, "tactics": inc.tactics, "techniques": inc.techniques,
            "tripwire": inc.tripwire, "assignee": inc.assignee, "tags": inc.tags or [],
            "url": f"{settings.notify.public_url.rstrip('/')}/incidents/{inc.id}"}


def sign(secret: str, ts: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def _record(inc_id: int | None, channel: str, ok: bool, error: str | None) -> None:
    try:
        with SessionLocal() as db:
            db.add(Notification(incident_id=inc_id, channel=channel[:32], phase="send", ok=ok, error=error))
            db.commit()
    except Exception:  # noqa: BLE001
        pass


async def emit(event: str, inc: Incident, settings: Settings) -> None:
    if settings.shadow_mode:
        return
    body = {"event": event, "sent_at": int(time.time()), "incident": payload(inc, settings)}
    raw = json.dumps(body, separators=(",", ":"), default=str).encode()
    for w in settings.webhooks:
        if not w.enabled or (event not in w.events and event != "automation") or band_rank(inc.band) < band_rank(w.min_band):
            continue
        ts = str(int(time.time()))
        headers = {"content-type": "application/json", "x-sieve-event": event, "x-sieve-timestamp": ts}
        secret = secrets_store.resolve(w.secret_env) if w.secret_env else ""
        if secret:
            headers["x-sieve-signature"] = sign(secret, ts, raw)
        try:
            async with http.client(timeout=10) as c:
                r = await c.post(w.url, content=raw, headers=headers)
            _record(inc.id, f"webhook:{w.name}", r.status_code < 300, None if r.status_code < 300 else f"HTTP {r.status_code}")
        except (httpx.TimeoutException, httpx.TransportError) as e:
            _record(inc.id, f"webhook:{w.name}", False, type(e).__name__)
    if event == "incident.notified":
        await _jira(inc, settings)
        await _thehive(inc, settings)


async def _jira(inc: Incident, settings: Settings) -> None:
    j = settings.jira
    if not (j.enabled and j.base_url and j.project_key) or band_rank(inc.band) < band_rank(j.min_band):
        return
    p = payload(inc, settings)
    desc = (f"{p['band'].upper()} incident from Sieve: {p['title']}\nHost: {p['host']}  Source: {p['srcip']}  "
            f"User: {p['user']}  Alerts: {p['alert_count']}\nATT&CK: {', '.join(p['techniques'])}\nOpen: {p['url']}")
    body = {"fields": {"project": {"key": j.project_key}, "issuetype": {"name": j.issue_type},
                       "summary": f"[Sieve {p['band']}] {p['ref']} {p['title']}"[:250],
                       "labels": ["sieve", f"sieve-{p['band']}"],
                       "description": {"type": "doc", "version": 1, "content": [
                           {"type": "paragraph", "content": [{"type": "text", "text": desc}]}]}}}
    try:
        async with http.client(timeout=15) as c:
            r = await c.post(f"{j.base_url.rstrip('/')}/rest/api/3/issue", json=body,
                             auth=(j.email, secrets_store.resolve(j.token_env)))
        ok = r.status_code in (200, 201)
        _record(inc.id, "jira", ok, None if ok else f"HTTP {r.status_code}")
        if ok:
            key = (r.json() or {}).get("key")
            if key:
                with SessionLocal() as db:
                    row = db.get(Incident, inc.id)
                    if row:
                        row.ticket_ref = {**(row.ticket_ref or {}), "jira": key,
                                          "jira_url": f"{j.base_url.rstrip('/')}/browse/{key}"}
                        db.commit()
    except (httpx.TimeoutException, httpx.TransportError) as e:
        _record(inc.id, "jira", False, type(e).__name__)


async def _thehive(inc: Incident, settings: Settings) -> None:
    t = settings.thehive
    if not (t.enabled and t.base_url) or band_rank(inc.band) < band_rank(t.min_band):
        return
    p = payload(inc, settings)
    sev = {"low": 1, "medium": 2, "high": 3, "critical": 4}[inc.band]
    observables = [{"dataType": "ip", "data": p["srcip"]}] if p["srcip"] else []
    body = {"type": "sieve", "source": "sieve", "sourceRef": p["ref"], "title": p["title"][:200], "severity": sev,
            "description": f"{p['alert_count']} alerts on {p['host']}. {p['url']}", "tags": ["sieve", *p["techniques"]],
            "observables": observables}
    try:
        async with http.client(timeout=15) as c:
            r = await c.post(f"{t.base_url.rstrip('/')}/api/v1/alert", json=body,
                             headers={"Authorization": f"Bearer {secrets_store.resolve(t.token_env)}"})
        _record(inc.id, "thehive", r.status_code in (200, 201), None if r.status_code in (200, 201) else f"HTTP {r.status_code}")
    except (httpx.TimeoutException, httpx.TransportError) as e:
        _record(inc.id, "thehive", False, type(e).__name__)

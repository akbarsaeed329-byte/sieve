"""Health: a public liveness probe, a detailed status page, and the connection tests behind every
"Test" button in the setup wizard and settings."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select, text

from .. import __version__, plugins, runtime
from ..auth import admin, audit, viewer
from ..errors import NOT_FOUND, NOTIFY_NOT_CONFIGURED, SieveError
from ..integrations import wazuh
from ..llm import client as llm
from ..models import KV, Incident, Notification, aware, utcnow
from ..notify import dispatch
from ..worker import Stats, enqueue, queue_depth
from .common import SessionLocal, iso

router = APIRouter(tags=["Health"])


def _kv_set(key: str, value: dict) -> None:
    with SessionLocal() as db:
        row = db.get(KV, key)
        if row:
            row.value = value
        else:
            db.add(KV(key=key, value=value))
        db.commit()


def _kv(key: str) -> dict:
    with SessionLocal() as db:
        row = db.get(KV, key)
        return dict(row.value) if row else {}


@router.get("/api/health")
def health():
    """Unauthenticated liveness probe (Docker HEALTHCHECK). Reveals nothing sensitive."""
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        q = queue_depth()
        ok = True
    except Exception:  # noqa: BLE001
        q, ok = {}, False
    return {"status": "ok" if ok and not q.get("failed") else "degraded", "version": __version__,
            "queue": {"pending": q.get("pending", 0), "failed": q.get("failed", 0)}}


def _light(ok: bool | None, warn: bool = False) -> str:
    return "unknown" if ok is None else ("red" if not ok else "amber" if warn else "green")


@router.get("/api/health/details")
def details(_=Depends(viewer)):
    s = runtime.current()
    q = queue_depth()
    hb = Stats.heartbeat
    worker_ok = hb is not None and utcnow() - aware(hb) < timedelta(seconds=30)
    comps = [{"id": "database", "name": "Database", "light": "green", "detail": "SQLite (WAL)"},
             {"id": "worker", "name": "Triage worker", "light": _light(worker_ok if hb else None),
              "detail": f"last heartbeat {iso(hb) or 'never'}"},
             {"id": "queue", "name": "Queue", "light": _light(not q["failed"], q["pending"] > 100),
              "detail": f"{q['pending']} waiting, {q['failed']} failed"}]
    wz = _kv("health.wazuh")
    comps.append({"id": "wazuh", "name": "Wazuh", "light": _light(wz.get("ok")) if wazuh.configured(s) else "unknown",
                  "detail": wz.get("message") or ("not configured: alerts arrive by push only"
                                                 if not wazuh.configured(s) else "not tested yet")})
    st = llm.status(s)
    for p in st["providers"]:
        light = {"ok": "green", "throttled": "amber", "half-open": "amber", "failing": "red", "open": "red",
                 "disabled": "unknown"}.get(p["state"], "unknown")
        comps.append({"id": f"llm:{p['name']}", "name": f"Model: {p['name']}", "light": light,
                      "detail": f"{p['state']}, circuit {p['circuit']}" + (f", retry in {p['retry_in_s']}s"
                                                                          if p["retry_in_s"] else ""),
                      "error": p["last_error"]})
    since = utcnow() - timedelta(hours=24)
    with SessionLocal() as db:
        for n in dispatch.build_notifiers(s):
            last = db.scalars(select(Notification).where(Notification.channel == n.name, Notification.at >= since)
                              .order_by(Notification.id.desc()).limit(1)).first()
            comps.append({"id": f"notify:{n.name}", "name": n.name.capitalize(),
                          "light": _light(None if last is None else last.ok) if n.name != "console" else "green",
                          "detail": "no messages in 24 h" if last is None else
                          (f"last message {iso(last.at)}" if last.ok else f"failed: {last.error}")})
        partial = db.scalar(select(func.count(Incident.id)).where(Incident.partial_context.is_(True),
                                                                  Incident.last_seen >= since)) or 0
    from ..plugins.enrichers import abuseipdb
    if plugins.is_enabled(s, "abuseipdb") and abuseipdb.configured(s):
        used = abuseipdb.usage_today()
        comps.append({"id": "intel:abuseipdb", "name": "AbuseIPDB", "light": _light(
            used < s.intel.abuseipdb_daily_limit, used > 0.8 * s.intel.abuseipdb_daily_limit),
            "detail": f"{used} of {s.intel.abuseipdb_daily_limit} lookups today; {partial} incident(s) with partial "
                      "context in 24 h"})
    overall = "red" if any(c["light"] == "red" for c in comps) else \
        "amber" if any(c["light"] == "amber" for c in comps) else "green"
    return {"overall": overall, "version": __version__, "components": comps, "queue": q, "llm": st,
            "shadow_mode": s.shadow_mode, "active_response": s.allow_active_response,
            "metrics": {"alerts": Stats.alerts, "suppressed": Stats.suppressed, "duplicates": Stats.duplicates,
                        "notifications": Stats.notifications}}


@router.post("/api/health/test/wazuh")
async def test_wazuh(user=Depends(admin)):
    s = runtime.current()
    if not wazuh.configured(s):
        res = {"manager": {"ok": False, "code": "SIEVE-WZ-424", "message": "Not configured.",
                           "fix": "Enter the Wazuh manager URL first."}}
    else:
        res = await wazuh.test_connection(s)
    ok = all(v.get("ok") for k, v in res.items() if (k == "manager" and s.wazuh.api_url) or
             (k == "indexer" and s.wazuh.indexer_url)) if wazuh.configured(s) else False
    _kv_set("health.wazuh", {"ok": ok, "message": "connected" if ok else "test failed", "at": iso(utcnow())})
    audit(user.username, "test.wazuh", ok=ok)
    return {"ok": ok, "checks": res}


@router.post("/api/health/test/llm/{name}")
async def test_llm(name: str, user=Depends(admin)):
    p = next((p for p in runtime.current().llm.providers if p.name == name), None)
    if p is None:
        raise SieveError(NOT_FOUND, f"No provider called {name}.", status=404)
    res = await llm.test_provider(p)
    audit(user.username, "test.llm", name, ok=res.get("ok"))
    return res


@router.post("/api/health/test/notify/{channel}")
async def test_notify(channel: str, user=Depends(admin)):
    s = runtime.current()
    if channel not in ("telegram", "slack", "discord", "email", "console"):
        raise SieveError(NOT_FOUND, f"No channel called {channel}.", status=404)
    if channel != "console" and not getattr(s.notify, channel).enabled:
        raise SieveError(NOTIFY_NOT_CONFIGURED, f"{channel.capitalize()} is not enabled.", status=424)
    try:
        await dispatch.channel_for(channel, s).send_text("Sieve test message: this channel works.")
        res = {"ok": True, "message": "Test message sent."}
    except SieveError as e:
        res = {"ok": False, **e.to_dict()}
    except Exception as e:  # noqa: BLE001
        res = {"ok": False, "code": "SIEVE-NTF-502", "message": type(e).__name__, "fix": ""}
    audit(user.username, "test.notify", channel, ok=res["ok"])
    return res


@router.get("/api/setup/progress")
def progress(_=Depends(admin)):
    return _kv("setup.progress") or {"steps": {}}


class Step(BaseModel):
    step: str
    state: str = "done"   # done | skipped


@router.post("/api/setup/progress")
def set_progress(body: Step, user=Depends(admin)):
    cur = _kv("setup.progress") or {"steps": {}}
    cur.setdefault("steps", {})[body.step[:30]] = {"state": body.state[:10], "at": iso(utcnow())}
    _kv_set("setup.progress", cur)
    audit(user.username, "setup.step", body.step[:30], state=body.state[:10])
    return cur


@router.post("/api/setup/test-alert", status_code=202)
def test_alert(user=Depends(admin)):
    now = utcnow()
    wid = f"sieve-selftest-{int(now.timestamp() * 1000)}"
    enqueue({"id": wid, "timestamp": now.isoformat(), "rule": {
        "id": "100999", "level": 12, "description": "Sieve self-test alert", "groups": ["sieve_selftest"]},
        "agent": {"id": "000", "name": "sieve-selftest"}, "full_log": "Sieve setup wizard test alert"}, "selftest")
    audit(user.username, "setup.test_alert", wid)
    return {"queued": True, "wazuh_id": wid}


@router.get("/api/setup/test-alert/{wid}")
def test_alert_status(wid: str, _=Depends(admin)):
    from ..models import Alert
    with SessionLocal() as db:
        a = db.scalar(select(Alert).where(Alert.wazuh_id == wid[:120]))
        if not a:
            return {"processed": False}
        notes = db.scalars(select(Notification).where(Notification.incident_id == a.incident_id)).all()
        return {"processed": True, "incident_id": a.incident_id,
                "notifications": [{"channel": n.channel, "ok": n.ok, "latency_ms": n.latency_ms, "error": n.error}
                                  for n in notes]}

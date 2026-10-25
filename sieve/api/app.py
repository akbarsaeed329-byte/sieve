"""HTTP API and static web app. Binds to 127.0.0.1 by default (see config)."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import random
import statistics
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from importlib import resources

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select

from .. import __version__
from ..auth import Sessions, audit, create_user, require, users_exist, verify
from ..config import Settings, load_settings
from ..db import SessionLocal, init_db
from ..errors import INGEST_BAD_PAYLOAD, INGEST_BAD_TOKEN, NOT_FOUND, SETUP_DONE, SieveError
from ..models import Alert, Explanation, Incident, QueueItem, Suppression
from ..pipeline import engine, playbooks
from ..worker import Stats, Worker

log = logging.getLogger("sieve.api")
STATIC = resources.files("sieve") / "web" / "static"


class Creds(BaseModel):
    username: str
    password: str


class Note(BaseModel):
    reason: str = ""


def create_app(settings: Settings | None = None, start_worker: bool = True) -> FastAPI:
    s = settings or load_settings()
    init_db(s.db_path)
    worker = Worker(s)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(worker.run()) if start_worker else None
        yield
        worker.stop()
        if task:
            await task

    app = FastAPI(title="Sieve", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    app.state.settings, app.state.sessions, app.state.worker = s, Sessions(s.secret_key), worker

    @app.exception_handler(SieveError)
    async def _sieve_err(_: Request, e: SieveError):
        return JSONResponse(e.to_dict(), status_code=e.status)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                                "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'")
        return resp

    # ---------- ingest ----------
    @app.post("/api/ingest/wazuh", status_code=202)
    async def ingest(request: Request):
        tok = request.headers.get("x-sieve-token", "")
        if not hmac.compare_digest(tok, s.ingest_token):
            raise SieveError(INGEST_BAD_TOKEN, "Ingest token missing or wrong.",
                             "Use the token printed by `sieve token` in the Wazuh integration's api_key.", status=401)
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            raise SieveError(INGEST_BAD_PAYLOAD, "Body is not JSON.", "Send one Wazuh alert JSON object or a list.") from e
        items = body if isinstance(body, list) else [body]
        if not all(isinstance(x, dict) and "rule" in x for x in items):
            raise SieveError(INGEST_BAD_PAYLOAD, "Each alert needs a 'rule' object.", "Send Wazuh alerts.json entries.")
        with SessionLocal() as db:
            db.add_all([QueueItem(payload=x) for x in items])
            db.commit()
        return {"queued": len(items)}

    # ---------- setup and auth ----------
    @app.get("/api/setup/status")
    def setup_status():
        return {"needs_admin": not users_exist(), "version": __version__,
                "llm_providers": [p.name for p in s.llm.providers], "telegram": s.notify.telegram.enabled}

    @app.post("/api/setup/admin")
    def setup_admin(c: Creds, response: Response, request: Request):
        if users_exist():
            raise SieveError(SETUP_DONE, "Setup is already complete.", "Sign in instead.", status=409)
        u = create_user(c.username, c.password, role="admin")
        audit(u.username, "setup.admin_created")
        app.state.sessions.issue(response, u, secure=request.url.scheme == "https")
        return {"ok": True, "username": u.username, "role": u.role}

    @app.post("/api/auth/login")
    def login(c: Creds, response: Response, request: Request):
        try:
            u = verify(c.username, c.password)
        except HTTPException:
            audit(c.username[:80], "auth.login_failed", ip=request.client.host if request.client else "")
            raise
        audit(u.username, "auth.login")
        app.state.sessions.issue(response, u, secure=request.url.scheme == "https")
        return {"ok": True, "username": u.username, "role": u.role}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie("sieve_session", path="/")
        response.delete_cookie("sieve_csrf", path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(sess=require("viewer")):
        return {"username": sess["u"], "role": sess["r"]}

    # ---------- incidents ----------
    def inc_summary(i: Incident) -> dict:
        return {"id": i.id, "title": i.title, "band": i.band, "score": i.score, "status": i.status,
                "agent_name": i.agent_name, "srcip": i.srcip, "user": i.user, "alert_count": i.alert_count,
                "tripwire": i.tripwire, "opened_at": i.opened_at.isoformat(), "last_seen": i.last_seen.isoformat(),
                "assignee": i.assignee}

    @app.get("/api/incidents")
    def list_incidents(status: str | None = None, sess=require("viewer")):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        with SessionLocal() as db:
            q = select(Incident)
            if status:
                q = q.where(Incident.status == status)
            rows = db.scalars(q).all()
        rows.sort(key=lambda i: (i.status == "resolved" or i.status == "false_positive",
                                 order.get(i.band, 9), -i.last_seen.timestamp()))
        return [inc_summary(i) for i in rows]

    @app.get("/api/incidents/{inc_id}")
    def get_incident(inc_id: int, sess=require("viewer")):
        with SessionLocal() as db:
            i = db.get(Incident, inc_id)
            if not i:
                raise SieveError(NOT_FOUND, f"Incident {inc_id} not found.", "Go back to the queue.", status=404)
            pb = playbooks.load().get(i.playbook or "PB-GENERIC")
            ex = db.scalars(select(Explanation).where(Explanation.incident_id == inc_id)
                            .order_by(Explanation.created_at.desc())).first()
            return {**inc_summary(i), "breakdown": i.breakdown, "overrides": i.overrides, "tactics": i.tactics,
                    "techniques": i.techniques, "tripwire_hits": i.tripwire_hits, "facts": engine.facts(i),
                    "playbook": pb,
                    "explanation": ({"provider": ex.provider, "model": ex.model, "summary": ex.summary,
                                     "validation": ex.validation, "latency_ms": ex.latency_ms} if ex else None),
                    "alerts": [{"id": a.id, "rule_id": a.rule_id, "level": a.level, "description": a.description,
                                "timestamp": a.timestamp.isoformat(), "srcip": a.srcip, "user": a.user,
                                "untrusted": a.untrusted, "full_log": a.full_log, "mitre_ids": a.mitre_ids}
                               for a in i.alerts[-200:]],
                    "wazuh_query": f'agent.name:"{i.agent_name}"' + (f' AND data.srcip:"{i.srcip}"' if i.srcip else "")}

    def transition(inc_id: int, status: str, who: str, reason: str = ""):
        with SessionLocal() as db:
            i = db.get(Incident, inc_id)
            if not i:
                raise SieveError(NOT_FOUND, f"Incident {inc_id} not found.", "Reload the queue.", status=404)
            now = datetime.now(UTC)
            i.status = status
            if status == "acknowledged":
                i.acknowledged_at, i.assignee = now, who
            if status in ("resolved", "false_positive"):
                i.resolved_at = now
            db.commit()
        audit(who, f"incident.{status}", f"INC-{inc_id}", reason=reason)
        return {"ok": True, "status": status}

    @app.post("/api/incidents/{inc_id}/acknowledge")
    def ack(inc_id: int, sess=require("analyst")):
        return transition(inc_id, "acknowledged", sess["u"])

    @app.post("/api/incidents/{inc_id}/resolve")
    def resolve(inc_id: int, n: Note, sess=require("analyst")):
        return transition(inc_id, "resolved", sess["u"], n.reason)

    @app.post("/api/incidents/{inc_id}/false-positive")
    def false_positive(inc_id: int, n: Note, sess=require("analyst")):
        return transition(inc_id, "false_positive", sess["u"], n.reason)

    @app.post("/api/incidents/{inc_id}/explain")
    async def explain(inc_id: int, sess=require("analyst")):
        res = await worker.explain(inc_id)
        return {"ok": res is not None, "explanation": res,
                "message": None if res else "No AI provider answered. Rule-based facts are still shown."}

    # ---------- suppression audit ----------
    @app.get("/api/suppressions")
    def suppressions(sess=require("viewer")):
        with SessionLocal() as db:
            total = db.scalar(select(func.count(Suppression.id))) or 0
            by_reason = db.execute(select(Suppression.reason, func.count()).group_by(Suppression.reason)).all()
            sample = db.scalars(select(Suppression).where(Suppression.sampled.is_(True))).all()
            if not sample:
                ids = [x for (x,) in db.execute(select(Suppression.id)).all()]
                for sid in random.sample(ids, min(20, len(ids))):
                    db.get(Suppression, sid).sampled = True
                db.commit()
                sample = db.scalars(select(Suppression).where(Suppression.sampled.is_(True))).all()
            return {"total": total, "by_reason": [{"reason": r, "count": c} for r, c in by_reason],
                    "sample": [{"id": x.id, "rule_id": x.rule_id, "description": x.description, "reason": x.reason,
                                "outcome": x.review_outcome} for x in sample]}

    @app.post("/api/suppressions/{sid}/{outcome}")
    def review(sid: int, outcome: str, sess=require("analyst")):
        if outcome not in ("noise", "restored"):
            raise SieveError(INGEST_BAD_PAYLOAD, "Outcome must be 'noise' or 'restored'.", "")
        with SessionLocal() as db:
            x = db.get(Suppression, sid)
            if not x:
                raise SieveError(NOT_FOUND, "Suppressed alert not found.", "", status=404)
            x.review_outcome = outcome
            db.commit()
        audit(sess["u"], f"suppression.{outcome}", str(sid))
        return {"ok": True}

    # ---------- health and metrics ----------
    @app.get("/api/health")
    def health():
        with SessionLocal() as db:
            pending = db.scalar(select(func.count(QueueItem.id)).where(QueueItem.status == "pending")) or 0
            failed = db.scalar(select(func.count(QueueItem.id)).where(QueueItem.status == "failed")) or 0
        return {"status": "ok" if failed == 0 else "degraded", "version": __version__,
                "queue": {"pending": pending, "failed": failed},
                "last_alert_at": Stats.last_alert_at.isoformat() if Stats.last_alert_at else None,
                "llm": worker.chain.status(),
                "notifiers": [n.name for n in worker.notifiers]}

    @app.get("/api/stats")
    def stats(sess=require("viewer")):
        with SessionLocal() as db:
            alerts = db.scalar(select(func.count(Alert.id))) or 0
            supp = db.scalar(select(func.count(Suppression.id))) or 0
            open_n = db.scalar(select(func.count(Incident.id)).where(Incident.status.in_(("new", "acknowledged")))) or 0
            need = db.scalars(select(Incident).where(Incident.status == "new",
                                                     Incident.band.in_(("critical", "high")))).all()
            trip = db.scalar(select(func.count(Incident.id)).where(Incident.tripwire.is_(True),
                                                                   Incident.status == "new")) or 0
            acked = db.scalars(select(Incident).where(Incident.acknowledged_at.is_not(None))).all()
        tta = [(i.acknowledged_at - i.opened_at).total_seconds() / 60 for i in acked]
        return {"alerts_received": alerts + supp, "alerts_kept": alerts, "suppressed": supp,
                "notifications": Stats.notifications, "open_incidents": open_n,
                "needs_action": len(need), "tripwire_open": trip,
                "median_tta_min": round(statistics.median(tta), 1) if tta else None}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        p = sorted(Stats.first_notify_ms)
        p95 = p[int(len(p) * 0.95) - 1] if p else 0
        lines = [
            f"sieve_alerts_processed_total {Stats.alerts}",
            f"sieve_alerts_suppressed_total {Stats.suppressed}",
            f"sieve_alerts_duplicate_total {Stats.duplicates}",
            f"sieve_notifications_total {Stats.notifications}",
            f"sieve_notification_failures_total {Stats.notify_failures}",
            f"sieve_llm_calls_total {Stats.llm_calls}",
            f"sieve_llm_failures_total {Stats.llm_failures}",
            f"sieve_first_notify_p95_ms {p95}",
        ]
        return "\n".join(lines) + "\n"

    # ---------- web app ----------
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(STATIC / "index.html"))

    return app

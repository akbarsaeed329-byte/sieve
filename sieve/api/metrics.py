"""Prometheus-compatible metrics (no auth; bind to localhost or protect at the proxy)."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from ..db import SessionLocal
from ..models import Incident, LlmCall, Notification, Suppression
from ..worker import Stats, queue_depth

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    with SessionLocal() as db:
        inc = db.scalar(select(func.count(Incident.id))) or 0
        open_ = db.scalar(select(func.count(Incident.id)).where(Incident.status.in_(("new", "acknowledged")))) or 0
        supp = db.scalar(select(func.count(Suppression.id))) or 0
        n_ok = db.scalar(select(func.count(Notification.id)).where(Notification.ok.is_(True))) or 0
        n_fail = db.scalar(select(func.count(Notification.id)).where(Notification.ok.is_(False))) or 0
        llm_ok = db.scalar(select(func.count(LlmCall.id)).where(LlmCall.ok.is_(True))) or 0
        llm_fail = db.scalar(select(func.count(LlmCall.id)).where(LlmCall.ok.is_(False))) or 0
        tokens = db.scalar(select(func.coalesce(func.sum(LlmCall.tokens), 0))) or 0
    q = queue_depth()
    p = sorted(Stats.first_notify_ms)
    p95 = p[max(0, int(len(p) * 0.95) - 1)] if p else 0
    m = [("sieve_incidents_total", "counter", inc), ("sieve_incidents_open", "gauge", open_),
         ("sieve_alerts_suppressed_total", "counter", supp), ("sieve_queue_pending", "gauge", q["pending"]),
         ("sieve_queue_failed", "gauge", q["failed"]), ("sieve_notifications_total", "counter", n_ok),
         ("sieve_notification_failures_total", "counter", n_fail), ("sieve_llm_calls_total", "counter", llm_ok),
         ("sieve_llm_failures_total", "counter", llm_fail), ("sieve_llm_tokens_total", "counter", tokens),
         ("sieve_alerts_processed_total", "counter", Stats.alerts), ("sieve_first_notify_p95_ms", "gauge", p95)]
    lines = []
    for name, kind, v in m:
        lines += [f"# TYPE {name} {kind}", f"{name} {v}"]
    return "\n".join(lines) + "\n"

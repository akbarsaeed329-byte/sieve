"""Simple Prometheus-compatible plain-text metrics endpoint."""
from fastapi import APIRouter
from sqlalchemy import func
from ..db import SessionLocal
from ..models import Incident, QueueItem, Suppression

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", response_class=__import__("fastapi").responses.PlainTextResponse)
def prometheus_metrics():
    with SessionLocal() as db:
        total_inc = db.query(func.count(Incident.id)).scalar() or 0
        open_inc = db.query(func.count(Incident.id)).filter(
            Incident.status.in_(["new", "acknowledged"])).scalar() or 0
        suppressed = db.query(func.count(Suppression.id)).scalar() or 0
        queue_pending = db.query(func.count(QueueItem.id)).filter(
            QueueItem.status == "pending").scalar() or 0
    lines = [
        "# HELP sieve_incidents_total Total incidents created",
        "# TYPE sieve_incidents_total counter",
        f"sieve_incidents_total {total_inc}",
        "# HELP sieve_incidents_open Currently open incidents",
        "# TYPE sieve_incidents_open gauge",
        f"sieve_incidents_open {open_inc}",
        "# HELP sieve_alerts_suppressed_total Total suppressed alerts",
        "# TYPE sieve_alerts_suppressed_total counter",
        f"sieve_alerts_suppressed_total {suppressed}",
        "# HELP sieve_queue_pending Alerts waiting to be processed",
        "# TYPE sieve_queue_pending gauge",
        f"sieve_queue_pending {queue_pending}",
    ]
    return "\n".join(lines) + "\n"

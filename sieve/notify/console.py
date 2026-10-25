"""Console notifier — always enabled; provides a guaranteed fallback."""
from __future__ import annotations
import json
from datetime import timezone
from ..models import Incident
from .base import Notifier

BANDS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


class ConsoleNotifier(Notifier):
    name = "console"

    async def send(self, incident: Incident, public_url: str) -> dict:
        icon = BANDS.get(incident.band, "⚪")
        tripwire = " 🪤 TRIPWIRE" if incident.tripwire else ""
        ts = incident.opened_at.replace(tzinfo=timezone.utc).strftime("%H:%M:%S UTC")
        msg = (
            f"\n{'='*72}\n"
            f"SIEVE ALERT {icon} [{incident.band.upper()}] {ts}{tripwire}\n"
            f"INC-{incident.id:04d} · {incident.title}\n"
            f"Host: {incident.agent_name or '?'}  Source: {incident.srcip or '?'}"
            f"  User: {incident.user or '?'}  Alerts: {incident.alert_count}\n"
            f"Score: {incident.score:.0f}  "
            f"Tactics: {', '.join(incident.tactics or []) or '—'}\n"
            f"Open: {public_url}/incidents/{incident.id}\n"
            f"{'='*72}"
        )
        print(msg, flush=True)
        return {"type": "console", "printed": True}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        summary_text = " ".join(s["text"] for s in (explanation.get("summary") or []))
        print(
            f"  [AI summary for INC-{incident.id:04d}]: {summary_text or '(none)'}",
            flush=True,
        )

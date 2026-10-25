"""PagerDuty Events API v2: trigger on notify, resolve when the incident is resolved in Sieve (dedup_key = INC id)."""
from __future__ import annotations

from .. import http, secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from ..pipeline.score import band_rank
from .base import Notifier
from .render import model

URL = "https://events.pagerduty.com/v2/enqueue"
SEV = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


class PagerDutyNotifier(Notifier):
    name = "pagerduty"

    def __init__(self, settings: Settings):
        self.cfg = settings.pagerduty
        self._key = secrets_store.resolve(self.cfg.routing_key_env)

    async def _event(self, body: dict) -> None:
        if not self._key:
            raise SieveError(NOTIFY_FAILED, "The PagerDuty routing key is missing.", status=424)
        async with http.client(timeout=15) as c:
            r = await c.post(URL, json={"routing_key": self._key, **body})
        if r.status_code not in (200, 202):
            raise SieveError(NOTIFY_FAILED, f"PagerDuty returned HTTP {r.status_code}.", status=502)

    async def send(self, incident: Incident, public_url: str) -> dict:
        if band_rank(incident.band) < band_rank(self.cfg.min_band):
            return {"type": "pagerduty", "ok": True, "skipped": "below min_band"}
        m = model(incident, public_url)
        await self._event({"event_action": "trigger", "dedup_key": m["ref"], "payload": {
            "summary": f"{m['band_label']} {m['ref']}: {m['title']} on {m['host']}"[:1000], "source": m["host"],
            "severity": SEV[incident.band], "custom_details": {"srcip": m["srcip"], "user": m["user"], "alerts": m["alerts"],
                                                               "tripwire": m["tripwire"]}},
            "links": [{"href": m["url"], "text": "Open in Sieve"}]})
        return {"type": "pagerduty", "ok": True, "dedup_key": m["ref"]}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        return None   # PagerDuty incidents are not edited; the link carries the summary

    async def resolve(self, incident: Incident) -> None:
        await self._event({"event_action": "resolve", "dedup_key": f"INC-{incident.id:04d}"})

    async def send_text(self, text: str) -> dict:
        return {"type": "pagerduty", "ok": True, "skipped": "PagerDuty is for incidents only"}

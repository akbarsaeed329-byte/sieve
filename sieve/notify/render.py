"""One message model for every channel, so each notifier shows the same facts and the same
dashed-amber "untrusted field" box. All values here are validated entities or capped excerpts;
each channel escapes them for its own markup."""
from __future__ import annotations

from ..models import Incident

BAND_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
BAND_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
AMBER = 0xB7791F


def model(incident: Incident, public_url: str, explanation: dict | None = None) -> dict:
    hit = (incident.tripwire_hits or [None])[0] if incident.tripwire else None
    summary = [s["text"] for s in (explanation or {}).get("summary", [])][:4]
    first_step = None
    steps = (explanation or {}).get("playbook_steps") or []
    if steps:
        from ..pipeline import playbooks
        pb = playbooks.render(incident.playbook, incident.user, incident.srcip, incident.agent_name) or {}
        first_step = next((s["title"] for s in pb.get("steps", []) if s["id"] == steps[0]), None)
    return {
        "band": incident.band, "band_label": BAND_LABEL.get(incident.band, incident.band),
        "icon": BAND_ICON.get(incident.band, "⚪"), "ref": f"INC-{incident.id:04d}",
        "title": incident.title, "host": incident.agent_name or "?", "srcip": incident.srcip,
        "user": incident.user, "alerts": incident.alert_count, "score": round(incident.score or 0),
        "url": f"{public_url.rstrip('/')}/incidents/{incident.id}",
        "tripwire": bool(incident.tripwire),
        "untrusted_field": hit["field"] if hit else None,
        "untrusted_excerpt": (hit["excerpt"][:160] if hit else None),
        "summary": summary, "first_step": first_step,
        "ai": explanation is not None,
    }

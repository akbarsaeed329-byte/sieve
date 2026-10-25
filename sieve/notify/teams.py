"""Microsoft Teams notifier (incoming webhook / Workflows URL) with an Adaptive Card.
Teams webhooks cannot edit a posted message, so the checked AI summary arrives as a follow-up card."""

from __future__ import annotations

from .. import http, secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from .base import Notifier
from .render import model

STYLE = {"critical": "attention", "high": "warning", "medium": "accent", "low": "default"}


def card(m: dict) -> dict:
    body = [
        {
            "type": "TextBlock",
            "size": "Medium",
            "weight": "Bolder",
            "wrap": True,
            "text": f"{m['band_label']} · {m['ref']} · {m['title']}",
            "color": STYLE.get(m["band"], "default"),
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Host", "value": m["host"]},
                {"title": "Source", "value": m["srcip"] or "-"},
                {"title": "User", "value": m["user"] or "-"},
                {"title": "Alerts", "value": str(m["alerts"])},
            ],
        },
    ]
    if m["ai"] and m["summary"]:
        body += [
            {"type": "TextBlock", "isSubtle": True, "text": "AI summary, checked against evidence", "wrap": True},
            {"type": "TextBlock", "text": " ".join(m["summary"]), "wrap": True},
        ]
    if m["tripwire"]:
        body.append(
            {
                "type": "Container",
                "style": "warning",
                "items": [
                    {
                        "type": "TextBlock",
                        "weight": "Bolder",
                        "wrap": True,
                        "text": f"Tripwire: untrusted field {m['untrusted_field']} tried to instruct the AI. Treated as data.",
                    },
                    {"type": "TextBlock", "fontType": "Monospace", "wrap": True, "text": m["untrusted_excerpt"] or ""},
                ],
            }
        )
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": [{"type": "Action.OpenUrl", "title": "Open in Sieve", "url": m["url"]}],
                },
            }
        ],
    }


class TeamsNotifier(Notifier):
    name = "teams"

    def __init__(self, settings: Settings):
        self._url = secrets_store.resolve(settings.teams.webhook_env)

    async def _post(self, body: dict) -> None:
        if not self._url:
            raise SieveError(NOTIFY_FAILED, "The Teams webhook URL is missing.", status=424)
        async with http.client(timeout=15) as c:
            r = await c.post(self._url, json=body)
        if r.status_code not in (200, 202):
            raise SieveError(NOTIFY_FAILED, f"Teams webhook failed with HTTP {r.status_code}.", status=502)

    async def send(self, incident: Incident, public_url: str) -> dict:
        await self._post(card(model(incident, public_url)))
        return {"type": "teams", "ok": True}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        m = model(incident, public_url, explanation)
        if m["summary"]:
            await self._post(card(m))

    async def send_text(self, text: str) -> dict:
        await self._post(
            {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "version": "1.4",
                            "body": [{"type": "TextBlock", "text": text, "wrap": True}],
                        },
                    }
                ],
            }
        )
        return {"type": "teams", "ok": True}

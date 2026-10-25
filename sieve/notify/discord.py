"""Discord notifier via webhook: POST ?wait=true returns the message id; PATCH edits it.
Mentions are disabled (allowed_mentions.parse = []) so a log field can never ping @everyone.
The untrusted field is a separate amber embed."""
from __future__ import annotations

import re

from .. import http, secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from .base import Notifier
from .render import AMBER, model

COLORS = {"critical": 0x8F1C13, "high": 0x8A3D08, "medium": 0x6B5200, "low": 0x1F4677}


def esc(text: object) -> str:
    return re.sub(r"([\\*_~`|>#\[\]()@-])", r"\\\1", str(text))


def _code(text: object) -> str:
    return str(text).replace("`", "ˋ")


def payload(m: dict) -> dict:
    desc = [f"{m['alerts']} alerts grouped. User `{_code(m['user'] or '-')}`, source `{_code(m['srcip'] or '-')}`."]
    if m["ai"] and m["summary"]:
        desc += ["", "*AI summary, checked against evidence*", esc(" ".join(m["summary"]))]
        if m["first_step"]:
            desc.append(f"**First step:** {esc(m['first_step'])}")
    embeds = [{"title": f"{m['band_label']} · {m['ref']} · {m['title']}"[:250], "url": m["url"],
               "description": "\n".join(desc)[:3900], "color": COLORS.get(m["band"], 0x56625F)}]
    if m["tripwire"]:
        embeds.append({"title": "Tripwire: untrusted field tried to instruct the AI", "color": AMBER,
                       "description": f"Treated as data; severity comes from rules.\n**Untrusted: "
                                      f"{esc(m['untrusted_field'])}**\n```{_code(m['untrusted_excerpt'])}```"})
    return {"embeds": embeds, "allowed_mentions": {"parse": []}}


class DiscordNotifier(Notifier):
    name = "discord"

    def __init__(self, settings: Settings):
        self._url = secrets_store.resolve(settings.notify.discord.webhook_env)

    async def _req(self, method: str, url: str, body: dict) -> dict:
        if not self._url:
            raise SieveError(NOTIFY_FAILED, "The Discord webhook URL is missing.", status=424)
        async with http.client(timeout=15) as c:
            r = await c.request(method, url, json=body)
        if r.status_code not in (200, 204):
            raise SieveError(NOTIFY_FAILED, f"Discord webhook failed with HTTP {r.status_code}.", status=502)
        return r.json() if r.status_code == 200 else {}

    async def send(self, incident: Incident, public_url: str) -> dict:
        j = await self._req("POST", f"{self._url}?wait=true", payload(model(incident, public_url)))
        return {"type": "discord", "ok": True, "message_id": j.get("id")}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        mid = (ref or {}).get("message_id")
        if not mid:
            return
        await self._req("PATCH", f"{self._url}/messages/{mid}", payload(model(incident, public_url, explanation)))

    async def send_text(self, text: str) -> dict:
        await self._req("POST", self._url, {"content": esc(text)[:1900], "allowed_mentions": {"parse": []}})
        return {"type": "discord", "ok": True}

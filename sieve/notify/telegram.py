"""Telegram notifier: send a plain message instantly, then edit it with the AI summary."""
from __future__ import annotations

import logging

from .. import http, secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from .base import Notifier
from .render import model

log = logging.getLogger("sieve.notify.telegram")
API = "https://api.telegram.org/bot{token}/{method}"


def _escape(text: object) -> str:
    text = str(text)
    for ch in r"\_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


def _code(text: object) -> str:
    return str(text).replace("\\", "\\\\").replace("`", "\\`")


def _text(m: dict) -> str:
    e = _escape
    out = [f"{m['icon']} *{e(m['band_label'])}* · {e(m['ref'])}", f"*{e(m['title'])} on {e(m['host'])}*",
           f"{m['alerts']} alerts grouped\\. User `{_code(m['user'] or '-')}`, source `{_code(m['srcip'] or '-')}`\\."]
    if m["ai"]:
        if m["summary"]:
            out += ["", "_AI summary, checked against evidence_", e(" ".join(m["summary"]))]
        if m["first_step"]:
            out.append(f"*First step:* {e(m['first_step'])}")
    if m["tripwire"]:
        out += ["", f"⚠️ Tripwire: the {e(m['untrusted_field'])} field tried to instruct the AI\\. Treated as data\\.",
                f"Untrusted `{_code(m['untrusted_field'])}`: `{_code(m['untrusted_excerpt'])}`"]
    out += ["", f"[Open in Sieve]({m['url'].replace(')', '%29')})"]
    return "\n".join(out)


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(self, settings: Settings):
        cfg = settings.notify.telegram
        self._token = secrets_store.resolve(cfg.token_env)
        self._chat = cfg.chat_id

    async def _post(self, method: str, body: dict) -> dict:
        if not (self._token and self._chat):
            raise SieveError(NOTIFY_FAILED, "Telegram bot token or chat ID is missing.", status=424)
        async with http.client(timeout=15) as c:
            r = await c.post(API.format(token=self._token, method=method),
                             json={"chat_id": self._chat, "parse_mode": "MarkdownV2",
                                   "disable_web_page_preview": True, **body})
        if r.status_code != 200:
            raise SieveError(NOTIFY_FAILED, f"Telegram {method} failed with HTTP {r.status_code}.", status=502)
        return r.json()

    def _markup(self, incident: Incident, public_url: str) -> dict:
        from .. import runtime
        if not runtime.current().chatops.telegram_buttons:
            return {}
        from ..chatops import telegram_markup
        return {"reply_markup": telegram_markup(incident.id, f"{public_url.rstrip('/')}/incidents/{incident.id}")}

    async def send(self, incident: Incident, public_url: str) -> dict:
        data = await self._post("sendMessage", {"text": _text(model(incident, public_url)), **self._markup(incident, public_url)})
        return {"type": "telegram", "ok": True, "message_id": data["result"]["message_id"]}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        if not (ref or {}).get("message_id"):
            return
        await self._post("editMessageText", {"message_id": ref["message_id"],
                                             "text": _text(model(incident, public_url, explanation)),
                                             **self._markup(incident, public_url)})

    async def send_text(self, text: str) -> dict:
        data = await self._post("sendMessage", {"text": _escape(text)})
        return {"type": "telegram", "ok": True, "message_id": data["result"]["message_id"]}

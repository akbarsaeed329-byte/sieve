"""Telegram notifier: send a plain message instantly, then edit it with the AI summary."""
from __future__ import annotations
import logging
import os
import httpx
from ..config import Settings
from ..models import Incident
from .base import Notifier

log = logging.getLogger("sieve.notify.telegram")
API = "https://api.telegram.org/bot{token}/{method}"
BANDS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def _escape(text: str) -> str:
    for ch in r"\_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


def _base_text(incident: Incident, public_url: str) -> str:
    icon = BANDS.get(incident.band, "⚪")
    tripwire = " 🪤 *TRIPWIRE*" if incident.tripwire else ""
    e = _escape
    return (
        f"{icon} *\\[{e(incident.band.upper())}\\] INC\\-{incident.id:04d}*{tripwire}\n"
        f"*{e(incident.title)}*\n\n"
        f"Host: `{e(incident.agent_name or '?')}` · "
        f"Source: `{e(incident.srcip or '?')}` · "
        f"User: `{e(incident.user or '?')}`\n"
        f"Alerts grouped: {incident.alert_count} · Score: {incident.score:.0f}\n"
        f"[Open in Sieve]({public_url}/incidents/{incident.id})"
    )


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(self, settings: Settings):
        cfg = settings.notify.telegram
        self._token = os.environ.get(cfg.token_env, "")
        self._chat = cfg.chat_id

    def _url(self, method: str) -> str:
        return API.format(token=self._token, method=method)

    async def send(self, incident: Incident, public_url: str) -> dict:
        text = _base_text(incident, public_url)
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(self._url("sendMessage"), json={
                "chat_id": self._chat,
                "text": text,
                "parse_mode": "MarkdownV2",
                "disable_web_page_preview": True,
            })
        if not r.is_success:
            log.error("Telegram sendMessage failed %s: %s", r.status_code, r.text[:200])
            return {"type": "telegram", "ok": False, "error": r.text[:200]}
        data = r.json()
        return {"type": "telegram", "ok": True, "message_id": data["result"]["message_id"]}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        msg_id = (ref or {}).get("message_id")
        if not msg_id:
            return
        summary_lines = "\n".join(
            f"• {_escape(s['text'])}" for s in (explanation.get("summary") or [])[:5]
        )
        hyps = explanation.get("hypotheses") or []
        hyp_text = ""
        if hyps:
            best = next((h for h in hyps if h["status"] == "supported"), None)
            if best:
                hyp_text = f"\n\nLikely: {_escape(best['name'])}"
        tripwire = " 🪤 *TRIPWIRE*" if incident.tripwire else ""
        e = _escape
        text = (
            f"{BANDS.get(incident.band,'⚪')} *\\[{e(incident.band.upper())}\\] INC\\-{incident.id:04d}*{tripwire}\n"
            f"*{e(incident.title)}*\n\n"
            f"{summary_lines or '_AI summary not available_'}{hyp_text}\n\n"
            f"[Open in Sieve]({public_url}/incidents/{incident.id})"
        )
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(self._url("editMessageText"), json={
                "chat_id": self._chat,
                "message_id": msg_id,
                "text": text,
                "parse_mode": "MarkdownV2",
                "disable_web_page_preview": True,
            })
        if not r.is_success:
            log.warning("Telegram editMessageText failed: %s", r.text[:200])

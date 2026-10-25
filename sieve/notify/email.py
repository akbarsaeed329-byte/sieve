"""Email notifier (SMTP with STARTTLS or SMTPS). Send-only: AI summaries arrive as a follow-up email."""
from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from .. import secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from .base import Notifier
from .render import model


def _body(m: dict) -> str:
    lines = [f"{m['band_label']} · {m['ref']} · {m['title']} on {m['host']}", "",
             f"{m['alerts']} alerts grouped. User: {m['user'] or '-'}. Source: {m['srcip'] or '-'}. Score: {m['score']}."]
    if m["ai"] and m["summary"]:
        lines += ["", "AI summary, checked against evidence:", *[f"- {s}" for s in m["summary"]]]
        if m["first_step"]:
            lines.append(f"First step: {m['first_step']}")
    if m["tripwire"]:
        lines += ["", f"TRIPWIRE: the {m['untrusted_field']} field tried to instruct the AI. It was treated as data.",
                  f"Untrusted {m['untrusted_field']}: {m['untrusted_excerpt']}"]
    lines += ["", f"Open in Sieve: {m['url']}"]
    return "\n".join(lines)


class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, settings: Settings):
        self.c = settings.notify.email
        self._pw = secrets_store.resolve(self.c.password_env)

    def _send_sync(self, subject: str, body: str) -> None:
        if not (self.c.host and self.c.sender and self.c.to):
            raise SieveError(NOTIFY_FAILED, "Email needs an SMTP host, a sender and at least one recipient.", status=424)
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject[:200], self.c.sender, ", ".join(self.c.to)
        msg.set_content(body)
        ctx = ssl.create_default_context()
        try:
            if self.c.port == 465:
                with smtplib.SMTP_SSL(self.c.host, self.c.port, context=ctx, timeout=15) as s:
                    if self.c.username:
                        s.login(self.c.username, self._pw)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(self.c.host, self.c.port, timeout=15) as s:
                    if self.c.starttls:
                        s.starttls(context=ctx)
                    if self.c.username:
                        s.login(self.c.username, self._pw)
                    s.send_message(msg)
        except (OSError, smtplib.SMTPException) as e:
            raise SieveError(NOTIFY_FAILED, f"SMTP failed ({type(e).__name__}).", status=502) from e

    async def send(self, incident: Incident, public_url: str) -> dict:
        m = model(incident, public_url)
        await asyncio.to_thread(self._send_sync, f"[Sieve {m['band_label']}] {m['ref']} {m['title']}", _body(m))
        return {"type": "email", "ok": True}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        m = model(incident, public_url, explanation)
        if m["summary"]:
            await asyncio.to_thread(self._send_sync, f"[Sieve] AI summary for {m['ref']}", _body(m))

    async def send_text(self, text: str) -> dict:
        await asyncio.to_thread(self._send_sync, "Sieve", text)
        return {"type": "email", "ok": True}

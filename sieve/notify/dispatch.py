"""Dispatch to all enabled notifiers: instant first (phase 1), AI edit second (phase 2).

* ``send_instant`` never waits on the LLM and never raises: each channel is isolated and timed out.
* Every attempt is recorded in ``notifications`` (drives metrics and the "channel failing" banner).
* If every real channel fails, the console notifier is the guaranteed backup and Health turns red.
* Shadow mode records what *would* have been sent and sends nothing.
"""
from __future__ import annotations

import asyncio
import logging

from ..config import Settings
from ..db import SessionLocal
from ..models import Incident, Notification, aware, utcnow
from .console import ConsoleNotifier
from .discord import DiscordNotifier
from .email import EmailNotifier
from .slack import SlackNotifier
from .telegram import TelegramNotifier

log = logging.getLogger("sieve.notify.dispatch")
TIMEOUT = 20


def build_notifiers(settings: Settings) -> list:
    out = []
    if settings.notify.telegram.enabled:
        out.append(TelegramNotifier(settings))
    if settings.notify.slack.enabled:
        out.append(SlackNotifier(settings))
    if settings.notify.discord.enabled:
        out.append(DiscordNotifier(settings))
    if settings.notify.email.enabled:
        out.append(EmailNotifier(settings))
    if settings.notify.console or not out:
        out.append(ConsoleNotifier())
    return out


def _record(**kw) -> None:
    try:
        with SessionLocal() as db:
            db.add(Notification(**kw))
            db.commit()
    except Exception:  # noqa: BLE001
        log.debug("could not record notification", exc_info=True)


async def _one(n, coro):
    try:
        return await asyncio.wait_for(coro, TIMEOUT), None
    except Exception as e:  # noqa: BLE001 - one channel must never stop another
        msg = getattr(e, "message", None) or type(e).__name__
        log.error("notifier failed", extra={"channel": n.name, "error": msg})
        return None, msg


async def send_instant(incident: Incident, settings: Settings, received_at=None) -> dict:
    """Phase 1: plain, rule-based message on every channel. Returns {channel: ref}."""
    latency = int((utcnow() - aware(received_at)).total_seconds() * 1000) if received_at else 0
    if settings.shadow_mode:
        _record(incident_id=incident.id, channel="shadow", phase="send", band=incident.band, ok=True,
                shadow=True, latency_ms=latency)
        return {}
    notifiers = build_notifiers(settings)
    results = await asyncio.gather(*[_one(n, n.send(incident, settings.notify.public_url)) for n in notifiers])
    refs: dict = {}
    for n, (ref, error) in zip(notifiers, results, strict=True):
        _record(incident_id=incident.id, channel=n.name, phase="send", band=incident.band, ok=error is None,
                error=error, latency_ms=latency)
        refs[n.name] = ref if error is None else {"ok": False, "error": error}
    real = [n for n in notifiers if n.name != "console"]
    if real and all(not (refs.get(n.name) or {}).get("ok") for n in real) and "console" not in refs:
        ref, _ = await _one(ConsoleNotifier(), ConsoleNotifier().send(incident, settings.notify.public_url))
        refs["console"] = ref
        _record(incident_id=incident.id, channel="console", phase="send", band=incident.band, ok=True,
                error="backup after all channels failed", latency_ms=latency)
    return refs


async def edit_with_ai(incident: Incident, refs: dict, explanation: dict, settings: Settings) -> None:
    """Phase 2: replace the message with the evidence-checked AI version (after the LLM returns)."""
    if not explanation or not refs or settings.shadow_mode:
        return
    notifiers = [n for n in build_notifiers(settings) if (refs.get(n.name) or {}).get("ok")]
    results = await asyncio.gather(*[_one(n, n.edit(refs[n.name], incident, explanation, settings.notify.public_url))
                                     for n in notifiers])
    for n, (_, error) in zip(notifiers, results, strict=True):
        _record(incident_id=incident.id, channel=n.name, phase="edit", band=incident.band, ok=error is None,
                error=error)


async def send_text(text: str, settings: Settings, phase: str = "digest", only: str | None = None) -> dict:
    out = {}
    for n in build_notifiers(settings):
        if only and n.name != only:
            continue
        ref, error = await _one(n, n.send_text(text))
        _record(channel=n.name, phase=phase, ok=error is None, error=error)
        out[n.name] = {"ok": error is None, "error": error}
    return out


def channel_for(name: str, settings: Settings):
    return {"telegram": TelegramNotifier, "slack": SlackNotifier, "discord": DiscordNotifier, "email": EmailNotifier,
            "console": lambda s: ConsoleNotifier()}[name](settings)

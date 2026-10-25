"""Dispatch to all enabled notifiers: instant first, AI edit second."""
from __future__ import annotations
import asyncio
import logging
from ..config import Settings
from ..models import Incident
from .console import ConsoleNotifier
from .telegram import TelegramNotifier

log = logging.getLogger("sieve.notify.dispatch")
BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _should_notify(incident: Incident, settings: Settings) -> bool:
    min_ord = BAND_ORDER.get(settings.notify.min_band, 1)
    inc_ord = BAND_ORDER.get(incident.band, 3)
    return inc_ord <= min_ord


def _build_notifiers(settings: Settings) -> list:
    notifiers = []
    if settings.notify.console:
        notifiers.append(ConsoleNotifier())
    if settings.notify.telegram.enabled:
        notifiers.append(TelegramNotifier(settings))
    return notifiers


async def send_instant(incident: Incident, settings: Settings) -> dict:
    """Phase 1: send plain alert immediately (< 1 s target)."""
    if not _should_notify(incident, settings):
        return {}
    notifiers = _build_notifiers(settings)
    refs = {}
    for n in notifiers:
        try:
            ref = await n.send(incident, settings.notify.public_url)
            refs[n.name] = ref
        except Exception as e:  # noqa: BLE001
            log.error("Notifier %s send failed: %s", n.name, e)
            refs[n.name] = {"ok": False, "error": str(e)}
    return refs


async def edit_with_ai(
    incident: Incident,
    refs: dict,
    explanation: dict,
    settings: Settings,
) -> None:
    """Phase 2: edit the same message with the AI summary (async, after LLM returns)."""
    if not explanation or not refs:
        return
    notifiers = _build_notifiers(settings)
    await asyncio.gather(*[
        n.edit(refs.get(n.name, {}), incident, explanation, settings.notify.public_url)
        for n in notifiers
    ], return_exceptions=True)

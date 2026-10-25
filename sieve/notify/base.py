from __future__ import annotations

from ..models import Incident


class Notifier:
    """Two-phase contract: ``send`` posts the rule-based message at once and returns a reference;
    ``edit`` later replaces it with the evidence-checked AI version. ``send_text`` is for digests
    and connection tests."""
    name: str = "base"

    async def send(self, incident: Incident, public_url: str) -> dict:
        raise NotImplementedError

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        raise NotImplementedError

    async def send_text(self, text: str) -> dict:
        raise NotImplementedError

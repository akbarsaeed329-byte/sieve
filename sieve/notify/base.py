from __future__ import annotations
from ..models import Incident


class Notifier:
    name: str = "base"
    async def send(self, incident: Incident, public_url: str) -> dict:
        raise NotImplementedError
    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        raise NotImplementedError

from __future__ import annotations

from ..db import SessionLocal
from ..errors import NOT_FOUND, SieveError
from ..models import Incident


def iso(d) -> str | None:
    from ..models import aware
    return aware(d).isoformat() if d else None


def get_incident(db, inc_id: int) -> Incident:
    i = db.get(Incident, inc_id)
    if not i:
        raise SieveError(NOT_FOUND, f"Incident {inc_id} not found.", status=404)
    return i


__all__ = ["SessionLocal", "get_incident", "iso"]

from __future__ import annotations

from ..db import SessionLocal
from ..errors import NOT_FOUND, SieveError
from ..models import Incident


def iso(d) -> str | None:
    from ..models import aware
    return aware(d).isoformat() if d else None


def get_incident(db, inc_id: int, user=None) -> Incident:
    """Tenant users get 404 (not 403) for other tenants' incidents, so existence is not revealed."""
    i = db.get(Incident, inc_id)
    if not i or (user is not None and getattr(user, "tenant_id", None) and i.tenant_id != user.tenant_id):
        raise SieveError(NOT_FOUND, f"Incident {inc_id} not found.", status=404)
    return i


def tenant_of(user) -> int | None:
    return getattr(user, "tenant_id", None) if user is not None else None


def scoped(stmt, column, user, requested: int | None = None):
    """Filter a query by tenant: tenant users see only theirs; provider staff may pick one (?tenant=)."""
    t = tenant_of(user)
    if t:
        return stmt.where(column == t)
    if requested:
        return stmt.where(column == requested)
    return stmt


__all__ = ["SessionLocal", "get_incident", "iso"]

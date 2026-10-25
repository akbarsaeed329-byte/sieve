"""Health endpoint: returns status of each component."""
from __future__ import annotations
import asyncio
import os
import httpx
from fastapi import APIRouter
from ..db import SessionLocal
from ..models import QueueItem

router = APIRouter(tags=["Health"])


async def _check_wazuh(base_url: str, user: str, password: str) -> str:
    if not base_url:
        return "not_configured"
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as c:
            r = await c.get(f"{base_url}/security/user/authenticate",
                            auth=(user, password))
        return "ok" if r.is_success else f"http_{r.status_code}"
    except Exception as e:
        return f"error: {str(e)[:60]}"


async def _check_llm(base_url: str, model: str) -> str:
    if not base_url:
        return "not_configured"
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{base_url.rstrip('/')}/api/tags")
        return "ok" if r.is_success else f"http_{r.status_code}"
    except Exception as e:
        return f"error: {str(e)[:60]}"


@router.get("/api/health")
async def health():
    from ..app import get_settings
    settings = get_settings()
    with SessionLocal() as db:
        queue_pending = db.query(QueueItem).filter(QueueItem.status == "pending").count()
        queue_failed = db.query(QueueItem).filter(QueueItem.status == "failed").count()
    provider = settings.llm.providers[0] if settings.llm.providers else None
    llm_status = "disabled"
    if provider:
        llm_status = await _check_llm(provider.base_url, provider.model)
    return {
        "status": "ok",
        "queue": {"pending": queue_pending, "failed": queue_failed},
        "llm": llm_status,
        "components": {
            "database": "ok",
            "worker": "running",
        },
    }

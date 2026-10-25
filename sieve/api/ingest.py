"""Wazuh integration endpoint and internal ingest helper."""
from __future__ import annotations
import hmac
import logging
from fastapi import APIRouter, Header, HTTPException, Request
from ..db import SessionLocal
from ..models import QueueItem

log = logging.getLogger("sieve.api.ingest")
router = APIRouter()


def _check_token(provided: str | None, expected: str) -> None:
    if not provided or not hmac.compare_digest(provided, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail={"code": "SIEVE-ING-401",
                                                      "message": "Invalid ingest token",
                                                      "fix": "Set the correct token in the Wazuh integration script."})


@router.post("/api/ingest", status_code=202, tags=["Ingest"])
async def ingest_alert(request: Request, authorization: str | None = Header(default=None)):
    """Receive a Wazuh alert (called by the Wazuh custom integration script)."""
    from ..app import get_settings
    settings = get_settings()
    _check_token(authorization, settings.ingest_token)
    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"code": "SIEVE-ING-400",
                                                      "message": f"Invalid JSON: {e}"}) from e
    with SessionLocal() as db:
        db.add(QueueItem(payload=payload))
        db.commit()
    return {"status": "queued"}


def enqueue(payload: dict) -> None:
    """Enqueue an alert without HTTP (used by the demo and tests)."""
    with SessionLocal() as db:
        db.add(QueueItem(payload=payload))
        db.commit()

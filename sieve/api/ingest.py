"""Wazuh integration endpoint. Writes to the durable queue and returns immediately (202)."""
from __future__ import annotations

import hmac
import json

from fastapi import APIRouter, Request

from .. import ratelimit, runtime
from ..errors import INGEST_BAD_PAYLOAD, INGEST_BAD_TOKEN, INGEST_TOO_LARGE, SieveError
from ..worker import enqueue

router = APIRouter(tags=["Ingest"])
MAX_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 1000


def _token_ok(request: Request, expected: str) -> bool:
    auth = request.headers.get("authorization", "")
    tok = auth[7:] if auth.lower().startswith("bearer ") else request.headers.get("x-sieve-token", "")
    return bool(tok) and hmac.compare_digest(tok.encode(), expected.encode())


@router.post("/api/ingest", status_code=202)
@router.post("/api/ingest/wazuh", status_code=202)
async def ingest_alert(request: Request):
    s = runtime.current()
    ratelimit.check("ingest", request.client.host if request.client else "?")
    if not _token_ok(request, s.ingest_token):
        raise SieveError(INGEST_BAD_TOKEN, "Ingest token missing or wrong.", status=401)
    body = await request.body()
    if len(body) > MAX_BYTES:
        raise SieveError(INGEST_TOO_LARGE, "Request body is too large.", status=413)
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SieveError(INGEST_BAD_PAYLOAD, "Body is not JSON.") from e
    items = data if isinstance(data, list) else [data]
    if len(items) > MAX_ITEMS:
        raise SieveError(INGEST_TOO_LARGE, f"At most {MAX_ITEMS} alerts per request.", status=413)
    if not items or not all(isinstance(x, dict) and isinstance(x.get("rule"), dict) for x in items):
        raise SieveError(INGEST_BAD_PAYLOAD, "Each alert needs a 'rule' object.")
    for x in items:
        enqueue(x, "wazuh")
    return {"queued": len(items)}

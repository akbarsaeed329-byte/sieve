"""Shared outbound HTTP factory. Always sets a timeout; tests inject an httpx.MockTransport."""
from __future__ import annotations

import httpx

_transport: list = [None]


def set_transport(t: httpx.AsyncBaseTransport | None) -> None:
    _transport[0] = t


def client(timeout: float = 10, verify: bool = True, **kw) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=verify, transport=_transport[0], **kw)

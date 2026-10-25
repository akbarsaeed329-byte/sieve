"""Read-only Wazuh access: manager API auth test and indexer search (OpenSearch DSL).

Only fixed, parameterised queries are built here (llm/investigate.py templates, rule backtest, the
"Show query" link). Nothing a model writes is ever passed through as a query string.
"""
from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from .. import http, secrets_store
from ..errors import WAZUH_AUTH, WAZUH_ERROR, WAZUH_NOT_CONFIGURED, WAZUH_UNREACHABLE, SieveError

_token_cache: dict[str, tuple[str, float]] = {}


def configured(settings) -> bool:
    return bool(settings.wazuh.api_url or settings.wazuh.indexer_url)


async def manager_token(settings) -> str:
    w = settings.wazuh
    if not w.api_url:
        raise SieveError(WAZUH_NOT_CONFIGURED, "The Wazuh manager API URL is not set.", status=424)
    cached = _token_cache.get(w.api_url)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    pw = secrets_store.resolve(w.password_env)
    try:
        async with http.client(timeout=w.timeout_s, verify=w.verify_tls) as c:
            r = await c.post(f"{w.api_url.rstrip('/')}/security/user/authenticate", auth=(w.username, pw))
    except (httpx.TimeoutException, httpx.TransportError) as e:
        raise SieveError(WAZUH_UNREACHABLE, f"Cannot reach the Wazuh manager ({type(e).__name__}).",
                         status=504) from e
    if r.status_code in (401, 403):
        raise SieveError(WAZUH_AUTH, "The Wazuh manager rejected the user or password.", status=401)
    if r.status_code != 200:
        raise SieveError(WAZUH_ERROR, f"The Wazuh manager returned HTTP {r.status_code}.", status=502)
    tok = ((r.json() or {}).get("data") or {}).get("token", "")
    _token_cache[w.api_url] = (tok, time.monotonic() + 600)
    return tok


async def indexer_search(settings, body: dict) -> dict:
    w = settings.wazuh
    if not w.indexer_url:
        raise SieveError(WAZUH_NOT_CONFIGURED, "The Wazuh indexer URL is not set.", status=424)
    pw = secrets_store.resolve(w.indexer_password_env)
    try:
        async with http.client(timeout=w.timeout_s, verify=w.verify_tls) as c:
            r = await c.post(f"{w.indexer_url.rstrip('/')}/{w.alerts_index}/_search", json=body,
                             auth=(w.indexer_username, pw))
    except (httpx.TimeoutException, httpx.TransportError) as e:
        raise SieveError(WAZUH_UNREACHABLE, f"Cannot reach the Wazuh indexer ({type(e).__name__}).",
                         status=504) from e
    if r.status_code in (401, 403):
        raise SieveError(WAZUH_AUTH, "The Wazuh indexer rejected the user or password.", status=401)
    if r.status_code != 200:
        raise SieveError(WAZUH_ERROR, f"The Wazuh indexer returned HTTP {r.status_code}.", status=502)
    return r.json()


async def test_connection(settings) -> dict:
    out: dict = {}
    for name, fn in (("manager", lambda: manager_token(settings)),
                     ("indexer", lambda: indexer_search(settings, {"size": 0, "query": {"match_all": {}}}))):
        try:
            await fn()
            out[name] = {"ok": True, "message": "Connected."}
        except SieveError as e:
            out[name] = {"ok": False, **e.to_dict()}
    return out


def kql(agent_name: str | None, srcip: str | None, user: str | None) -> str:
    parts = []
    for field, val in (("agent.name", agent_name), ("data.srcip", srcip), ("data.dstuser", user)):
        if val:
            parts.append(f'{field}:"{val}"')
    return " AND ".join(parts)


def dashboard_link(settings, query: str) -> str | None:
    base = settings.wazuh.dashboard_url.rstrip("/")
    if not base:
        return None
    return (f"{base}/app/threat-hunting#/overview/?_a=(query:(language:kuery,query:'{quote(query, safe='')}'))"
            "&_g=(time:(from:now-24h,to:now))")

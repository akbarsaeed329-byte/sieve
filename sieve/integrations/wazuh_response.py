"""Wazuh active response (master prompt 2.8). Off by default; every run is human-approved and audited.

Two actions only:
* firewall-drop    -> blocks the incident's source IP on the affected agent
* disable-account  -> locks the incident's user on the affected agent
The model never reaches this module: only the admin-only API route calls it, after
``allow_active_response: true`` in the config file and an explicit {"confirm": true} body.
"""
from __future__ import annotations

import httpx

from .. import http
from ..errors import AR_NOT_APPLICABLE, WAZUH_AUTH, WAZUH_ERROR, WAZUH_UNREACHABLE, SieveError
from .wazuh import manager_token

ACTIONS = {"firewall-drop": "!firewall-drop", "disable-account": "!disable-account"}


def build_body(action: str, srcip: str | None, user: str | None) -> dict:
    if action == "firewall-drop":
        if not srcip:
            raise SieveError(AR_NOT_APPLICABLE, "This incident has no source IP to block.", status=422)
        return {"command": ACTIONS[action], "arguments": [], "alert": {"data": {"srcip": srcip}}}
    if action == "disable-account":
        if not user:
            raise SieveError(AR_NOT_APPLICABLE, "This incident has no user to lock.", status=422)
        return {"command": ACTIONS[action], "arguments": [], "alert": {"data": {"dstuser": user}}}
    raise SieveError(AR_NOT_APPLICABLE, f"Unknown action {action}.", status=404)


async def run(settings, action: str, agent_id: str | None, srcip: str | None, user: str | None) -> dict:
    if not agent_id:
        raise SieveError(AR_NOT_APPLICABLE, "The incident has no Wazuh agent ID.", status=422)
    body = build_body(action, srcip, user)
    tok = await manager_token(settings)
    w = settings.wazuh
    try:
        async with http.client(timeout=w.timeout_s, verify=w.verify_tls) as c:
            r = await c.put(f"{w.api_url.rstrip('/')}/active-response", params={"agents_list": agent_id},
                            json=body, headers={"Authorization": f"Bearer {tok}"})
    except (httpx.TimeoutException, httpx.TransportError) as e:
        raise SieveError(WAZUH_UNREACHABLE, "Cannot reach the Wazuh manager.", status=504) from e
    if r.status_code in (401, 403):
        raise SieveError(WAZUH_AUTH, "Wazuh refused the active-response request.", status=401)
    if r.status_code != 200:
        raise SieveError(WAZUH_ERROR, f"Wazuh returned HTTP {r.status_code} for active response.", status=502)
    return {"ok": True, "action": action, "agent_id": agent_id, "wazuh": (r.json() or {}).get("data", {})}

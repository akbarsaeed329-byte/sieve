"""More threat-intel enrichers: MISP (two-way), AlienVault OTX, abuse.ch ThreatFox.

Each returns {"hit": bool, "source": str, ...details}; results are cached like AbuseIPDB. Only public IPs are
looked up. MISP also receives a *sighting* when an analyst confirms an incident as real (two-way sharing).
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

import httpx
from sqlalchemy import select

from ... import http, secrets_store
from ...db import SessionLocal
from ...errors import INTEL_AUTH, INTEL_UNREACHABLE, SieveError
from ...models import IntelCache, aware, utcnow
from .. import Manifest, config, register

MISP = register(
    Manifest(
        id="misp",
        name="MISP",
        type="enricher",
        version="1.0.0",
        description="Looks up source IPs in your MISP instance and records a sighting when an incident is confirmed real.",
        permissions={"network": ["your MISP server"], "read_alerts": False, "trigger_response": False},
        settings_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "title": "MISP URL", "default": ""},
                "verify_tls": {"type": "boolean", "title": "Verify TLS", "default": True},
                "push_sightings": {"type": "boolean", "title": "Send sightings for confirmed incidents", "default": True},
                "api_key": {"type": "string", "format": "password", "title": "Auth key", "x-secret-name": "SIEVE_MISP_KEY"},
            },
        },
        secret_fields=["api_key"],
    )
)
OTX = register(
    Manifest(
        id="otx",
        name="AlienVault OTX",
        type="enricher",
        version="1.0.0",
        description="Counts OTX pulses that mention the source IP.",
        permissions={"network": ["otx.alienvault.com"], "read_alerts": False, "trigger_response": False},
        settings_schema={
            "type": "object",
            "properties": {
                "min_pulses": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 2,
                    "title": "Pulses that count as a hit",
                },
                "api_key": {"type": "string", "format": "password", "title": "API key", "x-secret-name": "SIEVE_OTX_KEY"},
            },
        },
        secret_fields=["api_key"],
    )
)
THREATFOX = register(
    Manifest(
        id="threatfox",
        name="abuse.ch ThreatFox",
        type="enricher",
        version="1.0.0",
        description="Checks the source IP against ThreatFox indicators of compromise.",
        permissions={"network": ["threatfox-api.abuse.ch"], "read_alerts": False, "trigger_response": False},
        settings_schema={
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "format": "password", "title": "Auth key", "x-secret-name": "SIEVE_THREATFOX_KEY"}
            },
        },
        secret_fields=["api_key"],
    )
)


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _cached(source: str, ip: str, minutes: int) -> dict | None:
    with SessionLocal() as db:
        row = db.scalar(
            select(IntelCache)
            .where(IntelCache.source == source, IntelCache.indicator == ip)
            .order_by(IntelCache.fetched_at.desc())
        )
        if row and utcnow() - aware(row.fetched_at) < timedelta(minutes=minutes):
            return {**row.data, "cached": True}
    return None


def _store(source: str, ip: str, data: dict) -> dict:
    with SessionLocal() as db:
        db.add(IntelCache(source=source, indicator=ip, data=data))
        db.commit()
    return {**data, "cached": False}


async def _req(method: str, url: str, **kw) -> httpx.Response:
    try:
        async with http.client(timeout=6, verify=kw.pop("verify", True)) as c:
            return await c.request(method, url, **kw)
    except (httpx.TimeoutException, httpx.TransportError) as e:
        raise SieveError(INTEL_UNREACHABLE, f"Threat-intel service did not answer ({type(e).__name__}).", status=504) from e


def configured(settings, pid: str) -> bool:
    if pid == "misp":
        return bool(config(settings, "misp").get("url") and secrets_store.resolve("SIEVE_MISP_KEY"))
    return bool(secrets_store.resolve({"otx": "SIEVE_OTX_KEY", "threatfox": "SIEVE_THREATFOX_KEY"}[pid]))


async def misp(ip: str, settings) -> dict:
    if not _public(ip):
        return {"hit": False, "source": "MISP", "skipped": "not public"}
    if (c := _cached("misp", ip, settings.intel.cache_minutes)) is not None:
        return c
    cfg = config(settings, "misp")
    key = secrets_store.resolve("SIEVE_MISP_KEY")
    r = await _req(
        "POST",
        f"{cfg['url'].rstrip('/')}/attributes/restSearch",
        verify=cfg.get("verify_tls", True),
        headers={"Authorization": key, "Accept": "application/json"},
        json={"value": ip, "type": ["ip-src", "ip-dst"], "to_ids": True, "limit": 20},
    )
    if r.status_code in (401, 403):
        raise SieveError(INTEL_AUTH, "MISP rejected the key.", status=401)
    attrs = ((r.json() or {}).get("response") or {}).get("Attribute") or []
    events = sorted({str(a.get("event_id")) for a in attrs})
    return _store("misp", ip, {"hit": bool(attrs), "source": "MISP", "events": events[:10], "attributes": len(attrs)})


async def misp_sighting(ip: str, settings) -> bool:
    if not (configured(settings, "misp") and config(settings, "misp").get("push_sightings", True) and _public(ip)):
        return False
    cfg = config(settings, "misp")
    r = await _req(
        "POST",
        f"{cfg['url'].rstrip('/')}/sightings/add",
        verify=cfg.get("verify_tls", True),
        headers={"Authorization": secrets_store.resolve("SIEVE_MISP_KEY"), "Accept": "application/json"},
        json={"value": ip, "source": "Sieve", "type": "0"},
    )
    return r.status_code == 200


async def otx(ip: str, settings) -> dict:
    if not _public(ip):
        return {"hit": False, "source": "OTX", "skipped": "not public"}
    if (c := _cached("otx", ip, settings.intel.cache_minutes)) is not None:
        return c
    v = "IPv6" if ":" in ip else "IPv4"
    r = await _req(
        "GET",
        f"https://otx.alienvault.com/api/v1/indicators/{v}/{ip}/general",
        headers={"X-OTX-API-KEY": secrets_store.resolve("SIEVE_OTX_KEY")},
    )
    if r.status_code in (401, 403):
        raise SieveError(INTEL_AUTH, "OTX rejected the key.", status=401)
    pulses = int(((r.json() or {}).get("pulse_info") or {}).get("count") or 0)
    return _store(
        "otx", ip, {"hit": pulses >= int(config(settings, "otx").get("min_pulses", 2)), "source": "OTX", "pulses": pulses}
    )


async def threatfox(ip: str, settings) -> dict:
    if not _public(ip):
        return {"hit": False, "source": "ThreatFox", "skipped": "not public"}
    if (c := _cached("threatfox", ip, settings.intel.cache_minutes)) is not None:
        return c
    r = await _req(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Auth-Key": secrets_store.resolve("SIEVE_THREATFOX_KEY")},
        json={"query": "search_ioc", "search_term": ip},
    )
    if r.status_code in (401, 403):
        raise SieveError(INTEL_AUTH, "ThreatFox rejected the key.", status=401)
    j = r.json() or {}
    data = j.get("data") if j.get("query_status") == "ok" else []
    data = data if isinstance(data, list) else []
    return _store(
        "threatfox",
        ip,
        {"hit": bool(data), "source": "ThreatFox", "malware": sorted({d.get("malware_printable") for d in data if d})[:5]},
    )


LOOKUPS = {"misp": misp, "otx": otx, "threatfox": threatfox}

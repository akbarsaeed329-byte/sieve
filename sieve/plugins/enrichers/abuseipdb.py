"""AbuseIPDB threat-intel enricher (master prompt 2.4).

* ``async def enrich(srcip, settings) -> dict``
* results cached in SQLite (``intel_cache``) for ``intel.cache_minutes`` (default 60)
* free-tier daily limit tracked in ``intel_usage``; lookups stop when it is reached
* the key comes from SIEVE_ABUSEIPDB_KEY (env) or the encrypted secret store; never logged
* private, loopback and reserved addresses are never sent anywhere
Return: {"ip", "abuse_score", "country", "isp", "reports", "cached"}; errors raise SieveError so the
worker can mark the incident "partial context" and carry on.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select

from ... import http, secrets_store
from ...db import SessionLocal
from ...errors import INTEL_AUTH, INTEL_QUOTA, INTEL_UNREACHABLE, SieveError
from ...models import IntelCache, IntelUsage, aware, utcnow
from .. import Manifest, register

SOURCE = "abuseipdb"
URL = "https://api.abuseipdb.com/api/v2/check"

MANIFEST = register(Manifest(
    id="abuseipdb", name="AbuseIPDB", type="enricher", version="1.0.0",
    description="Looks up source IPs on AbuseIPDB. Sets the threat-intel term of the severity score.",
    permissions={"network": ["api.abuseipdb.com"], "read_alerts": False, "trigger_response": False},
    settings_schema={"type": "object", "properties": {
        "min_score": {"type": "integer", "minimum": 0, "maximum": 100, "default": 50,
                      "title": "Confidence that counts as a hit"},
        "max_age_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30,
                         "title": "Only count reports from the last N days"},
        "api_key": {"type": "string", "format": "password", "title": "API key",
                    "x-secret-name": "SIEVE_ABUSEIPDB_KEY"},
    }},
    secret_fields=["api_key"], default_enabled=True,
))


def _key(settings) -> str:
    return secrets_store.resolve(settings.intel.abuseipdb_key_env or "SIEVE_ABUSEIPDB_KEY")


def configured(settings) -> bool:
    return bool(_key(settings))


def _public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def usage_today() -> int:
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    with SessionLocal() as db:
        row = db.scalar(select(IntelUsage).where(IntelUsage.source == SOURCE, IntelUsage.day == day))
        return row.count if row else 0


def _bump_usage() -> None:
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    with SessionLocal() as db:
        row = db.scalar(select(IntelUsage).where(IntelUsage.source == SOURCE, IntelUsage.day == day))
        if row is None:
            db.add(IntelUsage(source=SOURCE, day=day, count=1))
        else:
            row.count += 1
        db.commit()


async def enrich(srcip: str, settings) -> dict:
    if not _public(srcip):
        return {"ip": srcip, "abuse_score": 0, "country": None, "isp": None, "reports": 0, "cached": False,
                "skipped": "not a public address"}
    ttl = timedelta(minutes=settings.intel.cache_minutes)
    with SessionLocal() as db:
        row = db.scalar(select(IntelCache).where(IntelCache.source == SOURCE, IntelCache.indicator == srcip)
                        .order_by(IntelCache.fetched_at.desc()))
        if row and utcnow() - aware(row.fetched_at) < ttl:
            return {**row.data, "cached": True}
    key = _key(settings)
    if not key:
        raise SieveError(INTEL_AUTH, "No AbuseIPDB key is configured.", status=424)
    if usage_today() >= settings.intel.abuseipdb_daily_limit:
        raise SieveError(INTEL_QUOTA, "AbuseIPDB daily lookup limit reached.", status=429)
    from .. import config as plugin_config
    cfg = plugin_config(settings, "abuseipdb")
    try:
        async with http.client(timeout=5) as c:
            r = await c.get(URL, params={"ipAddress": srcip, "maxAgeInDays": cfg.get("max_age_days", 30)},
                            headers={"Key": key, "Accept": "application/json"})
    except (httpx.TimeoutException, httpx.TransportError) as e:
        raise SieveError(INTEL_UNREACHABLE, f"AbuseIPDB did not answer ({type(e).__name__}).", status=504) from e
    _bump_usage()
    if r.status_code in (401, 403):
        raise SieveError(INTEL_AUTH, "AbuseIPDB rejected the key.", status=401)
    if r.status_code == 429:
        raise SieveError(INTEL_QUOTA, "AbuseIPDB rate limit reached.", status=429)
    if r.status_code != 200:
        raise SieveError(INTEL_UNREACHABLE, f"AbuseIPDB returned HTTP {r.status_code}.", status=502)
    d = (r.json() or {}).get("data") or {}
    out = {"ip": srcip, "abuse_score": int(d.get("abuseConfidenceScore") or 0),
           "country": d.get("countryCode"), "isp": (d.get("isp") or "")[:120] or None,
           "reports": int(d.get("totalReports") or 0)}
    with SessionLocal() as db:
        db.add(IntelCache(source=SOURCE, indicator=srcip, data=out))
        db.commit()
    return {**out, "cached": False}

"""Plugin registry (research doc 10.3).

A plugin declares a manifest: id, type (enricher | notifier | model_provider | playbook | report),
version, the permissions it needs (network domains, read alerts, trigger response) and a JSON Schema
for its settings. The UI renders the settings form from that schema. Enabled state and non-secret
settings live in ``settings.plugins[<id>]``; secret fields are stored through secrets_store.

v0.1 runs plugins in-process behind a strict call wrapper (timeout + exception containment), so a
broken plugin degrades to "partial context" and never stops the pipeline. Out-of-process isolation
is planned (ADR-006).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from ..errors import PLUGIN_BAD_SETTINGS, PLUGIN_UNKNOWN, SieveError

log = logging.getLogger("sieve.plugins")


@dataclass
class Manifest:
    id: str
    name: str
    type: str
    version: str
    description: str
    permissions: dict[str, Any]
    settings_schema: dict[str, Any]
    secret_fields: list[str] = field(default_factory=list)
    default_enabled: bool = False


REGISTRY: dict[str, Manifest] = {}


def register(m: Manifest) -> Manifest:
    REGISTRY[m.id] = m
    return m


def get(pid: str) -> Manifest:
    if pid not in REGISTRY:
        raise SieveError(PLUGIN_UNKNOWN, f"No plugin called {pid}.", status=404)
    return REGISTRY[pid]


def is_enabled(settings, pid: str) -> bool:
    st = settings.plugins.get(pid)
    return st.enabled if st is not None else REGISTRY[pid].default_enabled


def config(settings, pid: str) -> dict:
    m = REGISTRY[pid]
    defaults = {k: v.get("default") for k, v in m.settings_schema.get("properties", {}).items() if "default" in v}
    st = settings.plugins.get(pid)
    return {**defaults, **(st.config if st else {})}


def validate_settings(m: Manifest, values: dict) -> dict:
    """Minimal JSON Schema subset: object with typed properties, enum, minimum/maximum, required."""
    props = m.settings_schema.get("properties", {})
    out: dict[str, Any] = {}
    for k, v in values.items():
        if k not in props or k in m.secret_fields:
            raise SieveError(PLUGIN_BAD_SETTINGS, f"Unknown setting '{k}'.", status=422)
        spec = props[k]
        t = spec.get("type")
        ok = {"string": isinstance(v, str), "integer": isinstance(v, int) and not isinstance(v, bool),
              "number": isinstance(v, int | float) and not isinstance(v, bool), "boolean": isinstance(v, bool),
              "array": isinstance(v, list)}.get(t, True)
        if not ok:
            raise SieveError(PLUGIN_BAD_SETTINGS, f"'{k}' must be a {t}.", status=422)
        if "enum" in spec and v not in spec["enum"]:
            raise SieveError(PLUGIN_BAD_SETTINGS, f"'{k}' must be one of {spec['enum']}.", status=422)
        if "minimum" in spec and v < spec["minimum"] or "maximum" in spec and v > spec["maximum"]:
            raise SieveError(PLUGIN_BAD_SETTINGS, f"'{k}' is out of range.", status=422)
        out[k] = v
    return out


async def call_safely(pid: str, coro, timeout: float = 8.0):
    """Contain any plugin failure: returns (result, error_dict_or_None)."""
    try:
        return await asyncio.wait_for(coro, timeout), None
    except SieveError as e:
        return None, e.to_dict()
    except TimeoutError:
        return None, {"code": "SIEVE-PLG-504", "message": f"Plugin {pid} timed out.", "fix": ""}
    except Exception as e:  # noqa: BLE001 - containment is the point
        log.error("plugin crashed", extra={"plugin": pid, "error": type(e).__name__})
        return None, {"code": "SIEVE-PLG-500", "message": f"Plugin {pid} failed ({type(e).__name__}).", "fix": ""}


from .enrichers import abuseipdb as _abuseipdb  # noqa: E402,F401  (registers itself)
from .enrichers import feeds as _feeds  # noqa: E402,F401

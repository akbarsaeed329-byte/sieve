"""Human-written playbooks. The LLM may only reference step IDs that exist here."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml


@lru_cache
def load() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in resources.files("sieve.playbooks").iterdir():
        if f.name.endswith(".yaml"):
            pb = yaml.safe_load(f.read_text())
            out[pb["id"]] = pb
    return out


def choose(groups: set[str], techniques: set[str]) -> str:
    if groups & {"authentication_failed", "authentication_failures", "authentication_success", "invalid_login"}:
        return "PB-BRUTE"
    if groups & {"adduser", "account_changed", "group_changed"} or any(t.startswith("T1136") for t in techniques):
        return "PB-NEWADMIN"
    if any(t.startswith("T1059") for t in techniques):
        return "PB-EXEC"
    if groups & {"web", "web_scan", "attack", "accesslog"}:
        return "PB-WEBSCAN"
    return "PB-GENERIC"


def step_ids() -> set[str]:
    return {st["id"] for pb in load().values() for st in pb["steps"]}

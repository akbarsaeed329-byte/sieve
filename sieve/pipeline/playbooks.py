"""Human-written playbooks (sieve/playbooks/PB-*.yaml). The LLM may only reference IDs that exist here.

Loaded once at startup (``load``). Template variables ``{user}``, ``{srcip}`` and ``{agent_name}``
are substituted at render time from the incident's *validated* entity fields (normalise.py only
keeps syntactically valid IPs and account-like usernames), never from raw log text.
"""

from __future__ import annotations

import logging
import string
from functools import lru_cache
from importlib import resources

import yaml

log = logging.getLogger("sieve.playbooks")
VARS = ("user", "srcip", "agent_name")
_FALLBACK = {"user": "the affected account", "srcip": "the source IP", "agent_name": "the host"}


@lru_cache
def load() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in sorted(resources.files("sieve.playbooks").iterdir(), key=lambda x: x.name):
        if not (f.name.startswith("PB-") and f.name.endswith(".yaml")):
            continue
        try:
            pb = yaml.safe_load(f.read_text())
            if not (isinstance(pb, dict) and pb.get("id") and isinstance(pb.get("steps"), list)):
                raise ValueError("needs id and a list of steps")
            for st in pb["steps"]:
                if not (str(st.get("id", "")).startswith(pb["id"] + "-") and st.get("title")):
                    raise ValueError(f"step {st.get('id')!r} needs an id prefixed {pb['id']}- and a title")
        except (yaml.YAMLError, ValueError) as e:
            log.error("playbook rejected", extra={"file": f.name, "error": str(e)})
            continue
        out[pb["id"]] = pb
    return out


def ids() -> list[str]:
    return sorted(load())


def step_ids() -> set[str]:
    return {st["id"] for pb in load().values() for st in pb["steps"]}


def choose(groups: set[str], techniques: set[str]) -> str:
    if groups & {"authentication_failed", "authentication_failures", "authentication_success", "invalid_login",
                 "win_authentication_failed"}:
        return "PB-BRUTE"
    if groups & {"adduser", "addgroup", "account_changed", "account_changes", "group_changed"} or \
            any(t.startswith("T1136") for t in techniques):
        return "PB-NEWADMIN"
    if any(t.startswith(("T1059", "T1027")) for t in techniques):
        return "PB-EXEC"
    if groups & {"web", "web_scan", "attack", "accesslog", "sql_injection", "web_attack"}:
        return "PB-WEBSCAN"
    return "PB-GENERIC"


class _Safe(string.Formatter):
    """Only the documented variables are substituted; attribute/index lookups are refused."""

    def get_field(self, field_name, args, kwargs):
        if field_name not in VARS:
            return "{" + field_name + "}", field_name
        return kwargs.get(field_name) or _FALLBACK[field_name], field_name


def render(pb_id: str | None, user: str | None, srcip: str | None, agent_name: str | None) -> dict | None:
    pb = load().get(pb_id or "PB-GENERIC") or load().get("PB-GENERIC")
    if pb is None:
        return None
    vals = {"user": user, "srcip": srcip, "agent_name": agent_name}
    fmt = _Safe()
    steps = []
    for st in pb["steps"]:
        detail = st.get("detail") or st.get("text") or ""
        try:
            detail = fmt.format(detail, **vals)
        except (ValueError, IndexError, KeyError):
            pass
        steps.append({"id": st["id"], "title": st["title"], "detail": detail,
                      "requires_approval": bool(st.get("requires_approval")),
                      "active_response": st.get("active_response")})
    return {"id": pb["id"], "title": pb["title"], "mitre": pb.get("mitre", []), "steps": steps}

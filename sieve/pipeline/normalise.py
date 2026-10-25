"""Map raw Wazuh alert JSON to Sieve's internal NormAlert.

Every field a remote party can write ends up in ``untrusted``.
When in doubt, add the dotted path to UNTRUSTED_PATHS — it is a
blocklist, not a whitelist.  These fields are fenced before any LLM
call and scanned by the tripwire.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

UNTRUSTED_PATHS: tuple[str, ...] = (
    "data.srcuser", "data.dstuser", "data.user", "data.username",
    "data.url", "data.uri", "data.http_user_agent", "data.user_agent",
    "data.query", "data.dns.question.name", "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine", "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserName", "data.win.eventdata.scriptBlockText",
    "data.win.eventdata.image", "data.win.eventdata.targetFilename",
    "data.audit.command", "data.audit.exe", "data.command",
    "data.file", "syscheck.path", "full_log",
)
USER_PATHS = (
    "data.dstuser", "data.srcuser", "data.user", "data.username",
    "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
)
_FIRST_TOKEN = re.compile(r"\S+")


def _dig(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _safe_user(v: Any) -> str | None:
    """Return only the first whitespace-token so an injected suffix cannot fork the entity key."""
    if not v:
        return None
    m = _FIRST_TOKEN.search(str(v).strip())
    return (m.group()[:64]) if m else None


@dataclass
class NormAlert:
    wazuh_id: str
    rule_id: str
    level: int
    description: str
    agent_name: str | None
    srcip: str | None
    user: str | None
    groups: list[str]
    mitre_ids: list[str]
    mitre_tactics: list[str]
    timestamp: datetime
    full_log: str
    untrusted: dict[str, str] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


def normalise(raw: dict) -> NormAlert:
    rule = raw.get("rule") or {}
    mitre = rule.get("mitre") or {}
    agent = raw.get("agent") or {}
    untrusted: dict[str, str] = {}
    for p in UNTRUSTED_PATHS:
        v = _dig(raw, p)
        if v not in (None, ""):
            untrusted[p] = str(v)[:5000]
    user_raw = next((_dig(raw, p) for p in USER_PATHS if _dig(raw, p)), None)
    rid = str(rule.get("id", "0"))
    ts_raw = raw.get("timestamp", "")
    wid = str(raw.get("id") or f"{rid}-{ts_raw}-{agent.get('name', '')}")
    return NormAlert(
        wazuh_id=wid,
        rule_id=rid,
        level=int(rule.get("level", 0) or 0),
        description=str(rule.get("description", ""))[:500],
        agent_name=agent.get("name"),
        srcip=_dig(raw, "data.srcip"),
        user=_safe_user(user_raw),
        groups=list(rule.get("groups") or []),
        mitre_ids=list(mitre.get("id") or []),
        mitre_tactics=list(mitre.get("tactic") or []),
        timestamp=_parse_ts(ts_raw),
        full_log=str(raw.get("full_log", ""))[:4000],
        untrusted=untrusted,
        raw=raw,
    )

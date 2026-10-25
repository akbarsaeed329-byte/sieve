"""Map raw Wazuh alert JSON to Sieve's internal NormAlert.

Every field a remote party can write ends up in ``untrusted``.
When in doubt, add the dotted path to UNTRUSTED_PATHS — it is a
blocklist, not a whitelist.  These fields are fenced before any LLM
call and scanned by the tripwire.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    # Wazuh rule descriptions can interpolate decoded fields, e.g. "$(win.eventdata.targetUserName)",
    # so the description is attacker-influenced too. It is scanned and fenced like any other field.
    "rule.description",
    "data.win.eventdata.workstationName", "data.win.eventdata.ipAddress", "data.win.system.computer",
    "data.http_referer", "data.referer", "data.protocol", "data.extra_data", "data.status_message",
    "data.office365.UserId", "data.aws.userIdentity.userName", "data.gcp.protoPayload.authenticationInfo",
    "decoder.name",
)
USER_PATHS = (
    "data.dstuser", "data.srcuser", "data.user", "data.username",
    "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
)
_FIRST_TOKEN = re.compile(r"\S+")
_USER_SAFE = re.compile(r"^[A-Za-z0-9._@$\\-]{1,64}$")

# Canonical ATT&CK tactic names. Wazuh emits title case ("Credential Access"); other sources use
# ATT&CK short names ("credential-access"). Both map to one form so tactics are never double-counted.
# Retired names (e.g. "Defense Evasion") are kept as sent: there is no one-to-one modern mapping.
_TACTIC_ALIASES = {"command and control": "Command and Control"}


def _dig(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).astimezone(UTC)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return datetime.now(UTC)


def _safe_user(v: Any) -> str | None:
    """Return only the first whitespace-token so an injected suffix cannot fork the entity key.

    The token must also look like an account name; anything else (markup, quotes, brackets) is
    rejected so it can never reach a notification, a template or an entity key unescaped.
    """
    if not v:
        return None
    m = _FIRST_TOKEN.search(str(v).strip())
    if not m:
        return None
    tok = m.group()[:64]
    return tok if _USER_SAFE.match(tok) else None


def _safe_ip(v: Any) -> str | None:
    """Only a syntactically valid IP becomes an entity; anything else stays untrusted text."""
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def canonical_tactic(t: str) -> str:
    t = " ".join(str(t).replace("-", " ").replace("_", " ").split())
    low = t.lower()
    if low in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[low]
    return " ".join(w if w in ("and", "of") else w.capitalize() for w in low.split())


@dataclass
class NormAlert:
    wazuh_id: str
    rule_id: str
    level: int
    description: str
    agent_name: str | None
    agent_id: str | None
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
    srcip_raw = _dig(raw, "data.srcip")
    srcip = _safe_ip(srcip_raw)
    if srcip_raw and not srcip:
        untrusted["data.srcip"] = str(srcip_raw)[:5000]
    rid = str(rule.get("id", "0"))
    ts_raw = raw.get("timestamp", "")
    wid = str(raw.get("id") or f"{rid}-{ts_raw}-{agent.get('name', '')}")
    return NormAlert(
        wazuh_id=wid,
        rule_id=rid,
        level=int(rule.get("level", 0) or 0),
        description=str(rule.get("description", ""))[:500],
        agent_name=(str(agent["name"])[:200] if agent.get("name") else None),
        agent_id=(str(agent["id"])[:32] if agent.get("id") else None),
        srcip=srcip,
        user=_safe_user(user_raw),
        groups=[str(g) for g in (rule.get("groups") or [])][:30],
        mitre_ids=[str(t) for t in (mitre.get("id") or [])][:20],
        mitre_tactics=sorted({canonical_tactic(t) for t in (mitre.get("tactic") or [])}),
        timestamp=_parse_ts(ts_raw),
        full_log=str(raw.get("full_log", ""))[:4000],
        untrusted=untrusted,
        raw=raw,
    )

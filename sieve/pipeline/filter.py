"""Suppression with a recorded reason.  Nothing is dropped silently.
Tripwire hits are never suppressed regardless of any rule.
"""
from __future__ import annotations

from ..config import Settings
from .normalise import NormAlert


def suppression_reason(a: NormAlert, s: Settings, tripwire_hit: bool) -> str | None:
    if tripwire_hit:
        return None
    if a.rule_id in s.filter.allow_rule_ids:
        return f"rule allowlist: rule {a.rule_id}"
    if a.srcip and a.srcip in s.filter.allow_srcips:
        return f"approved-source allowlist: {a.srcip}"
    if a.level < s.filter.min_level:
        return f"below min_level {s.filter.min_level} (got {a.level})"
    return None

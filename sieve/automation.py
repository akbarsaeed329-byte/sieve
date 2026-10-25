"""Workflow automation rules: "when <trigger> and <conditions>, do <actions>".

Deliberately safe action set (research: users want conditional workflows; leaders do not yet trust automated
response): assign, add tags, set team, notify a channel, page the on-call person, call a webhook, open a Jira
issue. Nothing here touches a host. Every run is written to the audit log with the rule that fired.
"""

from __future__ import annotations

import fnmatch
import logging

from sqlalchemy import select

from .db import SessionLocal
from .models import AuditEvent, AutomationRule, Incident, utcnow
from .pipeline.score import band_rank

log = logging.getLogger("sieve.automation")
TRIGGERS = ("incident.created", "incident.band_raised", "incident.tripwire", "incident.overdue")
ACTIONS = ("assign", "tag", "team", "notify", "page_oncall", "webhook", "jira")


def matches(rule: AutomationRule, inc: Incident) -> bool:
    c = rule.conditions or {}
    if rule.tenant_id and inc.tenant_id != rule.tenant_id:
        return False
    if c.get("min_band") and band_rank(inc.band) < band_rank(c["min_band"]):
        return False
    if c.get("hosts") and not any(fnmatch.fnmatch(inc.agent_name or "", h) for h in c["hosts"]):
        return False
    rules = {a.rule_id for a in inc.alerts}
    if c.get("rule_ids") and not rules & set(map(str, c["rule_ids"])):
        return False
    techs = set(inc.techniques or [])
    if c.get("techniques") and not any(t == x or t.startswith(x + ".") for t in techs for x in c["techniques"]):
        return False
    if c.get("tripwire") is True and not inc.tripwire:
        return False
    return not (c.get("tags_any") and not set(c["tags_any"]) & set(inc.tags or []))


async def run(trigger: str, inc_id: int, settings) -> list[str]:
    done: list[str] = []
    with SessionLocal() as db:
        inc = db.get(Incident, inc_id)
        if inc is None:
            return done
        rules = db.scalars(
            select(AutomationRule).where(AutomationRule.enabled.is_(True), AutomationRule.trigger == trigger)
        ).all()
        for rule in rules:
            if not matches(rule, inc):
                continue
            for act in rule.actions or []:
                kind = act.get("type")
                try:
                    if kind == "assign" and act.get("user"):
                        inc.assignee = inc.assignee or act["user"]
                    elif kind == "tag":
                        inc.tags = sorted(set(inc.tags or []) | {str(t)[:40].lower() for t in act.get("tags", [])})
                    elif kind == "team":
                        inc.team = str(act.get("team", ""))[:80] or inc.team
                    elif kind in ("notify", "page_oncall", "webhook", "jira"):
                        db.commit()
                        await _external(kind, act, inc, settings)
                    done.append(f"{rule.name}: {kind}")
                except Exception as e:  # noqa: BLE001 - one failing action never blocks triage
                    log.warning("automation action failed", extra={"rule": rule.id, "action": kind, "error": type(e).__name__})
            rule.runs, rule.last_run_at = (rule.runs or 0) + 1, utcnow()
            db.add(
                AuditEvent(
                    actor=f"automation:{rule.name}"[:80],
                    action="automation.ran",
                    target=f"INC-{inc.id}",
                    detail={"rule_id": rule.id, "trigger": trigger, "actions": [a.get("type") for a in rule.actions or []]},
                )
            )
        db.commit()
    return done


async def _external(kind: str, act: dict, inc: Incident, settings) -> None:
    from .notify import dispatch

    if kind == "notify":
        await dispatch.send_text(
            f"[Sieve automation] {inc.band.upper()} INC-{inc.id:04d} {inc.title} on {inc.agent_name}. "
            f"{settings.notify.public_url.rstrip('/')}/incidents/{inc.id}",
            settings,
            phase="auto",
            only=act.get("channel"),
        )
    elif kind == "page_oncall":
        from .chatops import page_oncall

        await page_oncall(inc, settings, reason="automation rule")
    elif kind == "webhook":
        from .config import WebhookCfg
        from .integrations.outbound import emit

        s2 = settings.model_copy(
            update={
                "webhooks": [
                    WebhookCfg(
                        name=act.get("name", "automation"),
                        url=act["url"],
                        secret_env=act.get("secret_env", ""),
                        events=["automation"],
                        min_band="low",
                    )
                ]
            }
        )
        await emit("automation", inc, s2)
    elif kind == "jira":
        from .integrations.outbound import _jira

        s2 = settings.model_copy(update={"jira": settings.jira.model_copy(update={"enabled": True, "min_band": "low"})})
        await _jira(inc, s2)

"""NIS2 early-warning drafting aid (master prompt 2.9). Never sends anything to the CCB.

Deadlines follow NIS2 Article 23: early warning within 24 h of becoming aware, incident notification
within 72 h, final report within one month. Sieve uses ``opened_at`` as the awareness time; the user
must confirm it. The draft text may come from the LLM (fenced, labelled "draft for human review") or
from a rule-based template when no model answers.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends

from .. import runtime
from ..auth import analyst, audit
from ..llm.client import complete_json
from ..llm.fence import masker_for, task_prompt
from ..llm.validate import _clean
from ..models import aware
from ..pipeline.facts import facts
from ..pipeline.tripwire import scan
from .common import SessionLocal, get_incident

router = APIRouter(tags=["NIS2"])
LABEL = "DRAFT FOR HUMAN REVIEW. Not sent anywhere. Check every fact before you submit it."
IMPACT = {"critical": "Possible unauthorised access to a critical system; impact on services not yet known.",
          "high": "Suspicious activity on a business system; no confirmed service impact yet.",
          "medium": "Attempted attack; no evidence of compromise so far.",
          "low": "Low-risk event; probably not reportable."}
_SCHEMA = '{"draft_text": "<4-8 plain sentences for an early warning>"}'


def _template(d: dict) -> str:
    return (f"On {d['incident_date']} our monitoring detected: {d['title']}. Affected system(s): "
            f"{', '.join(d['affected_systems']) or 'under investigation'}. Initial indicators: "
            f"{'; '.join(d['initial_indicators']) or 'none recorded'}. {d['estimated_impact']} We are investigating "
            "and will send a full incident notification within 72 hours. We do not yet know whether the incident "
            "was caused by unlawful or malicious acts, or whether it has cross-border impact.")


@router.get("/api/incidents/{inc_id}/nis2-draft")
async def nis2_draft(inc_id: int, user=Depends(analyst)):
    s = runtime.current()
    with SessionLocal() as db:
        i = get_incident(db, inc_id)
        opened = aware(i.opened_at)
        d = {"incident_id": i.id, "title": i.title, "band": i.band,
             "incident_date": opened.strftime("%Y-%m-%d %H:%M UTC"),
             "affected_systems": [i.agent_name] if i.agent_name else [],
             "estimated_impact": IMPACT.get(i.band, IMPACT["low"]),
             "initial_indicators": [x for x in [f"source IP {i.srcip}" if i.srcip else None,
                                                f"account {i.user}" if i.user else None,
                                                *[f"ATT&CK {t}" for t in i.techniques[:5]]] if x],
             "reporting_deadline": (opened + timedelta(hours=24)).isoformat(),
             "notification_deadline": (opened + timedelta(hours=72)).isoformat(),
             "final_report_deadline": (opened + timedelta(days=30)).isoformat(),
             "facts": [f["text"] for f in facts(i)]}
        users, hosts = {i.user or ""}, {i.agent_name or ""}
    text, source = _template(d), "template"

    def build(is_cloud: bool):
        trusted = {k: d[k] for k in ("band", "incident_date", "affected_systems", "estimated_impact",
                                     "initial_indicators", "facts")}
        return task_prompt("Write a short, factual NIS2 early-warning draft for the national CSIRT. Use only "
                           "the trusted facts. Do not speculate about the attacker. Say what is not yet known.",
                           _SCHEMA, trusted, {"incident.title": d["title"]},
                           masker_for(is_cloud, s.llm.mask_for_cloud, users, hosts))

    ans = await complete_json(build, s, purpose="nis2", incident_id=inc_id)
    if ans:
        cand = _clean(ans.data.get("draft_text"), 3000)
        if cand and not scan({"model.nis2": cand}).triggered:
            text, source = cand, f"{ans.provider} ({ans.model})"
    audit(user.username, "nis2.draft", f"INC-{inc_id}", source=source)
    return {**{k: v for k, v in d.items() if k != "facts"}, "draft_text": text, "draft_source": source,
            "label": LABEL, "sent": False}

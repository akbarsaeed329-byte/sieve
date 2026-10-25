"""Phase-2 explanation: gated, fenced, validated. Never changes severity (contract 1)."""
from __future__ import annotations

import json
import logging

from ..config import Settings
from ..db import SessionLocal
from ..models import Explanation, Incident
from ..pipeline import playbooks
from ..pipeline.facts import evidence_refs, facts
from .client import complete_json
from .fence import build_prompt, masker_for
from .validate import validate

log = logging.getLogger("sieve.llm.explain")


def gather(inc: Incident) -> dict:
    """Split an incident into trusted facts and untrusted text (first value seen per field path)."""
    alerts = list(inc.alerts)
    sample = alerts[:15] + alerts[-5:] if len(alerts) > 20 else alerts
    summary = [{"ref": f"alert:{a.id}", "rule_id": a.rule_id, "level": a.level, "time": a.timestamp.isoformat(),
                "groups": a.groups[:8], "srcip": a.srcip, "user": a.user, "host": a.agent_name,
                "attack_ids": a.mitre_ids[:5]} for a in sample]
    untrusted: dict[str, str] = {}
    for a in alerts:
        for k, v in (a.untrusted or {}).items():
            key = f"alert:{a.id}:{k}" if k in untrusted else k
            if k not in untrusted or (inc.tripwire and any(h.get("alert_id") == a.id for h in inc.tripwire_hits)):
                untrusted.setdefault(key, v)
        if len(untrusted) > 40:
            break
    pb = playbooks.render(inc.playbook, inc.user, inc.srcip, inc.agent_name) or {"steps": []}
    return {"summary": summary, "untrusted": untrusted,
            "context": {"facts": [f["text"] for f in facts(inc)], "alert_count": inc.alert_count,
                        "tactics": inc.tactics, "techniques": inc.techniques,
                        "overrides": inc.overrides, "playbook": pb.get("title")},
            "steps": [s["id"] for s in pb["steps"]],
            "known_ips": {a.srcip for a in alerts if a.srcip} | ({inc.srcip} if inc.srcip else set()),
            "users": {a.user for a in alerts if a.user}, "hosts": {inc.agent_name} if inc.agent_name else set()}


async def explain_incident(inc_id: int, settings: Settings) -> dict | None:
    with SessionLocal() as db:
        inc = db.get(Incident, inc_id)
        if inc is None:
            return None
        g = gather(inc)
        refs = evidence_refs(inc)
        score, band, breakdown = inc.score, inc.band, inc.breakdown

    def build(is_cloud: bool):
        m = masker_for(is_cloud, settings.llm.mask_for_cloud, g["users"], g["hosts"])
        return build_prompt(inc_id, score, band, breakdown, g["summary"], g["untrusted"], refs, g["steps"],
                            masker=m, context=g["context"])

    ans = await complete_json(build, settings, purpose="summary", incident_id=inc_id)
    if ans is None:
        return None
    trusted_text = json.dumps({"s": g["summary"], "c": g["context"], "score": score}, default=str)
    v = validate(ans.data, refs, playbooks.ids(), known_ips=g["known_ips"], trusted_text=trusted_text,
                 allowed_steps=set(g["steps"]), untrusted=g["untrusted"])
    v["provider"], v["model"] = ans.provider, ans.model
    with SessionLocal() as db:
        db.add(Explanation(incident_id=inc_id, kind="summary", provider=ans.provider, model=ans.model, summary=v,
                           validation=v["validation"], hypotheses=v["hypotheses"], latency_ms=ans.latency_ms,
                           tokens=ans.tokens, prompt_hash=ans.prompt.digest))
        db.commit()
    return v

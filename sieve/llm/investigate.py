"""Hypothesis investigation for critical incidents (research doc 6.6, master prompt 2.6).

Bounded and read-only:
* The model chooses only a template NAME from TEMPLATES and an entity KEY (ip | user | host). The
  values are filled by Sieve from the incident's validated entities; the model never writes a query.
* Hard stop at MAX_LLM_CALLS model calls per investigation; ``steps_taken`` and ``budget_hit`` stored.
* Query results contain log data, so they are passed back to the model inside the ATTACKER_DATA fence.
* With no AI, every template still runs once and the checks are shown without a verdict.
* Severity is never changed by anything here.

Backends: the Wazuh indexer (OpenSearch DSL) when configured, otherwise Sieve's own alert store.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from sqlalchemy import select

from ..config import Settings
from ..db import SessionLocal
from ..errors import SieveError
from ..integrations import wazuh
from ..models import Alert, Baseline, Explanation, Incident, aware
from .client import complete_json
from .fence import masker_for, task_prompt
from .validate import _clean

log = logging.getLogger("sieve.llm.investigate")
MAX_LLM_CALLS = 6

TEMPLATES: dict[str, dict] = {
    "FIRST_SEEN_LOGIN": {"needs": ("user", "host"),
                         "question": "Has this user logged in to this host from this source before (14 days)?"},
    "HOST_ACTIVITY_NEXT_HOUR": {"needs": ("host",),
                                "question": "What else happened on the host in the hour after the incident?"},
    "OTHER_HOSTS_SAME_IP": {"needs": ("ip",), "question": "Did the same source IP touch any other host (24 h)?"},
    "RECENT_ALERTS_SAME_USER": {"needs": ("user",), "question": "What other alerts mention this user (24 h)?"},
    "SCHEDULED_JOBS_ON_HOST": {"needs": ("host",),
                               "question": "Did a scheduled job or cron task run on the host (24 h)?"},
}
SCHED_GROUPS = {"cron", "crond", "scheduled_task", "schtasks", "systemd_timer"}


def entities(inc: Incident) -> dict:
    return {"ip": inc.srcip, "user": inc.user, "host": inc.agent_name}


def validate_call(name: str, ents: dict) -> dict:
    if name not in TEMPLATES:
        raise SieveError("SIEVE-INV-422", f"Unknown query template {name!r}.", status=422)
    params = {k: ents.get(k) for k in TEMPLATES[name]["needs"]}
    if not all(params.values()):
        raise SieveError("SIEVE-INV-422", f"{name} needs {', '.join(TEMPLATES[name]['needs'])}.", status=422)
    return params


def _rows(alerts: list[Alert]) -> list[dict]:
    return [{"ref": f"alert:{a.id}", "time": aware(a.timestamp).isoformat(), "host": a.agent_name, "rule": a.rule_id,
             "level": a.level, "srcip": a.srcip, "user": a.user, "description": a.description[:160]}
            for a in alerts[:20]]


def _local(name: str, p: dict, inc: Incident) -> dict:
    t0, t1 = aware(inc.first_seen), aware(inc.last_seen)
    with SessionLocal() as db:
        if name == "FIRST_SEEN_LOGIN":
            ent = f"user:{p['user']}@{p['host']}"
            rows = db.scalars(select(Baseline).where(Baseline.entity == ent)).all()
            prior = [{"source": b.feature, "first_seen": aware(b.first_seen).isoformat(), "count": b.count}
                     for b in rows if aware(b.first_seen) < t0 - timedelta(seconds=1)]
            return {"count": len(prior), "rows": prior[:20]}
        q = select(Alert).order_by(Alert.timestamp)
        if name == "HOST_ACTIVITY_NEXT_HOUR":
            q = q.where(Alert.agent_name == p["host"], Alert.timestamp > t1, Alert.timestamp <= t1 + timedelta(hours=1))
        elif name == "OTHER_HOSTS_SAME_IP":
            q = q.where(Alert.srcip == p["ip"], Alert.agent_name != inc.agent_name,
                        Alert.timestamp >= t0 - timedelta(hours=24), Alert.timestamp <= t1 + timedelta(hours=1))
        elif name == "RECENT_ALERTS_SAME_USER":
            q = q.where(Alert.user == p["user"], Alert.incident_id != inc.id,
                        Alert.timestamp >= t0 - timedelta(hours=24))
        elif name == "SCHEDULED_JOBS_ON_HOST":
            q = q.where(Alert.agent_name == p["host"], Alert.timestamp >= t0 - timedelta(hours=24))
        rows = list(db.scalars(q.limit(500)).all())
        if name == "SCHEDULED_JOBS_ON_HOST":
            rows = [a for a in rows if SCHED_GROUPS & set(a.groups) or any(t.startswith("T1053") for t in a.mitre_ids)]
        return {"count": len(rows), "rows": _rows(rows)}


def dsl(name: str, p: dict, inc: Incident) -> dict:
    """The exact indexer query for a template (also shown to the user as "Show query")."""
    t0, t1 = aware(inc.first_seen), aware(inc.last_seen)
    must: list[dict] = []
    must_not: list[dict] = []
    rng = {"gte": (t0 - timedelta(hours=24)).isoformat(), "lte": (t1 + timedelta(hours=1)).isoformat()}
    if name == "FIRST_SEEN_LOGIN":
        must += [{"term": {"agent.name": p["host"]}}, {"term": {"data.dstuser": p["user"]}},
                 {"terms": {"rule.groups": ["authentication_success"]}}]
        rng = {"gte": (t0 - timedelta(days=14)).isoformat(), "lt": t0.isoformat()}
    elif name == "HOST_ACTIVITY_NEXT_HOUR":
        must.append({"term": {"agent.name": p["host"]}})
        rng = {"gt": t1.isoformat(), "lte": (t1 + timedelta(hours=1)).isoformat()}
    elif name == "OTHER_HOSTS_SAME_IP":
        must.append({"term": {"data.srcip": p["ip"]}})
        must_not.append({"term": {"agent.name": inc.agent_name or ""}})
    elif name == "RECENT_ALERTS_SAME_USER":
        must.append({"term": {"data.dstuser": p["user"]}})
    elif name == "SCHEDULED_JOBS_ON_HOST":
        must += [{"term": {"agent.name": p["host"]}},
                 {"bool": {"should": [{"terms": {"rule.groups": sorted(SCHED_GROUPS)}},
                                      {"prefix": {"rule.mitre.id": "T1053"}}], "minimum_should_match": 1}}]
    must.append({"range": {"timestamp": rng}})
    return {"size": 20, "sort": [{"timestamp": "asc"}], "query": {"bool": {"must": must, "must_not": must_not}}}


async def run_template(name: str, inc: Incident, settings: Settings) -> dict:
    p = validate_call(name, entities(inc))
    body = dsl(name, p, inc)
    result: dict
    source = "sieve"
    if settings.wazuh.indexer_url:
        try:
            j = await wazuh.indexer_search(settings, body)
            hits = (j.get("hits") or {}).get("hits") or []
            total = ((j.get("hits") or {}).get("total") or {}).get("value", len(hits))
            result = {"count": int(total), "rows": [{"time": h["_source"].get("timestamp"),
                                                     "host": (h["_source"].get("agent") or {}).get("name"),
                                                     "rule": (h["_source"].get("rule") or {}).get("id"),
                                                     "description": str((h["_source"].get("rule") or {})
                                                                        .get("description", ""))[:160]}
                                                    for h in hits]}
            source = "wazuh-indexer"
        except SieveError as e:
            log.warning("indexer query failed, using local store", extra={"code": e.code})
            result = _local(name, p, inc)
    else:
        result = _local(name, p, inc)
    return {"template": name, "question": TEMPLATES[name]["question"], "params": p, "source": source,
            "query": json.dumps(body), **result}


_SCHEMA = """{
  "hypotheses": [{"name": "<short label>", "status": "supported|refuted|inconclusive", "evidence": ["<reason>"]}],
  "next_template": "<one of allowed_templates, or STOP>"
}"""


async def investigate(inc_id: int, settings: Settings) -> dict | None:
    with SessionLocal() as db:
        inc = db.get(Incident, inc_id)
        if inc is None or inc.band != "critical":
            return None
        db.expunge_all()
    steps: list[dict] = []
    ran: set[str] = set()
    for name in TEMPLATES:  # deterministic checks first: useful with or without a model
        try:
            steps.append(await run_template(name, inc, settings))
            ran.add(name)
        except SieveError:
            continue
    hypotheses: list[dict] = []
    calls, budget_hit, provider, model = 0, False, "rules", ""
    ents = entities(inc)
    while settings.llm.enabled:
        if calls >= MAX_LLM_CALLS:
            budget_hit = True
            break
        trusted = {"incident": {"title_rule_based": True, "band": inc.band, "score": inc.score,
                                "tactics": inc.tactics, "overrides": inc.overrides, "alert_count": inc.alert_count},
                   "entities": {k: bool(v) for k, v in ents.items()}, "allowed_templates": sorted(TEMPLATES),
                   "templates_already_run": sorted(ran), "current_hypotheses": hypotheses,
                   "step": calls + 1, "max_steps": MAX_LLM_CALLS}
        untrusted = {f"result:{s['template']}": json.dumps({"count": s["count"], "rows": s["rows"][:8]},
                                                           default=str)[:900] for s in steps}

        def build(is_cloud: bool, trusted=trusted, untrusted=untrusted):
            m = masker_for(is_cloud, settings.llm.mask_for_cloud, {inc.user or ""}, {inc.agent_name or ""})
            return task_prompt("Propose 2-3 competing explanations for this incident and judge each against the "
                               "read-only check results. Then pick one more check from allowed_templates or STOP.",
                               _SCHEMA, trusted, untrusted, m)

        ans = await complete_json(build, settings, purpose="investigate", incident_id=inc_id)
        calls += 1
        if ans is None:
            break
        provider, model = ans.provider, ans.model
        hyps = []
        for h in (ans.data.get("hypotheses") or [])[:4]:
            if isinstance(h, dict) and h.get("status") in ("supported", "refuted", "inconclusive"):
                ev = h.get("evidence") or []
                hyps.append({"name": _clean(h.get("name"), 120), "status": h["status"],
                             "evidence": [_clean(e, 240) for e in (ev if isinstance(ev, list) else [ev])[:4]]})
        if hyps:
            hypotheses = hyps
        nxt = str(ans.data.get("next_template") or "STOP")
        sup = [h for h in hypotheses if h["status"] == "supported"]
        if nxt == "STOP" or nxt in ran or nxt not in TEMPLATES or (len(sup) == 1 and len(hypotheses) > 1):
            break
        try:
            steps.append(await run_template(nxt, inc, settings))
            ran.add(nxt)
        except SieveError:
            break
    result = {"hypotheses": hypotheses, "steps": steps, "steps_taken": calls, "budget_hit": budget_hit,
              "checks_run": len(steps), "provider": provider}
    with SessionLocal() as db:
        db.add(Explanation(incident_id=inc_id, kind="investigation", provider=provider, model=model,
                           summary={"checks_run": len(steps)}, validation={}, hypotheses=hypotheses, steps=steps,
                           steps_taken=calls, budget_hit=budget_hit))
        db.commit()
    return result

"""Deterministic, evidence-linked summary. Always available, even with no AI (ADR-002).

Evidence ids: ``alert:<id>`` for log lines, ``context:<kind>`` for enrichment. The same ids are the
only ones the model may cite.
"""
from __future__ import annotations

from ..models import Incident, aware
from .score import BRUTE_GROUPS, SUCCESS_GROUPS


def facts(inc: Incident) -> list[dict]:
    out: list[dict] = []
    alerts = list(inc.alerts)
    fails = [a for a in alerts if BRUTE_GROUPS & set(a.groups)]
    oks = [a for a in alerts if SUCCESS_GROUPS & set(a.groups)]
    if fails:
        secs = int((aware(fails[-1].timestamp) - aware(fails[0].timestamp)).total_seconds())
        who = f" for {fails[0].user}" if fails[0].user else ""
        src = fails[0].srcip or "one source"
        span = f" in {secs} seconds" if len(fails) > 1 and secs > 0 else ""
        noun = "login" if len(fails) == 1 else "logins"
        out.append({"text": f"{len(fails)} {noun}{who} failed from {src}{span} on {inc.agent_name}.",
                    "evidence": [f"alert:{fails[0].id}", f"alert:{fails[-1].id}"]})
    if oks:
        ok = oks[0]
        lead = "Then"
        if fails and aware(ok.timestamp) >= aware(fails[-1].timestamp):
            lead = f"{int((aware(ok.timestamp) - aware(fails[-1].timestamp)).total_seconds())} seconds later,"
        as_user = f" as {ok.user}" if ok.user else ""
        out.append({"text": f"{lead} {ok.srcip or 'the same source'} logged in successfully{as_user}.",
                    "evidence": [f"alert:{ok.id}"]})
    if not out and alerts:
        top = max(alerts, key=lambda x: x.level)
        n = inc.alert_count
        what = (top.description or f"rule {top.rule_id}").strip().rstrip(".")
        out.append({"text": f"{n} {'alert' if n == 1 else 'alerts'} on {inc.agent_name}: {what} "
                            f"(Wazuh rule {top.rule_id}, level {top.level}).", "evidence": [f"alert:{top.id}"]})
    labels = [b["label"] for b in (inc.breakdown or [])]
    if any("threat-intel" in lbl for lbl in labels):
        src = (inc.intel or {}).get("source") or "a configured list"
        out.append({"text": f"{inc.srcip} is on a threat-intel list ({src}).", "evidence": ["context:intel"]})
    if any(lbl.startswith("First-seen") for lbl in labels):
        out.append({"text": "This is first-seen behaviour for this account in the last 14 days.",
                    "evidence": ["context:baseline"]})
    if inc.tripwire:
        fields = sorted({h["field"] for h in inc.tripwire_hits or []})
        out.append({"text": f"Instruction-like text was found in {', '.join(fields)}; it was treated as data.",
                    "evidence": ["context:tripwire"]})
    if inc.partial_context:
        out.append({"text": "Some context sources were unavailable, so this incident has partial context.",
                    "evidence": ["context:partial"]})
    return out


def evidence_refs(inc: Incident) -> list[str]:
    refs = [f"alert:{a.id}" for a in inc.alerts]
    refs += ["context:intel", "context:baseline", "context:tripwire", "context:partial"]
    return refs

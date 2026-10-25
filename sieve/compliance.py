"""Regulatory clocks and evidence packs: NIS2, DORA, GDPR.

Deadlines (all computed from timestamps the team records, defaults from the incident):
* NIS2 Art. 23: early warning 24 h after awareness, notification 72 h, final report one month.
* DORA Art. 19 + RTS 2025/301: initial notification within 4 h of classifying the incident as major and no later
  than 24 h after awareness; intermediate report within 72 h of the initial notification; final report one month
  after the latest intermediate report.
* GDPR Art. 33: notify the supervisory authority within 72 h of becoming aware of a personal-data breach.
The DORA classification helper follows RTS 2024/1772: an incident is major when it affects critical services and
either involves malicious unauthorised access with data loss, or meets at least two other criteria. Sieve only
suggests; the organisation decides and records its decision with a timestamp.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import zipfile
from datetime import datetime, timedelta

from .models import Incident, aware, utcnow

DORA_CRITERIA = {
    "critical_services": "Critical or important functions/services affected",
    "clients": "Clients, counterparties or transactions affected above threshold",
    "reputational": "Reputational impact (media, complaints, regulatory attention)",
    "duration": "Duration or service downtime above threshold",
    "geographical": "Impact in two or more EU member states",
    "data_losses": "Data losses (availability, authenticity, integrity or confidentiality)",
    "economic": "Economic impact above threshold",
}


def _ts(v) -> datetime | None:
    if not v:
        return None
    return aware(datetime.fromisoformat(str(v).replace("Z", "+00:00")))


def dora_suggestion(criteria: dict, malicious_access_with_loss: bool) -> dict:
    met = [k for k, v in (criteria or {}).items() if v and k in DORA_CRITERIA]
    others = [k for k in met if k != "critical_services"]
    major = "critical_services" in met and (malicious_access_with_loss or len(others) >= 2)
    why = (
        (
            "Critical services affected and "
            + ("malicious access with data loss" if malicious_access_with_loss else f"{len(others)} other criteria met")
        )
        if major
        else (
            "Critical services not marked as affected"
            if "critical_services" not in met
            else f"Only {len(others)} other criterion met"
        )
    )
    return {
        "suggest_major": major,
        "met": met,
        "reason": why,
        "note": "Suggestion based on RTS 2024/1772 criteria. Your organisation's classification decision is what counts.",
    }


def clocks(inc: Incident, regimes) -> dict:
    c = dict(inc.compliance or {})
    aware_at = _ts(c.get("aware_at")) or aware(inc.aware_at) or aware(inc.opened_at)
    now = utcnow()
    out: dict = {"aware_at": aware_at.isoformat(), "regimes": {}}

    def item(name, due, sent_key):
        sent = c.get(sent_key)
        return {
            "name": name,
            "due": due.isoformat() if due else None,
            "sent_at": sent,
            "state": "sent" if sent else ("overdue" if due and now > due else "open"),
            "minutes_left": int((due - now).total_seconds() // 60) if due and not sent else None,
        }

    if regimes.nis2 and c.get("nis2_applies", True):
        out["regimes"]["nis2"] = [
            item("Early warning", aware_at + timedelta(hours=24), "nis2_early_sent"),
            item("Incident notification", aware_at + timedelta(hours=72), "nis2_notification_sent"),
            item("Final report", aware_at + timedelta(days=30), "nis2_final_sent"),
        ]
    if regimes.dora and c.get("dora_applies", True):
        classified = _ts(c.get("dora_classified_major_at"))
        if classified:
            initial_due = min(classified + timedelta(hours=4), aware_at + timedelta(hours=24))
            initial_sent = _ts(c.get("dora_initial_sent"))
            inter_due = (initial_sent or initial_due) + timedelta(hours=72)
            inter_sent = _ts(c.get("dora_intermediate_sent"))
            out["regimes"]["dora"] = [
                item("Initial notification", initial_due, "dora_initial_sent"),
                item("Intermediate report", inter_due, "dora_intermediate_sent"),
                item("Final report", (inter_sent or inter_due) + timedelta(days=30), "dora_final_sent"),
            ]
        else:
            out["regimes"]["dora"] = [
                {
                    "name": "Classify the incident (major or not)",
                    "due": (aware_at + timedelta(hours=24)).isoformat(),
                    "state": "overdue" if now > aware_at + timedelta(hours=24) else "open",
                    "sent_at": None,
                    "minutes_left": int((aware_at + timedelta(hours=24) - now).total_seconds() // 60),
                    "hint": "Classification must be fast: the 24-hour cap from awareness applies even if you classify late.",
                }
            ]
        out["dora_assessment"] = dora_suggestion(c.get("dora_criteria") or {}, bool(c.get("dora_malicious_loss")))
    if regimes.gdpr and c.get("personal_data"):
        breach = _ts(c.get("gdpr_aware_at")) or aware_at
        out["regimes"]["gdpr"] = [item("Notify the data protection authority", breach + timedelta(hours=72), "gdpr_dpa_sent")]
    out["record"] = c
    return out


def report_markdown(inc: Incident, trace: dict, comp: dict | None) -> str:
    """Human-readable investigation report for tickets, auditors and customers."""
    L = [
        f"# INC-{inc.id:04d}: {inc.title}",
        "",
        f"**Severity:** {inc.band} (score {round(inc.score or 0)}) · **Status:** {inc.status} · **Host:** {inc.agent_name} · "
        f"**Source:** {inc.srcip or '-'} · **User:** {inc.user or '-'} · **Alerts:** {inc.alert_count}",
        f"**Opened:** {aware(inc.opened_at).isoformat()} · **Owner:** {inc.assignee or 'unassigned'}",
        "",
        "## What happened",
    ]
    ai = next((x for x in reversed(trace.get("ai", [])) if x["kind"] == "summary" and x["kept_sentences"]), None)
    from .pipeline.facts import facts

    sents = [s["text"] for s in ai["kept_sentences"]] if ai else [f["text"] for f in facts(inc)]
    L += [f"- {s}" for s in sents]
    L += ["", "## Why this severity (decided by rules, never by the AI)"]
    L += [f"- {b['label']}: +{round(b['points'])}" for b in inc.breakdown or []]
    L += [f"- Override: {o}" for o in inc.overrides or []]
    if inc.tripwire:
        L += [
            "",
            "## Manipulation attempt",
            "Instruction-like text was found in: "
            + ", ".join(sorted({h["field"] for h in inc.tripwire_hits or []}))
            + ". It was treated as data (MITRE ATLAS AML.T0051).",
        ]
    inv = next((x for x in reversed(trace.get("ai", [])) if x["kind"] == "investigation"), None)
    if inv:
        L += ["", "## Explanations tested"]
        L += [f"- {h['name']}: **{h['status']}** ({'; '.join(h.get('evidence', []))})" for h in inv.get("hypotheses", [])]
        L += [f"- Check `{c['template']}`: {c['count']} result(s)" for c in inv.get("checks", [])]
    L += ["", "## Actions taken"]
    L += [f"- {a['at']} · {a['actor']} · {a['action']}" for a in trace.get("human_actions", [])] or ["- none recorded"]
    if comp and comp.get("regimes"):
        L += ["", "## Regulatory clocks"]
        for reg, items in comp["regimes"].items():
            for it in items:
                L.append(f"- {reg.upper()} · {it['name']}: due {it['due']} · {it['state']}")
    L += ["", "## Evidence", "| Time | Rule | Level | Source | User |", "| --- | --- | --- | --- | --- |"]
    L += [
        f"| {a['time']} | {a['rule_id']} | {a['level']} | {a['validated_entities']['srcip'] or '-'} | "
        f"{a['validated_entities']['user'] or '-'} |"
        for a in trace.get("inputs", [])[:200]
    ]
    L += ["", "_Generated by Sieve. Log fields that may contain attacker-written text are not reproduced in this report._"]
    return "\n".join(L) + "\n"


def evidence_pack(
    inc: Incident, trace: dict, report_md: str, raw_alerts: list[dict], secret: str, actor: str
) -> tuple[bytes, dict]:
    """ZIP with report, decision trace and raw alerts, plus a SHA-256 manifest sealed with an HMAC.
    Anyone holding the server key can verify that no file was changed after export."""
    files = {
        "report.md": report_md.encode(),
        "decision-trace.json": json.dumps(trace, indent=1, default=str).encode(),
        "raw-alerts.jsonl": "\n".join(json.dumps(a, default=str, sort_keys=True) for a in raw_alerts).encode(),
    }
    manifest = {
        "incident": f"INC-{inc.id:04d}",
        "exported_at": utcnow().isoformat(),
        "exported_by": actor,
        "sha256": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
    }
    body = json.dumps(manifest, sort_keys=True).encode()
    manifest["hmac_sha256"] = hmac.new(secret.encode(), b"sieve-evidence:" + body, hashlib.sha256).hexdigest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files.items():
            z.writestr(n, b)
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=1))
    return buf.getvalue(), manifest


def verify_manifest(manifest: dict, files: dict[str, bytes], secret: str) -> bool:
    m = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    ok_hash = all(hashlib.sha256(files[n]).hexdigest() == h for n, h in m["sha256"].items())
    mac = hmac.new(secret.encode(), b"sieve-evidence:" + json.dumps(m, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    return ok_hash and hmac.compare_digest(mac, manifest.get("hmac_sha256", ""))

"""Post-generation validation.  Sentences that cannot be grounded are dropped.
ATT&CK IDs that do not match the pattern are dropped.
Playbook IDs not in the allowed list are dropped.
Severity is NEVER read from the model output.
"""
from __future__ import annotations

import re

_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate(
    raw: dict,
    evidence_refs: list[str],
    allowed_playbooks: list[str],
) -> dict:
    valid_refs = set(evidence_refs)

    # Validate summary sentences — drop any without a valid evidence_ref
    clean_summary = []
    for item in raw.get("summary") or []:
        refs = [r for r in (item.get("evidence_refs") or []) if r in valid_refs]
        if refs:
            clean_summary.append({"text": str(item.get("text", ""))[:500], "evidence_refs": refs})

    # Validate hypotheses
    clean_hyp = []
    for h in raw.get("hypotheses") or []:
        status = h.get("status", "")
        if status not in ("supported", "refuted", "inconclusive"):
            continue
        clean_hyp.append({
            "name": str(h.get("name", ""))[:120],
            "status": status,
            "evidence": [str(e)[:300] for e in (h.get("evidence") or [])[:5]],
        })

    # Validate ATT&CK IDs
    extra_ids = [t for t in (raw.get("extra_attack_ids") or []) if _ATTACK_RE.match(str(t))]

    # Validate playbook IDs
    playbook_ids = [p for p in (raw.get("playbook_ids") or []) if p in allowed_playbooks]

    return {
        "summary": clean_summary,
        "hypotheses": clean_hyp[:4],
        "extra_attack_ids": extra_ids[:10],
        "playbook_ids": playbook_ids,
        "validation": {
            "summary_sentences_kept": len(clean_summary),
            "summary_sentences_dropped": len(raw.get("summary") or []) - len(clean_summary),
            "hypotheses_dropped": len(raw.get("hypotheses") or []) - len(clean_hyp),
            "invalid_attack_ids_dropped": len(raw.get("extra_attack_ids") or []) - len(extra_ids),
        },
    }

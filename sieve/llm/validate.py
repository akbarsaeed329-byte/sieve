"""Post-generation validation (research doc 6.5).  Nothing the model writes reaches a user unchecked.

* Sentences must cite at least one evidence id that exists; otherwise they are dropped.
* Any IP address in a sentence must be one of the incident's known IPs.
* Any number (2 or more) in a sentence must appear somewhere in the trusted prompt data.
* Sentences that themselves look like injected instructions (tripwire rules) are dropped.
* Sentences that repeat a 4-word phrase from an attacker-controlled field that itself trips the
  tripwire are dropped (echo check), so a hijacked model cannot relay the attacker's framing
  ("approved maintenance") to the analyst. Ordinary log text is not treated as an echo source.
* ATT&CK IDs must exist in the official catalogue (llm/attack.py).
* Playbook step IDs must exist in the human-written playbook library.
* Severity is NEVER read from the model output, and no field of it is returned.
"""
from __future__ import annotations

import re

from ..pipeline.tripwire import scan
from .attack import valid_technique

_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_NUM = re.compile(r"(?<![\w.:])\d[\d,]*(?![\w:])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
MAX_SENTENCES = 8


def _clean(text: object, limit: int) -> str:
    return _CTRL.sub("", str(text or "")).strip()[:limit]


def _numbers(text: str) -> set[int]:
    out = set()
    for m in _NUM.findall(text):
        try:
            out.add(int(m.replace(",", "")))
        except ValueError:
            continue
    return out


_WORD = re.compile(r"[a-z0-9]+")


def _ngrams(text: str, n: int = 4) -> set[tuple[str, ...]]:
    w = _WORD.findall(text.lower())
    return {tuple(w[i:i + n]) for i in range(len(w) - n + 1)}


def validate(
    raw: dict,
    evidence_refs: list[str],
    allowed_playbooks: list[str],
    *,
    known_ips: set[str] | None = None,
    trusted_text: str | None = None,
    allowed_steps: set[str] | None = None,
    untrusted: dict[str, str] | None = None,
) -> dict:
    if not isinstance(raw, dict):
        raw = {}
    valid_refs = set(evidence_refs)
    known_numbers = _numbers(trusted_text) if trusted_text is not None else None
    dropped: list[dict] = []
    attacker_grams: set = set()
    for k, v in (untrusted or {}).items():
        if scan({str(k): str(v)}).triggered:
            attacker_grams |= _ngrams(str(v))

    clean_summary = []
    for item in (raw.get("summary") or [])[:20]:
        if not isinstance(item, dict):
            dropped.append({"reason": "not an object"})
            continue
        text = _clean(item.get("text"), 500)
        cited = item.get("evidence_refs") or item.get("evidence") or []
        refs = [str(r) for r in (cited if isinstance(cited, list) else [cited]) if str(r) in valid_refs]
        reason = None
        if not text:
            reason = "empty"
        elif not refs:
            reason = "no valid evidence reference"
        elif known_ips is not None and any(ip not in known_ips for ip in _IP.findall(text)):
            reason = "mentions an IP that is not in the evidence"
        elif known_numbers is not None and any(n >= 2 and n not in known_numbers for n in _numbers(text)):
            reason = "states a number that is not in the evidence"
        elif scan({"model.summary": text}).triggered:
            reason = "sentence looks like an injected instruction"
        elif attacker_grams and _ngrams(text) & attacker_grams:
            reason = "sentence repeats attacker-controlled text"
        if reason:
            dropped.append({"text": text[:160], "reason": reason})
            continue
        clean_summary.append({"text": text, "evidence_refs": refs[:6]})
        if len(clean_summary) >= MAX_SENTENCES:
            break

    clean_hyp = []
    for h in (raw.get("hypotheses") or [])[:8]:
        if not isinstance(h, dict) or h.get("status") not in ("supported", "refuted", "inconclusive"):
            continue
        name = _clean(h.get("name"), 120)
        if not name or scan({"model.hypothesis": name}).triggered:
            continue
        ev = h.get("evidence") or []
        clean_hyp.append({"name": name, "status": h["status"],
                          "evidence": [_clean(e, 300) for e in (ev if isinstance(ev, list) else [ev])[:5]]})

    ids_in = [str(t) for t in (raw.get("extra_attack_ids") or []) if isinstance(t, str | int)]
    extra_ids = sorted({t for t in ids_in if valid_technique(t)})

    steps_in = raw.get("playbook_steps") or []
    steps = [s for s in steps_in if isinstance(s, str) and allowed_steps is not None and s in allowed_steps]
    playbook_ids = [p for p in (raw.get("playbook_ids") or []) if p in allowed_playbooks]

    return {
        "summary": clean_summary,
        "hypotheses": clean_hyp[:4],
        "extra_attack_ids": extra_ids[:10],
        "playbook_steps": steps[:10],
        "playbook_ids": playbook_ids,
        "validation": {
            "summary_sentences_kept": len(clean_summary),
            "summary_sentences_dropped": len(dropped),
            "dropped": dropped[:10],
            "hypotheses_dropped": len(raw.get("hypotheses") or []) - len(clean_hyp),
            "invalid_attack_ids_dropped": len(ids_in) - len(extra_ids),
            "invalid_playbook_steps_dropped": len(steps_in) - len(steps),
        },
    }

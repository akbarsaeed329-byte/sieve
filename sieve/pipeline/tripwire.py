"""Injection tripwire — scan untrusted fields BEFORE any LLM call.

Design contract
---------------
* Transparent rules only (v0).  Every hit is logged with the reason,
  field path, score and a capped excerpt.  No silent matching.
* A field score is the sum of matching rule weights.
  The alert score is the maximum across all untrusted fields.
* Hitting the threshold raises its own Sieve alert tagged
  MITRE ATLAS AML.T0051 (LLM Prompt Injection).
* Because the LLM never decides severity, a successful injection can
  only affect the wording of a summary, not the band or the action.
* Benchmark every rule change on the PoisonedLogs dataset.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# (label, weight, compiled pattern)
RULES: list[tuple[str, float, re.Pattern]] = [
    ("override instruction", 1.0, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}"
        r"\b(previous|prior|earlier|above|all|instructions?)\b", re.I)),
    ("verdict steering", 1.0, re.compile(
        r"\b(mark|classif|treat|label|flag|consider|report|deem|categori[sz])\w*\b.{0,50}"
        r"\b(benign|false[ -]?positive|safe|harmless|low\s+(severity|priority)|"
        r"approved|maintenance|authori[sz]ed)\b", re.I)),
    ("role marker", 0.8, re.compile(
        r"(\[\s*(soc|admin|system|assistant|analyst|security\s+team)[^\]]{0,30}\]"
        r"|(?:^|\s)(system|assistant|developer)\s*:)", re.I | re.M)),
    ("prompt structure", 0.8, re.compile(
        r"(<\|im_(start|end)\|>|</?\s*(system|instructions?|prompt)\s*>"
        r"|###\s*(instruction|system)"
        r"|\byou\s+are\s+(an?\s+|the\s+)?[a-z ]{0,30}(assistant|analyst|model)\b"
        r"|\bnew\s+instructions?\b)", re.I)),
    ("addressed to AI", 0.4, re.compile(
        r"\b(llm|language\s+model|chatgpt|gpt[-\s]?[34o]|claude|copilot|gemini|"
        r"llama|mistral|ai\s+assistant)\b", re.I)),
    ("long base64 run", 0.4, re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")),
    ("jailbreak phrase", 0.9, re.compile(
        r"\b(dan|do anything now|jailbreak|jail\s*break|in this mode|"
        r"pretend\s+(you\s+are|to\s+be)|act\s+as\s+(if\s+you\s+(are|were)|an?))\b", re.I)),
]

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")


def _mixed_script_word(word: str) -> bool:
    scripts: set[str] = set()
    for ch in word:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split()[0] if name else "UNKNOWN")
    return "LATIN" in scripts and bool({"CYRILLIC", "GREEK"} & scripts)


def _has_mixed_script(text: str) -> bool:
    return any(_mixed_script_word(w) for w in re.findall(r"\w{3,}", text))


@dataclass
class TripwireResult:
    score: float = 0.0
    hits: list[dict] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return bool(self.hits)


def scan(untrusted: dict[str, str], threshold: float = 1.0) -> TripwireResult:
    result = TripwireResult()
    for path, value in untrusted.items():
        text = value[:5000]
        reasons, score = [], 0.0
        for label, weight, rx in RULES:
            if rx.search(text):
                reasons.append(label)
                score += weight
        if _INVISIBLE.search(text):
            reasons.append("invisible unicode")
            score += 0.7
        if _has_mixed_script(text):
            reasons.append("mixed-script homoglyphs")
            score += 0.5
        result.score = max(result.score, score)
        if score >= threshold:
            result.hits.append({
                "field": path,
                "score": round(score, 2),
                "reasons": reasons,
                "excerpt": text[:240],
                "atlas": "AML.T0051",
            })
    return result

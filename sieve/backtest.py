"""Detection-rule backtest (master prompt 3.1).

Accepts a Sigma rule (subset: ``detection`` with named selections of field: value, the modifiers
contains / startswith / endswith / re, lists meaning OR, and a condition made of selection names
with and / or / not / 1 of / all of) or a single Wazuh <rule> element (if_sid, match, regex, field,
srcip, user, group). Replays it over alerts and suppressed alerts Sieve has stored and reports how
often it would have fired, how many hits belong to incidents a human confirmed versus marked false
positive, and which incidents it would have caught. It never deploys anything.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import timedelta

import yaml
from sqlalchemy import select

from .db import SessionLocal
from .errors import RULE_PARSE, SieveError
from .models import Alert, Incident, Suppression, utcnow

SIGMA_FIELDS = {"User": "data.dstuser", "TargetUserName": "data.win.eventdata.targetUserName",
                "CommandLine": "data.win.eventdata.commandLine", "Image": "data.win.eventdata.image",
                "SourceIp": "data.srcip", "src_ip": "data.srcip", "cs-uri-query": "data.url",
                "c-useragent": "data.http_user_agent"}


def _dig(d: dict, path: str):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _match_value(actual, expected, mod: str | None) -> bool:
    if actual is None:
        return False
    values = actual if isinstance(actual, list) else [actual]
    exp = str(expected).lower()
    for v in values:
        s = str(v).lower()
        if (mod == "contains" and exp in s) or (mod == "startswith" and s.startswith(exp)) or \
                (mod == "endswith" and s.endswith(exp)) or (mod is None and s == exp):
            return True
        if mod == "re":
            try:
                if re.search(str(expected), str(v)):
                    return True
            except re.error:
                return False
    return False


def _selection(spec) -> Callable[[dict], bool]:
    if isinstance(spec, list):  # list of maps = OR
        subs = [_selection(s) for s in spec]
        return lambda raw: any(f(raw) for f in subs)
    if not isinstance(spec, dict):
        raise SieveError(RULE_PARSE, "Each Sigma selection must be a map of field: value.", status=422)
    checks = []
    for key, val in spec.items():
        field, _, mod = str(key).partition("|")
        path = SIGMA_FIELDS.get(field, field)
        vals = val if isinstance(val, list) else [val]
        checks.append((path, mod or None, vals))
    return lambda raw: all(any(_match_value(_dig(raw, p), v, m) for v in vs) for p, m, vs in checks)


def _condition(cond: str, sels: dict[str, Callable]) -> Callable[[dict], bool]:
    tokens = re.findall(r"\(|\)|\w[\w*]*", cond)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def take():
        pos[0] += 1
        return tokens[pos[0] - 1]

    def names(pattern: str) -> list[Callable]:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        found = [f for n, f in sels.items() if rx.match(n)]
        if not found:
            raise SieveError(RULE_PARSE, f"Condition refers to unknown selection '{pattern}'.", status=422)
        return found

    def atom():
        t = take() if peek() else None
        if t == "(":
            f = expr()
            take()
            return f
        if t == "not":
            f = atom()
            return lambda r: not f(r)
        if t in ("1", "all") and peek() == "of":
            take()
            fs = names(take())
            return (lambda r: any(g(r) for g in fs)) if t == "1" else (lambda r: all(g(r) for g in fs))
        if t is None:
            raise SieveError(RULE_PARSE, "The Sigma condition is incomplete.", status=422)
        return names(t)[0]

    def term():
        f = atom()
        while peek() == "and":
            take()
            g = atom()
            f = (lambda a, b: lambda r: a(r) and b(r))(f, g)
        return f

    def expr():
        f = term()
        while peek() == "or":
            take()
            g = term()
            f = (lambda a, b: lambda r: a(r) or b(r))(f, g)
        return f

    return expr()


def compile_sigma(text: str) -> tuple[str, Callable[[dict], bool]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SieveError(RULE_PARSE, "The rule is not valid YAML.", status=422) from e
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        raise SieveError(RULE_PARSE, "A Sigma rule needs a 'detection' section.", status=422)
    det = dict(doc["detection"])
    cond = str(det.pop("condition", "selection"))
    sels = {k: _selection(v) for k, v in det.items() if k != "timeframe"}
    return str(doc.get("title") or "Sigma rule"), _condition(cond, sels)


def compile_wazuh(text: str) -> tuple[str, Callable[[dict], bool]]:
    try:
        el = ET.fromstring(text.strip())
    except ET.ParseError as e:
        raise SieveError(RULE_PARSE, "The Wazuh rule is not valid XML.", status=422) from e
    if el.tag != "rule":
        raise SieveError(RULE_PARSE, "Paste a single <rule> element.", status=422)
    checks: list[Callable[[dict], bool]] = []
    for c in el:
        txt = (c.text or "").strip()
        if c.tag == "if_sid":
            sids = {s.strip() for s in re.split(r"[ ,]+", txt) if s.strip()}
            checks.append(lambda r, s=sids: str(_dig(r, "rule.id")) in s)
        elif c.tag == "match":
            checks.append(lambda r, t=txt: t.lower() in str(r.get("full_log", "")).lower())
        elif c.tag in ("regex", "field"):
            path = "full_log" if c.tag == "regex" else "data." + c.get("name", "")
            try:
                rx = re.compile(txt)
            except re.error as e:
                raise SieveError(RULE_PARSE, f"Bad regex in <{c.tag}>.", status=422) from e
            checks.append(lambda r, p=path, x=rx: bool(x.search(str(_dig(r, p) or ""))))
        elif c.tag == "srcip":
            checks.append(lambda r, t=txt: str(_dig(r, "data.srcip") or "") == t)
        elif c.tag == "user":
            checks.append(lambda r, t=txt: str(_dig(r, "data.dstuser") or "").lower() == t.lower())
        elif c.tag == "group":
            gs = {g for g in txt.split(",") if g}
            checks.append(lambda r, g=gs: bool(g & set(_dig(r, "rule.groups") or [])))
    if not checks:
        raise SieveError(RULE_PARSE, "The rule has no conditions Sieve can test.", status=422)
    desc = el.findtext("description") or f"Wazuh rule {el.get('id', '')}"
    return desc, lambda r: all(f(r) for f in checks)


def backtest(text: str, days: int = 30) -> dict:
    title, fn = compile_wazuh(text) if text.lstrip().startswith("<") else compile_sigma(text)
    since = utcnow() - timedelta(days=days)
    hits_alert, incs, hits_supp = [], {}, 0
    with SessionLocal() as db:
        for a in db.scalars(select(Alert).where(Alert.timestamp >= since)).yield_per(500):
            if fn(a.raw or {}):
                hits_alert.append(a.id)
                if a.incident_id:
                    incs.setdefault(a.incident_id, 0)
                    incs[a.incident_id] += 1
        for s in db.scalars(select(Suppression).where(Suppression.created_at >= since)).yield_per(500):
            if s.raw and fn(s.raw):
                hits_supp += 1
        rows = db.scalars(select(Incident).where(Incident.id.in_(list(incs)))).all() if incs else []
    fp = [i for i in rows if i.status == "false_positive"]
    real = [i for i in rows if i.status in ("resolved", "acknowledged", "new") and i.band in ("high", "critical")]
    total = len(hits_alert) + hits_supp
    return {"title": title, "days": days, "would_fire": total, "on_kept_alerts": len(hits_alert),
            "on_suppressed_alerts": hits_supp, "incidents_touched": len(rows),
            "pct_in_false_positives": round(100 * len(fp) / len(rows), 1) if rows else 0.0,
            "pct_benign": round(100 * (hits_supp + sum(incs[i.id] for i in fp)) / total, 1) if total else 0.0,
            "would_have_caught": [{"id": i.id, "title": i.title, "band": i.band} for i in real][:20],
            "note": "Backtest only. Sieve never deploys rules; copy it into Wazuh yourself after review."}

"""Background triage worker: reads the durable queue and runs each alert through the pipeline.

Contracts kept here (MASTER_AI_PROMPT):
* Alerts are written to ``queue`` BEFORE processing; pending items are replayed after a restart and
  processing is idempotent by wazuh_id (contract 4).
* Severity comes only from pipeline/score.py (contract 1). Tripwire hits are never suppressed (3).
* Phase-1 notification is sent before, and never waits for, any model call; the AI edit and the
  critical-incident investigation run as background tasks (contract 5).
* Every external call (threat intel, notifiers, LLM) is contained; failure means "partial context"
  or "AI summary unavailable", never a lost alert (contract 6).
* One notification per incident per band: a message is sent when an incident first reaches the
  notify band, again only if it escalates, and once more on its first tripwire hit (a manipulation
  attempt is its own alert, research doc 6.4).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from . import plugins, runtime
from .config import Settings
from .db import SessionLocal
from .llm.explain import explain_incident
from .llm.investigate import investigate
from .models import KV, Alert, Baseline, Explanation, Incident, QueueItem, Suppression, aware, utcnow
from .notify.dispatch import edit_with_ai, send_instant
from .pipeline import playbooks
from .pipeline.filter import suppression_reason
from .pipeline.group import OPEN_STATUSES, actor, find_or_create_incident, key_actor
from .pipeline.normalise import NormAlert, normalise
from .pipeline.score import SUCCESS_GROUPS, band_rank, compute_score
from .pipeline.tripwire import scan

log = logging.getLogger("sieve.worker")

NOVELTY_DAYS = 14
MAX_ATTEMPTS = 5
PROCESS_GROUPS = {"sysmon_event1", "sysmon_eid1_detections", "process_creation"}


class Stats:
    """In-process counters for /metrics (history lives in the notifications / llm_calls tables)."""
    alerts = suppressed = duplicates = notifications = notify_failures = 0
    last_alert_at: datetime | None = None
    heartbeat: datetime | None = None
    first_notify_ms: list[int] = []

    @classmethod
    def reset(cls) -> None:
        cls.alerts = cls.suppressed = cls.duplicates = cls.notifications = cls.notify_failures = 0
        cls.last_alert_at = cls.heartbeat = None
        cls.first_notify_ms = []


@dataclass
class Outcome:
    outcome: str                 # duplicate | suppressed | grouped
    incident_id: int | None = None
    band: str | None = None
    notified: bool = False


_tasks: set[asyncio.Task] = set()
_llm_sem = asyncio.Semaphore(2)


def _spawn(coro) -> None:
    t = asyncio.create_task(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def drain() -> None:
    """Wait for background AI tasks (demo, tests, shutdown)."""
    while _tasks:
        await asyncio.gather(*list(_tasks), return_exceptions=True)


def _touch(db, entity: str, feature: str, now: datetime) -> bool:
    """Rolling-window first-seen: True when (entity, feature) was not seen in the last 14 days."""
    row = db.scalar(select(Baseline).where(Baseline.entity == entity, Baseline.feature == feature))
    if row is None:
        db.add(Baseline(entity=entity, feature=feature, first_seen=now, last_seen=now, count=1))
        return True
    novel = now - aware(row.last_seen) > timedelta(days=NOVELTY_DAYS)
    row.last_seen = max(aware(row.last_seen), now)
    row.count = (row.count or 0) + 1
    return novel


def _check_novelty(na: NormAlert, db) -> bool:
    """Master prompt 2.5. Features that raise N (none decides alone):
    * a successful login of user@host from a source IP not seen for that pair in 14 days
    * a process image not seen on that host in 14 days (Sysmon / process-creation events)
    """
    now = na.timestamp
    novel = False
    if SUCCESS_GROUPS & set(na.groups) and na.user and na.srcip:
        novel |= _touch(db, f"user:{na.user}@{na.agent_name}", f"srcip:{na.srcip}", now)
    image = na.untrusted.get("data.win.eventdata.image")
    if image and PROCESS_GROUPS & set(na.groups):
        novel |= _touch(db, f"host:{na.agent_name}", f"process:{image.lower()[:200]}", now)
    return novel


def _static_intel(srcip: str | None, settings: Settings) -> bool:
    return bool(srcip and srcip in set(settings.intel.blocklist_ips))


async def _intel(srcip: str | None, settings: Settings) -> tuple[bool, dict | None, list[str]]:
    """Return (hit, details, context_notes). AbuseIPDB replaces the static list when a key is set."""
    if not srcip:
        return False, None, []
    if _static_intel(srcip, settings):
        return True, {"source": "offline blocklist"}, []
    from .plugins.enrichers import abuseipdb
    if not (plugins.is_enabled(settings, "abuseipdb") and abuseipdb.configured(settings)):
        return False, None, []
    res, error = await plugins.call_safely("abuseipdb", abuseipdb.enrich(srcip, settings), timeout=6)
    if error:
        return False, None, [f"Threat intel unavailable: {error['message']}"]
    min_score = plugins.config(settings, "abuseipdb").get("min_score", settings.intel.abuseipdb_min_score)
    return res["abuse_score"] >= min_score, {"source": "AbuseIPDB", **res}, []


def _continues_open_incident(db, na: NormAlert) -> bool:
    """Context beats level: a low-level event (e.g. the successful login) that continues an open
    incident from the same actor on the same host is kept, so chains are never broken by the filter."""
    rows = db.scalars(select(Incident.grouping_key).where(Incident.status.in_(OPEN_STATUSES),
                                                          Incident.agent_name == na.agent_name)).all()
    return any(key_actor(k) == actor(na) for k in rows) and actor(na) != "unknown"


async def process_alert(payload: dict, settings: Settings, *, bypass_filter: bool = False,
                        received_at: datetime | None = None, selftest: bool = False) -> Outcome:
    received_at = received_at or utcnow()
    na = normalise(payload)
    Stats.last_alert_at = utcnow()
    with SessionLocal() as db:
        if db.scalar(select(Alert.id).where(Alert.wazuh_id == na.wazuh_id)) or (
                not bypass_filter and db.scalar(select(Suppression.id).where(Suppression.wazuh_id == na.wazuh_id))):
            Stats.duplicates += 1
            return Outcome("duplicate")
        tw = scan(na.untrusted, settings.tripwire_threshold)
        reason = None if bypass_filter else suppression_reason(na, settings, tw.triggered)
        if reason and reason.startswith("below min_level") and _continues_open_incident(db, na):
            reason = None
        if reason:
            db.add(Suppression(wazuh_id=na.wazuh_id, rule_id=na.rule_id, level=na.level, agent_name=na.agent_name,
                               description=na.description, reason=reason, raw=payload))
            db.commit()
            Stats.suppressed += 1
            return Outcome("suppressed")

    intel_hit, intel_info, notes = await _intel(na.srcip, settings)   # no session held across await

    with SessionLocal() as db:
        novelty = _check_novelty(na, db)
        inc = find_or_create_incident(na, db, settings, tw.triggered, tw.hits)
        is_new = inc.alert_count == 1
        alert = Alert(wazuh_id=na.wazuh_id, rule_id=na.rule_id, level=na.level, description=na.description,
                      agent_name=na.agent_name, agent_id=na.agent_id, srcip=na.srcip, user=na.user, groups=na.groups,
                      mitre_ids=na.mitre_ids, mitre_tactics=na.mitre_tactics, timestamp=na.timestamp,
                      received_at=received_at, untrusted=na.untrusted, full_log=na.full_log, raw=payload, incident=inc)
        db.add(alert)
        db.flush()
        new_tripwire = False
        if tw.triggered:
            inc.tripwire_hits = [{**h, "alert_id": h.get("alert_id") or alert.id} for h in inc.tripwire_hits]
            new_tripwire = not any(h["alert_id"] != alert.id for h in inc.tripwire_hits)
        db.refresh(inc)
        alerts = sorted(inc.alerts, key=lambda a: aware(a.timestamp))
        inc.alert_count = len(alerts)
        since = aware(inc.last_seen) - timedelta(hours=24)
        host_tactics = {t for (ts,) in db.execute(select(Alert.mitre_tactics).where(
            Alert.agent_name == inc.agent_name, Alert.timestamp >= since)).all() for t in (ts or [])}
        inc.novelty = bool(inc.novelty or novelty)
        if intel_hit:
            inc.intel = intel_info
        inc.partial_context = bool(inc.partial_context or notes)
        inc.context_notes = sorted(set(inc.context_notes or []) | set(notes))
        prev_band = inc.band if not is_new else None
        score, band, breakdown, overrides = compute_score(
            inc, settings, inc.novelty, False, bool(inc.intel), [a.groups for a in alerts],
            sequence=[(a.groups, a.srcip) for a in alerts], entity_tactics=host_tactics)
        inc.score, inc.band, inc.breakdown, inc.overrides = score, band, breakdown, overrides
        if overrides and any("brute force" in o for o in overrides):
            inc.title = "Brute force, then a successful login"
        elif is_new:
            inc.title = (na.description.strip().rstrip(".") or f"Rule {na.rule_id}")[:300]
        inc.playbook = playbooks.choose({g for a in alerts for g in a.groups}, set(inc.techniques))
        inc.is_selftest = inc.is_selftest or selftest
        should = band_rank(band) >= band_rank(settings.notify.min_band) or inc.tripwire
        already = inc.notified_band is not None and band_rank(inc.notified_band) >= band_rank(band)
        notify = (should and not already) or new_tripwire   # a first tripwire hit is its own alert
        if notify:
            inc.notified_band = band
        db.commit()
        inc_id = inc.id
        Stats.alerts += 1

    out = Outcome("grouped", inc_id, band, notify)
    if notify:
        with SessionLocal() as db:
            inc = db.get(Incident, inc_id)
            refs = await send_instant(inc, settings, received_at)
            Stats.notifications += 1
            Stats.first_notify_ms.append(int((utcnow() - received_at).total_seconds() * 1000))
            Stats.first_notify_ms[:] = Stats.first_notify_ms[-1000:]
            inc.notify_ref = {**(inc.notify_ref or {}), **refs}
            db.commit()

    gate = settings.llm.enabled and band_rank(band) >= band_rank(settings.llm.min_band)
    band_rose = prev_band is None or band_rank(band) > band_rank(prev_band)
    if gate and (band_rose or notify):
        _spawn(_phase2(inc_id))
    elif band == "critical" and band_rose and settings.llm.investigate_critical:
        _spawn(_checks_only(inc_id))   # read-only checks are deterministic: they run with no AI too
    return out


async def _checks_only(inc_id: int) -> None:
    try:
        with SessionLocal() as db:
            done = db.scalar(select(Explanation.id).where(Explanation.incident_id == inc_id,
                                                          Explanation.kind == "investigation"))
        if not done:
            await investigate(inc_id, runtime.current())
    except Exception:  # noqa: BLE001
        log.exception("investigation checks failed", extra={"incident": inc_id})


async def _phase2(inc_id: int) -> None:
    settings = runtime.current()
    async with _llm_sem:
        try:
            exp = await explain_incident(inc_id, settings)
            with SessionLocal() as db:
                inc = db.get(Incident, inc_id)
                if exp and inc and inc.notify_ref:
                    await edit_with_ai(inc, inc.notify_ref, exp, settings)
                need_inv = bool(inc and inc.band == "critical" and settings.llm.investigate_critical and not
                                db.scalar(select(Explanation.id).where(Explanation.incident_id == inc_id,
                                                                       Explanation.kind == "investigation")))
            if need_inv:
                await investigate(inc_id, settings)
        except Exception:  # noqa: BLE001 - phase 2 failures never affect triage
            log.exception("phase-2 failed", extra={"incident": inc_id})


def enqueue(payload: dict, source: str = "wazuh", bypass_filter: bool = False) -> int:
    with SessionLocal() as db:
        q = QueueItem(payload=payload, source=source, bypass_filter=bypass_filter)
        db.add(q)
        db.commit()
        return q.id


async def run_once(limit: int = 50) -> int:
    """Process up to ``limit`` pending queue items; returns how many were taken."""
    settings = runtime.current()
    with SessionLocal() as db:
        items = db.scalars(select(QueueItem).where(QueueItem.status == "pending")
                           .order_by(QueueItem.id).limit(limit)).all()
        work = [(i.id, i.payload, i.attempts, i.bypass_filter, aware(i.received_at), i.source) for i in items]
    for item_id, payload, attempts, bypass, received, source in work:
        try:
            await process_alert(payload, settings, bypass_filter=bypass, received_at=received,
                                selftest=source == "selftest")
            status, error = "done", None
        except Exception as e:  # noqa: BLE001
            log.error("queue item failed", extra={"item": item_id, "attempt": attempts + 1, "error": repr(e)[:300]})
            status = "failed" if attempts + 1 >= MAX_ATTEMPTS else "pending"
            error = repr(e)[:500]
        with SessionLocal() as db:
            item = db.get(QueueItem, item_id)
            if item:
                item.status = status
                item.last_error = error
                item.attempts = attempts + (0 if status == "done" else 1)
                db.commit()
    return len(work)


async def _maybe_digest(settings: Settings) -> None:
    d = settings.notify.digest
    now = datetime.now(UTC)
    if not d.enabled or now.hour != d.hour_utc:
        return
    today = now.strftime("%Y-%m-%d")
    with SessionLocal() as db:
        kv = db.get(KV, "digest.last")
        if kv and kv.value.get("day") == today:
            return
        if kv:
            kv.value = {"day": today}
        else:
            db.add(KV(key="digest.last", value={"day": today}))
        db.commit()
    from .digest import send_digest
    await send_digest(settings, d.version)


async def run_worker(stop: asyncio.Event | None = None) -> None:
    log.info("triage worker started")
    stop = stop or asyncio.Event()
    while not stop.is_set():
        took = 0
        try:
            Stats.heartbeat = utcnow()
            took = await run_once()
            await _maybe_digest(runtime.current())
        except Exception:  # noqa: BLE001 - the loop must survive anything
            log.exception("worker loop error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.2 if took else 1.0)
        except TimeoutError:
            pass
    await drain()


def queue_depth() -> dict:
    with SessionLocal() as db:
        rows = dict(db.execute(select(QueueItem.status, func.count()).group_by(QueueItem.status)).all())
    return {"pending": rows.get("pending", 0), "failed": rows.get("failed", 0), "done": rows.get("done", 0)}

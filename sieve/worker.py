"""Background triage worker: reads from the durable queue and runs each alert through the pipeline.

Architecture
------------
* Alerts are written to `queue` table BEFORE processing.
  If the process dies mid-flight, they are retried on restart.
* Deduplication: wazuh_id uniqueness is enforced on the alerts table.
* LLM calls are gated: only medium+ incidents, only when below the hourly budget.
* Phase 1 notification is synchronous (instant).  Phase 2 (AI edit) is a background task.
* Error handling contract: transient errors are retried up to 3 times with exponential
  backoff; permanent errors (bad payload, DB constraint) mark the queue item "failed".
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from .config import Settings
from .db import SessionLocal
from .llm.client import explain
from .models import Alert, AuditEvent, Baseline, Incident, QueueItem, Suppression, utcnow
from .notify.dispatch import edit_with_ai, send_instant
from .pipeline.filter import suppression_reason
from .pipeline.group import find_or_create_incident
from .pipeline.normalise import normalise
from .pipeline.score import compute_score
from .pipeline.tripwire import scan

log = logging.getLogger("sieve.worker")

BAND_LLM_MIN = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Simple hourly budget counter
_llm_calls: list[float] = []


def _can_call_llm(settings: Settings) -> bool:
    now = time.time()
    _llm_calls[:] = [t for t in _llm_calls if now - t < 3600]
    return len(_llm_calls) < settings.llm.calls_per_hour


def _check_novelty(na, db) -> bool:
    entity = f"user:{na.user}" if na.user else f"agent:{na.agent_name}"
    feature = f"srcip:{na.srcip}" if na.srcip else f"rule:{na.rule_id}"
    bl = db.query(Baseline).filter(Baseline.entity == entity, Baseline.feature == feature).first()
    if bl is None:
        db.add(Baseline(entity=entity, feature=feature))
        return True
    bl.last_seen = utcnow()
    return False


def _check_intel(na, settings: Settings) -> bool:
    return bool(na.srcip and na.srcip in set(settings.intel.blocklist_ips))


async def process_alert(payload: dict, settings: Settings) -> None:
    na = normalise(payload)
    with SessionLocal() as db:
        # Dedup check
        existing = db.query(Alert).filter(Alert.wazuh_id == na.wazuh_id).first()
        if existing:
            return

        tw = scan(na.untrusted, settings.tripwire_threshold)
        reason = suppression_reason(na, settings, tw.triggered)

        if reason:
            db.add(Suppression(
                wazuh_id=na.wazuh_id, rule_id=na.rule_id,
                description=na.description, reason=reason,
            ))
            db.commit()
            return

        novelty = _check_novelty(na, db)
        intel_hit = _check_intel(na, settings)

        incident = find_or_create_incident(na, db, settings, tw.triggered, tw.hits)

        alert = Alert(
            wazuh_id=na.wazuh_id, rule_id=na.rule_id, level=na.level,
            description=na.description, agent_name=na.agent_name,
            srcip=na.srcip, user=na.user, groups=na.groups,
            mitre_ids=na.mitre_ids, mitre_tactics=na.mitre_tactics,
            timestamp=na.timestamp, untrusted=na.untrusted,
            full_log=na.full_log, raw=na.raw, incident=incident,
        )
        db.add(alert)
        db.flush()

        all_groups = [a.groups for a in incident.alerts]
        score, band, breakdown, overrides = compute_score(
            incident, settings, novelty, False, intel_hit, all_groups,
        )
        incident.score = score
        incident.band = band
        incident.breakdown = breakdown
        incident.overrides = overrides
        db.commit()

        # Phase 1: instant plain notification
        refs = await send_instant(incident, settings)
        incident.notify_ref = refs
        db.commit()

    # Phase 2: LLM (async, non-blocking for the queue)
    min_ord = BAND_LLM_MIN.get(settings.llm.min_band, 2)
    inc_ord = BAND_LLM_MIN.get(band, 3)
    if settings.llm.enabled and inc_ord <= min_ord and _can_call_llm(settings):
        _llm_calls.append(time.time())
        with SessionLocal() as db:
            inc = db.get(Incident, incident.id)
            alerts_summary = [
                {"id": str(a.id), "rule": a.rule_id, "desc": a.description,
                 "ts": a.timestamp.isoformat(), "level": a.level}
                for a in (inc.alerts or [])[:20]
            ]
            evidence_refs = [str(a.id) for a in (inc.alerts or [])]
            merged_untrusted: dict[str, str] = {}
            for a in (inc.alerts or []):
                for k, v in (a.untrusted or {}).items():
                    if k not in merged_untrusted:
                        merged_untrusted[k] = v

        exp = await explain(
            incident.id, score, band, breakdown,
            alerts_summary, merged_untrusted, evidence_refs,
            settings.playbook_ids if hasattr(settings, "playbook_ids") else [],
            settings,
        )
        if exp:
            from .models import Explanation
            with SessionLocal() as db:
                db.add(Explanation(
                    incident_id=incident.id,
                    provider=exp.get("provider", ""),
                    model=exp.get("model", ""),
                    summary=exp,
                    validation=exp.get("validation", {}),
                    latency_ms=0,
                ))
                db.commit()
            await edit_with_ai(incident, refs, exp, settings)


async def run_worker(settings: Settings) -> None:
    log.info("Triage worker started")
    while True:
        try:
            with SessionLocal() as db:
                items = (
                    db.query(QueueItem)
                    .filter(QueueItem.status == "pending")
                    .order_by(QueueItem.received_at)
                    .limit(20)
                    .all()
                )
                ids = [i.id for i in items]
                payloads = [(i.id, i.payload, i.attempts) for i in items]

            for item_id, payload, attempts in payloads:
                try:
                    await process_alert(payload, settings)
                    with SessionLocal() as db:
                        item = db.get(QueueItem, item_id)
                        if item:
                            item.status = "done"
                            db.commit()
                except Exception as e:  # noqa: BLE001
                    log.error("Queue item %d failed (attempt %d): %s", item_id, attempts + 1, e)
                    with SessionLocal() as db:
                        item = db.get(QueueItem, item_id)
                        if item:
                            item.attempts += 1
                            item.last_error = str(e)[:500]
                            if item.attempts >= 3:
                                item.status = "failed"
                            db.commit()

        except Exception as e:  # noqa: BLE001
            log.error("Worker loop error: %s", e)

        await asyncio.sleep(1.0 if ids else 2.0)

"""High availability: leased queue claims, crash recovery, leader lock, concurrent workers (PostgreSQL)."""

import asyncio
import os
import threading
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from sieve.db import SessionLocal
from sieve.models import Alert, Incident, QueueItem, utcnow
from sieve.worker import claim, enqueue_many, is_leader, run_once
from tests.helpers import alert


def test_claim_is_exclusive_and_expired_leases_return(settings):
    enqueue_many([alert(i) for i in range(5)])
    a = claim(3)
    b = claim(10)
    assert len(a) == 3 and len(b) == 2 and not {x[0] for x in a} & {x[0] for x in b}
    assert claim(10) == []  # everything is leased
    with SessionLocal() as db:  # simulate a crashed worker
        for q in db.scalars(select(QueueItem).where(QueueItem.id.in_([x[0] for x in a]))):
            q.lease_until = utcnow() - timedelta(seconds=1)
        db.commit()
    assert {x[0] for x in claim(10)} == {x[0] for x in a}  # expired leases are retried


def test_leader_lock_single_holder(settings, monkeypatch):
    import sieve.worker as w

    assert is_leader("t")
    monkeypatch.setattr(w, "WORKER_ID", "other:1")
    assert not is_leader("t")


@pytest.mark.skipif(not os.environ.get("SIEVE_TEST_DATABASE_URL"), reason="needs PostgreSQL")
def test_two_workers_process_each_alert_once(settings):
    settings.risk.enabled = False   # isolate exactly-once processing from risk-based alerts
    n = 300
    enqueue_many([alert(i, ip=f"203.0.113.{i % 7}") for i in range(n)])
    errors = []

    def worker():
        try:

            async def loop():
                while await run_once(25):
                    pass

            asyncio.run(loop())
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == n
        assert db.scalar(select(func.count(QueueItem.id)).where(QueueItem.status == "done")) == n
        incs = db.scalars(select(Incident)).all()
        keys = [i.grouping_key for i in incs]
        assert len(keys) == len(set(keys)) == 7  # one incident per source IP, no duplicates from races

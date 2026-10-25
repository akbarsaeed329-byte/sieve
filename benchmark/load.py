"""Load test: how many alerts per second one Sieve worker sustains on SQLite (no AI, no network).

    python benchmark/load.py --alerts 3000
Mix: 70% low-level noise (suppressed), 25% grouped attack bursts, 5% unique high alerts.
"""

import argparse
import asyncio
import random
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sieve import runtime  # noqa: E402
from sieve.config import Settings  # noqa: E402
from sieve.db import SessionLocal, init_db  # noqa: E402
from sieve.models import Incident, Notification, Suppression  # noqa: E402
from sieve.worker import drain, enqueue, run_once  # noqa: E402


def gen(n: int, seed: int = 1) -> list[dict]:
    rnd, t0, out = random.Random(seed), datetime.now(UTC) - timedelta(hours=2), []
    for k in range(n):
        t = t0 + timedelta(seconds=k * 0.5)
        r = rnd.random()
        if r < 0.70:
            a = {"rule": {"id": "530", "level": 2, "description": "noise", "groups": ["ossec"]}, "agent": {"name": f"h{k % 50}"}}
        elif r < 0.95:
            ip = f"203.0.113.{k % 40}"
            a = {
                "rule": {
                    "id": "5716",
                    "level": 5,
                    "description": "sshd: authentication failed.",
                    "groups": ["sshd", "authentication_failed"],
                    "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
                },
                "agent": {"name": f"web-{k % 8}"},
                "data": {"srcip": ip, "dstuser": "root"},
            }
        else:
            a = {
                "rule": {
                    "id": "92057",
                    "level": 12,
                    "description": "encoded powershell",
                    "groups": ["sysmon_event1"],
                    "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
                },
                "agent": {"name": f"pc-{k}"},
            }
        out.append({**a, "id": f"load-{k}", "timestamp": t.isoformat(), "full_log": "x" * 200})
    return out


async def main(n: int) -> None:
    tmp = tempfile.mkdtemp()
    s = Settings(data_dir=tmp, secret_key="x", ingest_token="x")
    s.filter.min_level, s.llm.enabled, s.notify.console = 4, False, False
    s.sla.escalate = False
    runtime.set_current(s)
    init_db(Path(tmp) / "sieve.db")
    alerts = gen(n)
    t_enq = time.perf_counter()
    for a in alerts:
        enqueue(a)
    enq = time.perf_counter() - t_enq
    t0 = time.perf_counter()
    while await run_once(500):
        pass
    await drain()
    dt = time.perf_counter() - t0
    with SessionLocal() as db:
        lat = sorted(x.latency_ms for x in db.query(Notification).all())
        incs, sup = db.query(Incident).count(), db.query(Suppression).count()
    print(
        f"alerts={n} enqueue={n / enq:,.0f}/s processed={n / dt:,.0f}/s ({dt:.1f}s) incidents={incs} suppressed={sup} "
        f"notifications={len(lat)}"
    )
    print("Note: in batch replay, latency includes queue wait; live arrival latency is measured by benchmark/run.py.")
    if lat:
        print(f"median queue+process latency {statistics.median(lat)} ms")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", type=int, default=3000)
    asyncio.run(main(ap.parse_args().alerts))

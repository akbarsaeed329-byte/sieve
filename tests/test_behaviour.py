"""UEBA (login hours, volume spikes) and risk-based alerting; dashboards."""

from datetime import timedelta

from sqlalchemy import select

from sieve.db import SessionLocal
from sieve.models import Incident
from tests.conftest import run, signed_in
from tests.helpers import T0, alert, feed, success


def test_unusual_login_hour_is_explained(settings):
    settings.filter.min_level = 0
    base = T0.replace(hour=9)
    history = [success(i, ip="10.0.4.12", t=base + timedelta(days=i % 20, minutes=i)) for i in range(25)]
    run(feed(history, settings))
    late = success(500, ip="10.0.4.12", t=(base + timedelta(days=21)).replace(hour=3))
    run(feed([late], settings))
    with SessionLocal() as db:
        inc = db.scalars(select(Incident).order_by(Incident.id.desc())).first()
    note = next(n for n in inc.context_notes if n.startswith("Behaviour:"))
    assert "03:00" in note and "usually 09:00-10:00" in note and inc.novelty


def test_risk_based_alerting_catches_slow_attack(settings):
    settings.notify.min_band = "high"
    settings.risk.threshold = 20
    # many low, spread-out alerts for one user on different hosts: never notified on their own
    slow = [
        alert(
            i,
            rule=f"60{i % 5}",
            level=5,
            groups=("windows",),
            ip=None,
            user="m.janssens",
            host=f"pc-{i % 4}",
            t=T0 + timedelta(hours=2 * i),
            tech=None,
            tactic=None,
        )
        for i in range(14)
    ]
    run(feed(slow, settings))
    run(feed([], settings))
    with SessionLocal() as db:
        risk = db.scalars(select(Incident).where(Incident.title.like("Risk threshold%"))).all()
    assert len(risk) == 1 and risk[0].band in ("high", "critical") and "m.janssens" in risk[0].title


def test_loud_attack_does_not_spawn_risk_duplicates(settings):
    settings.risk.threshold = 10
    run(feed([alert(i) for i in range(30)] + [success()], settings))
    run(feed([], settings))
    with SessionLocal() as db:
        assert not db.scalars(select(Incident).where(Incident.title.like("Risk threshold%"))).all()


def test_dashboard_layout_and_data(client, settings):
    run(feed([alert(i) for i in range(6)] + [success()], settings))
    c = signed_in(client)
    assert "kpis" in c.get("/api/dashboard").json()["widgets"]
    assert c.put("/api/dashboard", json={"widgets": ["risk_top", "evil", "kpis"]}).json()["widgets"] == ["risk_top", "kpis"]
    d = c.get("/api/dashboard/data").json()
    assert d["kpis"]["open"] >= 1 and d["open_by_band"]["critical"] == 1
    assert c.get("/api/risk").status_code == 200

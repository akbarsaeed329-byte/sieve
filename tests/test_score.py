import asyncio
from sieve.config import load_settings
from sieve.db import init_db, SessionLocal
from sieve.models import Alert, Incident, utcnow
from sieve.pipeline.score import compute_score


def _make_incident(db, level=10, tactics=None):
    inc = Incident(
        grouping_key="test", title="Test", agent_name="web-01",
        tactics=tactics or [], alert_count=10,
    )
    db.add(inc)
    db.flush()
    a = Alert(
        wazuh_id="test-001", rule_id="5715", level=level,
        description="test", timestamp=utcnow(), raw={},
    )
    a.incident = inc
    db.add(a)
    db.flush()
    return inc


def test_brute_force_success_override():
    settings = load_settings.__wrapped__() if hasattr(load_settings, "__wrapped__") else load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        inc = _make_incident(db, level=8,
                             tactics=["Credential Access", "Initial Access"])
        score, band, _, overrides = compute_score(
            inc, settings, novelty=True, vuln_match=False, intel_hit=True,
            recent_alert_groups=[
                ["authentication_failures"],
                ["authentication_success"],
            ],
        )
    assert band == "critical"
    assert score == 100.0
    assert any("brute" in o.lower() or "successful" in o.lower() for o in overrides)


def test_low_level_low_score():
    settings = load_settings.__wrapped__() if hasattr(load_settings, "__wrapped__") else load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        inc = _make_incident(db, level=3)
        score, band, _, _ = compute_score(
            inc, settings, novelty=False, vuln_match=False, intel_hit=False,
            recent_alert_groups=[[]],
        )
    assert score < 60

from sieve.config import load_settings
from sieve.db import SessionLocal, init_db
from sieve.models import Alert, Incident, utcnow
from sieve.pipeline.score import OVERRIDE_BRUTE, compute_score, success_after_bruteforce


def _make_incident(db, level=10, tactics=None, count=10):
    inc = Incident(grouping_key="test", title="Test", agent_name="web-01", tactics=tactics or [], alert_count=count)
    db.add(inc)
    db.flush()
    a = Alert(wazuh_id=f"t-{level}-{count}", rule_id="5715", level=level, description="t", timestamp=utcnow(), raw={})
    a.incident = inc
    db.add(a)
    db.flush()
    return inc


def test_brute_force_success_override_sets_band_not_score():
    settings = load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        inc = _make_incident(db, level=8, tactics=["Credential Access", "Initial Access"])
        score, band, _, overrides = compute_score(
            inc, settings, novelty=True, vuln_match=False, intel_hit=True,
            recent_alert_groups=[["authentication_failures"], ["authentication_success"]])
    assert band == "critical" and overrides == [OVERRIDE_BRUTE]
    assert score < 100  # the honest score is reported; the override changes the band only


def test_low_level_low_score():
    settings = load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        inc = _make_incident(db, level=3, count=1)
        score, band, _, _ = compute_score(inc, settings, False, False, False, [[]])
    assert score < 40 and band == "low"


def test_tactic_case_is_normalised_for_chain():
    settings = load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        a = _make_incident(db, tactics=["Credential Access", "credential-access"], count=1)
        b = _make_incident(db, level=9, tactics=["Credential Access", "Initial Access"], count=1)
        _, _, br_a, _ = compute_score(a, settings, False, False, False, [[]])
        _, _, br_b, _ = compute_score(b, settings, False, False, False, [[]])
    chain = lambda br: sum(x["points"] for x in br if x["label"].startswith("Attack chain"))  # noqa: E731
    assert chain(br_a) == 5.0  # one distinct tactic = 1/4 of w_c (20)
    assert chain(br_b) == 10.0
    assert any("credential access, then initial access" in x["label"] for x in br_b)


def test_strict_override_needs_same_source_and_order():
    fail, ok = ["authentication_failed"], ["authentication_success"]
    assert success_after_bruteforce([(fail, "1.1.1.1")] * 5 + [(ok, "1.1.1.1")])
    assert not success_after_bruteforce([(fail, "1.1.1.1")] * 5 + [(ok, "2.2.2.2")])
    assert not success_after_bruteforce([(ok, "1.1.1.1")] + [(fail, "1.1.1.1")] * 5)
    assert not success_after_bruteforce([(fail, "1.1.1.1")] * 4 + [(ok, "1.1.1.1")])


def test_tripwire_with_execution_is_critical():
    settings = load_settings()
    init_db(":memory:")
    with SessionLocal() as db:
        inc = _make_incident(db, level=3, tactics=["Execution"], count=1)
        inc.tripwire = True
        _, band, _, overrides = compute_score(inc, settings, False, False, False, [[]])
    assert band == "critical" and overrides

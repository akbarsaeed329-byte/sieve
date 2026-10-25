from sieve.config import load_settings
from sieve.pipeline.filter import suppression_reason
from sieve.pipeline.normalise import normalise

_BASE = {
    "id": "x", "timestamp": "2026-10-16T09:00:00.000+00:00",
    "rule": {"id": "5716", "level": 8, "description": "SSH fail",
             "groups": [], "mitre": {}},
    "agent": {"name": "web-01"}, "data": {"srcip": "1.2.3.4"},
}


def _settings(**kw):
    s = load_settings()
    for k, v in kw.items():
        setattr(s.filter, k, v)
    return s


def test_tripwire_never_suppressed():
    na = normalise(_BASE)
    s = _settings(min_level=99)   # would normally suppress
    assert suppression_reason(na, s, tripwire_hit=True) is None


def test_below_min_level_suppressed():
    na = normalise(_BASE)
    s = _settings(min_level=10)
    reason = suppression_reason(na, s, tripwire_hit=False)
    assert reason is not None
    assert "min_level" in reason


def test_allowlisted_rule_suppressed():
    na = normalise(_BASE)
    s = _settings(allow_rule_ids=["5716"])
    assert suppression_reason(na, s, False) is not None


def test_allowlisted_srcip_suppressed():
    na = normalise(_BASE)
    s = _settings(allow_srcips=["1.2.3.4"])
    assert suppression_reason(na, s, False) is not None

"""API: auth, CSRF, roles (401/403 for every protected route), and route behaviour."""
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from sieve.db import SessionLocal, engine
from sieve.models import Incident
from tests.conftest import run, signed_in
from tests.helpers import alert, feed, success

VIEWER_GET = ["/api/incidents", "/api/incidents/1", "/api/stats", "/api/playbooks", "/api/playbooks/PB-BRUTE",
              "/api/suppressions", "/api/baselines", "/api/coverage", "/api/graph?incident_id=1",
              "/api/metrics/summary", "/api/shadow/agreement", "/api/digest", "/api/health/details",
              "/api/incidents/1/stix", "/api/auth/me", "/api/exceptions", "/api/maintenance", "/api/tuning/noisy-rules",
              "/api/reports/executive", "/api/reports/handover", "/api/users/directory"]
ANALYST_POST = [("/api/incidents/1/acknowledge", None), ("/api/incidents/1/resolve", {}),
                ("/api/incidents/1/false-positive", {"reason": "x"}), ("/api/incidents/1/checklist/PB-BRUTE-01", {}),
                ("/api/incidents/1/human-band", {"band": "high"}), ("/api/suppressions/1/review", {"outcome": "noise"}),
                ("/api/backtest", {"rule": "detection:\n  s: {a: 1}\n  condition: s"}),
                ("/api/incidents/1/explain", None), ("/api/incidents/1/comments", {"body": "x"}),
                ("/api/incidents/1/assign", {"assignee": None}), ("/api/incidents/1/tags", {"tags": []}),
                ("/api/exceptions", {"reason": "abc", "rule_id": "1"})]
ADMIN = [("GET", "/api/users", None), ("POST", "/api/users/invite", {"role": "viewer"}),
         ("POST", "/api/users/1/role", {"role": "admin"}), ("GET", "/api/settings", None),
         ("PUT", "/api/settings", {"shadow_mode": False}), ("GET", "/api/audit", None), ("GET", "/api/plugins", None),
         ("PUT", "/api/plugins/abuseipdb", {"enabled": False}), ("PUT", "/api/secrets", {"name": "SIEVE_X", "value": ""}),
         ("POST", "/api/incidents/1/response/firewall-drop", {"confirm": True}),
         ("POST", "/api/health/test/wazuh", None), ("POST", "/api/setup/test-alert", None),
         ("GET", "/api/setup/progress", None), ("POST", "/api/coverage/results",
                                               {"technique": "T1110", "outcome": "detected"}),
         ("POST", "/api/digest/send", None), ("GET", "/api/tokens", None), ("POST", "/api/tokens", {"name": "x"}),
         ("POST", "/api/maintenance", {"agent_name": "x", "starts_at": "2026-01-01T00:00:00Z",
                                       "ends_at": "2026-01-01T01:00:00Z", "reason": "abc"})]


@pytest.fixture
def seeded(client, settings):
    run(feed([alert(i) for i in range(6)] + [success(), alert(50, ip="198.51.100.7")], settings))
    return client


ALL_PROTECTED = [("GET", p) for p in VIEWER_GET] + [("POST", p) for p, _ in ANALYST_POST] + \
    [(m, p) for m, p, _ in ADMIN] + [("GET", "/api/incidents/1/nis2-draft")]


@pytest.mark.parametrize("method,path", ALL_PROTECTED)
def test_unauthenticated_is_401(seeded, method, path):
    r = seeded.request(method, path, json={})
    assert r.status_code == 401, r.text
    assert r.json()["code"] == "SIEVE-AUTH-403"


@pytest.mark.parametrize("path,body", ANALYST_POST)
def test_viewer_cannot_change_things(seeded, path, body):
    c = signed_in(seeded, "vic", role="viewer")
    assert c.post(path, json=body).status_code == 403


@pytest.mark.parametrize("method,path,body", ADMIN)
def test_analyst_is_not_admin(seeded, method, path, body):
    c = signed_in(seeded, "ann", role="analyst")
    assert c.request(method, path, json=body).status_code == 403


@pytest.mark.parametrize("path", VIEWER_GET)
def test_viewer_routes_work(seeded, path):
    assert signed_in(seeded).get(path).status_code == 200


def test_csrf_required(seeded):
    c = signed_in(seeded)
    del c.headers["x-sieve-csrf"]
    r = c.post("/api/incidents/1/acknowledge")
    assert r.status_code == 419 and r.json()["code"] == "SIEVE-AUTH-419"


def test_setup_once_and_weak_password(client):
    assert client.post("/api/setup", json={"username": "a", "password": "short"}).status_code == 422
    assert client.post("/api/setup", json={"username": "admin", "password": "correct horse battery"}).status_code == 201
    assert client.post("/api/setup", json={"username": "b", "password": "correct horse battery"}).status_code == 409


def test_lockout_after_ten_failures(client):
    signed_in(client)
    client.cookies.clear()
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 423


def test_invite_flow_and_last_admin(client):
    c = signed_in(client)
    url = c.post("/api/users/invite", json={"role": "analyst"}).json()["url"]
    tok = url.rsplit("/", 1)[1]
    c.cookies.clear()
    assert c.get(f"/api/invites/{tok}").json()["role"] == "analyst"
    assert c.post(f"/api/invites/{tok}/accept", json={"username": "omar", "password": "a long passphrase"}).status_code == 201
    assert c.post(f"/api/invites/{tok}/accept", json={"username": "o2", "password": "a long passphrase"}).status_code == 410
    c = signed_in(client)
    me = c.get("/api/auth/me").json()
    r = c.post(f"/api/users/{me['id']}/role", json={"role": "viewer"})
    assert r.status_code == 409 and r.json()["code"] == "SIEVE-AUTH-428"


def test_incident_detail_and_workflow(seeded):
    c = signed_in(seeded)
    d = c.get("/api/incidents/1").json()
    assert d["band"] == "critical" and d["facts"] and d["playbook"]["id"] == "PB-BRUTE"
    assert "deploy" in d["playbook"]["steps"][0]["detail"]
    assert c.post("/api/incidents/1/checklist/PB-BRUTE-01", json={"checked": True}).status_code == 200
    assert c.get("/api/incidents/1").json()["checked_steps"] == ["PB-BRUTE-01"]
    assert c.post("/api/incidents/1/checklist/PB-OTHER-01", json={}).status_code == 422
    assert c.post("/api/incidents/1/false-positive", json={"reason": ""}).status_code == 422
    assert c.post("/api/incidents/1/acknowledge").json()["status"] == "acknowledged"
    items = c.get("/api/incidents?status=open").json()["items"]
    assert items[0]["assignee"] == "admin"
    log = c.get("/api/audit").json()["items"]
    assert any(e["action"] == "incident.acknowledged" for e in log)


def test_audit_is_append_only(seeded):
    signed_in(seeded)
    with pytest.raises(DBAPIError, match="append-only"):
        with engine().begin() as conn:
            conn.execute(text("DELETE FROM audit"))
    with pytest.raises(DBAPIError, match="append-only"):
        with engine().begin() as conn:
            conn.execute(text("UPDATE audit SET actor='x'"))


def test_suppression_sample_and_restore_requeues(seeded, settings):
    c = signed_in(seeded)
    d = c.get("/api/suppressions?sampled=true").json()
    assert d["items"] and d["items"][0]["reason"].startswith("approved-source")
    sid = d["items"][0]["id"]
    r = c.post(f"/api/suppressions/{sid}/review", json={"outcome": "restore"}).json()
    assert r["requeued"] and r["flag"]
    from sieve.worker import run_once
    run(run_once())
    with SessionLocal() as db:
        assert any(i.srcip == "198.51.100.7" for i in db.scalars(select(Incident)))
    assert c.post(f"/api/suppressions/{sid}/review", json={"outcome": "noise"}).status_code == 409
    assert c.get("/api/suppressions").json()["by_reason"][0]["flagged"]


def test_settings_update_validated_and_persisted(seeded, settings):
    c = signed_in(seeded)
    assert c.put("/api/settings", json={"filter": {"min_level": 99}}).status_code == 422
    assert c.put("/api/settings", json={"data_dir": "/tmp"}).status_code == 422
    assert c.put("/api/settings", json={"allow_active_response": True}).status_code == 422
    r = c.put("/api/settings", json={"filter": {"min_level": 6}, "llm": {"calls_per_hour": 5}})
    assert r.status_code == 200 and r.json()["settings"]["filter"]["min_level"] == 6
    assert "min_level: 6" in settings.override_path.read_text()
    from sieve import runtime
    assert runtime.current().llm.calls_per_hour == 5


def test_secrets_are_write_only(seeded):
    c = signed_in(seeded)
    assert c.put("/api/secrets", json={"name": "SIEVE_TELEGRAM_TOKEN", "value": "123:ABC"}).status_code == 200
    assert c.put("/api/secrets", json={"name": "SIEVE_NOT_USED", "value": "x"}).status_code == 422
    body = c.get("/api/settings").text + c.get("/api/audit").text
    assert "123:ABC" not in body and '"SIEVE_TELEGRAM_TOKEN":"stored"' in body.replace(" ", "")
    from sieve import secrets_store
    assert secrets_store.resolve("SIEVE_TELEGRAM_TOKEN") == "123:ABC"


def test_plugin_needs_permission_approval(seeded):
    c = signed_in(seeded)
    c.put("/api/plugins/abuseipdb", json={"enabled": False})
    assert c.put("/api/plugins/abuseipdb", json={"enabled": True}).status_code == 428
    assert c.put("/api/plugins/abuseipdb", json={"enabled": True, "approve_permissions": True}).status_code == 200
    assert c.put("/api/plugins/abuseipdb", json={"config": {"min_score": 500}}).status_code == 422
    assert c.put("/api/plugins/nope", json={}).status_code == 404


def test_nis2_draft_without_ai(seeded):
    d = signed_in(seeded).get("/api/incidents/1/nis2-draft").json()
    from datetime import datetime
    opened = datetime.fromisoformat(signed_in(seeded).get("/api/incidents/1").json()["opened_at"])
    assert datetime.fromisoformat(d["reporting_deadline"]) - opened == timedelta(hours=24)
    assert d["sent"] is False and "DRAFT" in d["label"] and d["draft_source"] == "template"
    assert "web-01" in d["draft_text"]


def test_stix_bundle(seeded):
    b = signed_in(seeded).get("/api/incidents/1/stix").json()
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "indicator", "sighting", "attack-pattern", "relationship"} <= types
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[ipv4-addr:value = '203.0.113.45']" and ind["spec_version"] == "2.1"


def test_shadow_agreement(seeded):
    c = signed_in(seeded)
    c.post("/api/incidents/1/human-band", json={"band": "critical"})
    d = c.get("/api/shadow/agreement?since=2020-01-01").json()
    assert d["labelled"] == 1 and d["agreement"] == 1.0 and d["confusion"]["critical"]["critical"] == 1


def test_active_response_off_confirm_and_audit(seeded, settings):
    c = signed_in(seeded)
    assert c.post("/api/incidents/1/response/firewall-drop", json={"confirm": True}).status_code == 403
    settings.allow_active_response = True
    settings.wazuh.api_url = "https://wazuh.test:55000"
    assert c.post("/api/incidents/1/response/firewall-drop", json={}).status_code == 428
    seen = []

    def h(req):
        seen.append(req)
        if req.url.path.endswith("/authenticate"):
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        return httpx.Response(200, json={"data": {"affected_items": ["001"]}})
    from sieve import http
    http.set_transport(httpx.MockTransport(h))
    r = c.post("/api/incidents/1/response/firewall-drop", json={"confirm": True})
    assert r.status_code == 200, r.text
    put = seen[-1]
    assert put.method == "PUT" and put.url.params["agents_list"] == "001"
    assert b"!firewall-drop" in put.content and b"203.0.113.45" in put.content
    ev = c.get("/api/audit?action=response").json()["items"][0]
    assert ev["detail"]["approved_by"] == "admin"


def test_backtest_sigma_and_wazuh(seeded):
    c = signed_in(seeded)
    sig = "title: SSH fails\ndetection:\n  sel:\n    rule.groups|contains: authentication_failed\n  condition: sel"
    r = c.post("/api/backtest", json={"rule": sig}).json()
    assert r["on_kept_alerts"] == 6 and r["would_have_caught"][0]["id"] == 1
    xml = '<rule id="100100" level="10"><if_sid>5715</if_sid><srcip>203.0.113.45</srcip><description>x</description></rule>'
    assert c.post("/api/backtest", json={"rule": xml}).json()["on_kept_alerts"] == 1
    assert c.post("/api/backtest", json={"rule": "<nope"}).status_code == 422


def test_coverage_graph_metrics_digest(seeded):
    c = signed_in(seeded)
    c.post("/api/coverage/results", json={"technique": "T1110", "outcome": "detected"})
    cov = c.get("/api/coverage").json()
    cred = next(t for t in cov["tactics"] if t["name"] == "Credential Access")
    assert next(x for x in cred["techniques"] if x["id"] == "T1110")["state"] == "detected"
    g = c.get("/api/graph?incident_id=1").json()
    assert {"ip:203.0.113.45", "host:web-01", "user:deploy"} <= {n["id"] for n in g["nodes"]}
    m = c.get("/api/metrics/summary?days=3").json()
    assert len(m["days"]) == 3 and set(m["incidents_by_band"]) == {"low", "medium", "high", "critical"}
    man = c.get("/api/digest?version=manager").json()["text"]
    import re
    assert not re.search(r"\d+\.\d+\.\d+\.\d+|T\d{4}", man) and "probed" in man
    assert "203.0.113.45" in c.get("/api/digest?version=technical").json()["text"]


def test_ingest_token_and_validation(client, settings):
    assert client.post("/api/ingest", json=alert(1)).status_code == 401
    h = {"Authorization": "Bearer test-token"}
    assert client.post("/api/ingest", json={"no": "rule"}, headers=h).status_code == 400
    r = client.post("/api/ingest/wazuh", json=[alert(1), alert(2)], headers={"x-sieve-token": "test-token"})
    assert r.json() == {"queued": 2}


def test_health_public_is_minimal(client):
    d = client.get("/api/health").json()
    assert set(d) == {"status", "version", "queue"}


def test_unknown_api_route_is_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.json()["code"] == "SIEVE-API-404"


def test_selftest_alert_always_notifies(client, settings):
    from sieve.models import Notification
    from sieve.worker import run_once
    c = signed_in(client)
    wid = c.post("/api/setup/test-alert").json()["wazuh_id"]
    run(run_once())
    st = c.get(f"/api/setup/test-alert/{wid}").json()
    assert st["processed"] and st["notifications"] and st["notifications"][0]["ok"]
    with SessionLocal() as db:
        assert db.scalars(select(Notification)).first().channel == "console"

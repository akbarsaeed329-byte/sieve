import asyncio
import os

import httpx
import pytest

from sieve import http, runtime
from sieve.config import Asset, Settings
from sieve.db import init_db
from sieve.llm import client as llm_client
from sieve.worker import Stats


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEVE_DATA_DIR", str(tmp_path))
    for k in ("SIEVE_ABUSEIPDB_KEY", "SIEVE_TELEGRAM_TOKEN", "SIEVE_CLOUD_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    s = Settings(data_dir=str(tmp_path), secret_key="test-secret", ingest_token="test-token")
    s.filter.min_level = 4
    s.filter.allow_srcips = ["198.51.100.7"]
    s.intel.blocklist_ips = ["203.0.113.45"]
    s.assets = [Asset(agent_name="web-01", criticality="critical"), Asset(agent_name="dc-01", criticality="critical")]
    s.llm.enabled = False
    s.notify.console = True
    runtime.set_current(s)
    pg = os.environ.get("SIEVE_TEST_DATABASE_URL")
    if pg:   # run the whole suite on PostgreSQL: fresh schema per test
        from sqlalchemy import create_engine, text
        monkeypatch.setenv("SIEVE_DATABASE_URL", pg)
        eng = create_engine(pg.replace("postgresql://", "postgresql+psycopg://", 1))
        with eng.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
        eng.dispose()
    init_db(s.db_path)
    llm_client.reset_state()
    llm_client._sleep = _nosleep
    llm_client.set_transport(None)
    http.set_transport(None)
    Stats.reset()
    from sieve import ratelimit
    ratelimit.reset()
    yield s
    runtime.reset()
    llm_client.set_transport(None)
    http.set_transport(None)


async def _nosleep(*_a, **_k):
    return None


@pytest.fixture
def client(settings):
    from fastapi.testclient import TestClient

    from sieve.app import create_app
    with TestClient(create_app(settings, start_worker=False)) as c:
        yield c


def signed_in(client, username="admin", password="correct horse battery", role="admin"):
    """Return a client signed in as a user with the given role (creating the admin first if needed)."""
    from sieve.auth import create_user, users_exist
    if not users_exist():
        r = client.post("/api/setup", json={"username": "admin", "password": "correct horse battery"})
        assert r.status_code == 201, r.text
    if username != "admin":
        create_user(username, password, role)
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    client.headers["x-sieve-csrf"] = client.cookies.get("sieve_csrf")
    return client


def mock_llm(handler):
    """handler(request_json) -> dict content the model 'returns'."""
    def respond(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        content = handler(body)
        if isinstance(content, httpx.Response):
            return content
        return httpx.Response(200, json={"message": {"content": json.dumps(content)}, "eval_count": 10,
                                         "prompt_eval_count": 90})
    llm_client.set_transport(httpx.MockTransport(respond))


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)

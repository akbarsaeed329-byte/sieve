import pytest

from sieve.config import Asset, Settings
from sieve.db import init_db


@pytest.fixture
def settings(tmp_path):
    s = Settings(data_dir=str(tmp_path), secret_key="test-secret", ingest_token="test-token")
    s.filter.min_level = 4
    s.filter.allow_srcips = ["198.51.100.7"]
    s.intel.blocklist_ips = ["203.0.113.45"]
    s.assets = [Asset(agent_name="web-01", criticality="critical"), Asset(agent_name="dc-01", criticality="critical")]
    s.llm.enabled = False
    init_db(s.db_path)
    return s

"""Configuration: defaults < YAML file < environment variables.

The YAML path comes from SIEVE_CONFIG (default ./config/sieve.yaml). Secrets should come from the
environment (SIEVE_INGEST_TOKEN, SIEVE_TELEGRAM_TOKEN, SIEVE_CLOUD_API_KEY ...), never from git.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

from .errors import CONFIG_INVALID, SieveError


class Weights(BaseModel):
    asset: float = 15.0      # w_a, applied to A in [0, 1]
    vuln: float = 10.0       # w_v
    intel: float = 10.0      # w_t
    chain: float = 20.0      # w_c, applied to C in [0, 1]
    novelty: float = 10.0    # w_n
    volume: float = 2.0      # w_r, applied to log2(1 + n)


class Bands(BaseModel):
    critical: float = 80
    high: float = 60
    medium: float = 40


class Grouping(BaseModel):
    window_minutes: int = 10
    max_minutes: int = 120


class FilterCfg(BaseModel):
    min_level: int = 3
    allow_rule_ids: list[str] = Field(default_factory=list)       # always suppressed (with reason)
    allow_srcips: list[str] = Field(default_factory=list)         # e.g. approved vulnerability scanner


class Provider(BaseModel):
    name: str
    kind: Literal["ollama", "openai_compatible"]
    base_url: str
    model: str
    api_key_env: str | None = None   # name of env var holding the key; never the key itself
    timeout_s: float = 60
    is_cloud: bool = False


class LLMCfg(BaseModel):
    enabled: bool = True
    min_band: Literal["low", "medium", "high", "critical"] = "medium"
    calls_per_hour: int = 60
    mask_for_cloud: bool = True
    providers: list[Provider] = Field(default_factory=lambda: [
        Provider(name="local-ollama", kind="ollama", base_url="http://ollama:11434", model="llama3.1:8b"),
    ])


class TelegramCfg(BaseModel):
    enabled: bool = False
    chat_id: str = ""
    token_env: str = "SIEVE_TELEGRAM_TOKEN"


class NotifyCfg(BaseModel):
    min_band: Literal["low", "medium", "high", "critical"] = "high"
    console: bool = True
    telegram: TelegramCfg = Field(default_factory=TelegramCfg)
    public_url: str = "http://localhost:8080"


class Asset(BaseModel):
    agent_name: str
    criticality: Literal["test", "normal", "critical"] = "normal"


class IntelCfg(BaseModel):
    blocklist_ips: list[str] = Field(default_factory=list)   # offline list; plugins add live feeds
    abuseipdb_key_env: str | None = None


class Settings(BaseModel):
    data_dir: str = "./data"
    bind_host: str = "127.0.0.1"
    port: int = 8080
    secret_key: str = ""
    ingest_token: str = ""
    weights: Weights = Field(default_factory=Weights)
    bands: Bands = Field(default_factory=Bands)
    grouping: Grouping = Field(default_factory=Grouping)
    filter: FilterCfg = Field(default_factory=FilterCfg)
    llm: LLMCfg = Field(default_factory=LLMCfg)
    notify: NotifyCfg = Field(default_factory=NotifyCfg)
    assets: list[Asset] = Field(default_factory=list)
    intel: IntelCfg = Field(default_factory=IntelCfg)
    tripwire_threshold: float = 1.0

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "sieve.db"

    def criticality(self, agent_name: str | None) -> float:
        for a in self.assets:
            if a.agent_name == agent_name:
                return {"test": 0.0, "normal": 0.5, "critical": 1.0}[a.criticality]
        return 0.5


def _secret_file(data_dir: Path, name: str) -> str:
    """Persist generated secrets with 0600 permissions so restarts keep sessions and tokens."""
    data_dir.mkdir(parents=True, exist_ok=True)
    p = data_dir / name
    if p.exists():
        return p.read_text().strip()
    value = secrets.token_urlsafe(32)
    p.write_text(value)
    os.chmod(p, 0o600)
    return value


def load_settings(path: str | None = None) -> Settings:
    path = path or os.environ.get("SIEVE_CONFIG", "config/sieve.yaml")
    raw: dict = {}
    p = Path(path)
    if not p.exists() and (p.parent / "sieve.example.yaml").exists():
        p = p.parent / "sieve.example.yaml"  # first run: start from the documented defaults
    if p.exists():
        try:
            raw = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as e:
            raise SieveError(CONFIG_INVALID, f"Config file {p} is not valid YAML: {e}",
                             "Fix the YAML syntax, or copy config/sieve.example.yaml again.") from e
    env_map = {
        "SIEVE_DATA_DIR": "data_dir",
        "SIEVE_BIND_HOST": "bind_host",
        "SIEVE_PORT": "port",
        "SIEVE_SECRET_KEY": "secret_key",
        "SIEVE_INGEST_TOKEN": "ingest_token",
    }
    for env, key in env_map.items():
        if os.environ.get(env):
            raw[key] = os.environ[env]
    try:
        s = Settings(**raw)
    except ValidationError as e:
        raise SieveError(CONFIG_INVALID, f"Config is invalid: {e.errors()[0]['loc']} {e.errors()[0]['msg']}",
                         "Compare your file with config/sieve.example.yaml.") from e
    d = Path(s.data_dir)
    if not s.secret_key:
        s.secret_key = _secret_file(d, ".secret_key")
    if not s.ingest_token:
        s.ingest_token = _secret_file(d, ".ingest_token")
    return s

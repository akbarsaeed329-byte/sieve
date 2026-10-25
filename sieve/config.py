"""Configuration: defaults < YAML file < UI override file < environment variables.

The YAML path comes from SIEVE_CONFIG (default ./config/sieve.yaml). Changes made in the web UI are
written to ``<data_dir>/settings.override.yaml`` because the config directory is mounted read-only in
Docker. Secrets never live in either file: they come from environment variables or the encrypted
secret store (``sieve/secrets_store.py``).
"""

from __future__ import annotations

import copy
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from .errors import CONFIG_INVALID, CONFIG_READONLY, SieveError

BandName = Literal["low", "medium", "high", "critical"]


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
    window_minutes: int = Field(10, ge=1, le=1440)
    max_minutes: int = Field(120, ge=1, le=10080)


class FilterCfg(BaseModel):
    min_level: int = Field(3, ge=0, le=16)
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
    enabled: bool = True


class LLMCfg(BaseModel):
    enabled: bool = True
    min_band: BandName = "medium"
    calls_per_hour: int = Field(60, ge=0, le=100000)
    mask_for_cloud: bool = True
    investigate_critical: bool = True
    providers: list[Provider] = Field(default_factory=lambda: [
        Provider(name="local-ollama", kind="ollama", base_url="http://ollama:11434", model="llama3.1:8b"),
    ])


class TelegramCfg(BaseModel):
    enabled: bool = False
    chat_id: str = ""
    token_env: str = "SIEVE_TELEGRAM_TOKEN"


class SlackCfg(BaseModel):
    enabled: bool = False
    channel: str = ""                       # needed with a bot token (chat.postMessage / chat.update)
    token_env: str = "SIEVE_SLACK_TOKEN"     # xoxb- bot token: supports send + edit
    webhook_env: str = "SIEVE_SLACK_WEBHOOK"  # incoming webhook: send only, edit posts a follow-up


class DiscordCfg(BaseModel):
    enabled: bool = False
    webhook_env: str = "SIEVE_DISCORD_WEBHOOK"


class EmailCfg(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 587
    starttls: bool = True
    username: str = ""
    password_env: str = "SIEVE_SMTP_PASSWORD"
    sender: str = ""
    to: list[str] = Field(default_factory=list)


class DigestCfg(BaseModel):
    enabled: bool = False
    hour_utc: int = Field(7, ge=0, le=23)
    version: Literal["manager", "technical"] = "manager"


class NotifyCfg(BaseModel):
    min_band: BandName = "high"
    console: bool = True
    telegram: TelegramCfg = Field(default_factory=TelegramCfg)
    slack: SlackCfg = Field(default_factory=SlackCfg)
    discord: DiscordCfg = Field(default_factory=DiscordCfg)
    digest: DigestCfg = Field(default_factory=DigestCfg)
    email: EmailCfg = Field(default_factory=EmailCfg)
    public_url: str = "http://localhost:8080"


class Asset(BaseModel):
    agent_name: str
    criticality: Literal["test", "normal", "critical"] = "normal"
    owner: str = ""
    tags: list[str] = Field(default_factory=list)


class IntelCfg(BaseModel):
    blocklist_ips: list[str] = Field(default_factory=list)   # offline list; plugins add live feeds
    abuseipdb_key_env: str | None = "SIEVE_ABUSEIPDB_KEY"
    abuseipdb_min_score: int = Field(50, ge=0, le=100)       # confidence at or above this counts as T=1
    abuseipdb_daily_limit: int = Field(1000, ge=0)           # free tier
    cache_minutes: int = Field(60, ge=1)


class WazuhCfg(BaseModel):
    """Read-only access for queries; a separate, stronger user is only needed for active response."""
    api_url: str = ""                  # manager API, e.g. https://wazuh.manager:55000
    indexer_url: str = ""              # e.g. https://wazuh.indexer:9200
    dashboard_url: str = ""            # for "Show query" deep links, e.g. https://wazuh.local
    username: str = "wazuh-wui"
    password_env: str = "SIEVE_WAZUH_PASSWORD"
    indexer_username: str = "admin"
    indexer_password_env: str = "SIEVE_WAZUH_INDEXER_PASSWORD"
    verify_tls: bool = True
    alerts_index: str = "wazuh-alerts-*"
    timeout_s: float = 10
    pull_enabled: bool = False      # poll the indexer instead of installing the integration on the manager
    pull_interval_s: int = Field(15, ge=5, le=3600)


class SlaCfg(BaseModel):
    """Minutes to acknowledge per band. Unacknowledged past due -> one escalation message."""
    critical: int = Field(15, ge=1)
    high: int = Field(60, ge=1)
    medium: int = Field(480, ge=1)
    low: int = Field(1440, ge=1)
    escalate: bool = True


class WebhookCfg(BaseModel):
    name: str
    url: str
    secret_env: str = ""            # HMAC-SHA256 signing secret (X-Sieve-Signature)
    events: list[str] = Field(default_factory=lambda: ["incident.notified", "incident.escalated",
                                                       "incident.status_changed"])
    min_band: BandName = "high"
    enabled: bool = True


class JiraCfg(BaseModel):
    enabled: bool = False
    base_url: str = ""              # https://yourcompany.atlassian.net
    email: str = ""
    token_env: str = "SIEVE_JIRA_TOKEN"
    project_key: str = ""
    issue_type: str = "Task"
    min_band: BandName = "high"


class TheHiveCfg(BaseModel):
    enabled: bool = False
    base_url: str = ""              # https://thehive.local:9000
    token_env: str = "SIEVE_THEHIVE_TOKEN"
    min_band: BandName = "high"


class RetentionCfg(BaseModel):
    alerts_days: int = Field(90, ge=1)          # raw alerts and suppressions; incidents and audit are kept
    llm_calls_days: int = Field(30, ge=1)


class Floor(BaseModel):
    """A single event that always reaches at least `band` (deterministic; shown as an override)."""
    name: str
    band: BandName = "high"
    min_level: int | None = Field(None, ge=0, le=16)
    techniques: list[str] = Field(default_factory=list)   # prefix match: T1136 matches T1136.001
    critical_asset_only: bool = False
    enabled: bool = True


def _default_floors() -> list[Floor]:
    return [
        Floor(name="High-importance Wazuh rule (level 12+)", min_level=12, band="high"),
        Floor(name="Account created on a critical asset", techniques=["T1136", "T1098"], band="high",
              critical_asset_only=True),
        Floor(name="Credential dumping", techniques=["T1003"], band="high"),
        Floor(name="Ransomware-like impact", techniques=["T1486", "T1490"], band="critical"),
    ]


class Route(BaseModel):
    """Send matching incidents to a team's own channels (in addition to, or instead of, the defaults)."""
    name: str
    hosts: list[str] = Field(default_factory=list)       # glob patterns, e.g. web-*, dc-0?
    tags: list[str] = Field(default_factory=list)        # asset tags
    min_band: BandName = "low"
    team: str = ""
    telegram_chat_id: str = ""
    slack_channel: str = ""
    email_to: list[str] = Field(default_factory=list)
    assign_to: str = ""                                  # auto-assign owner
    exclusive: bool = False                              # True: do not also send to the default channels
    enabled: bool = True


class AutoCloseCfg(BaseModel):
    """Graduated autonomy: per-rule auto-close of low/medium incidents, earned by analyst agreement."""
    enabled: bool = False
    rules: list[str] = Field(default_factory=list)       # rule IDs an admin approved for auto-close
    max_band: Literal["low", "medium"] = "medium"
    min_verdicts: int = Field(30, ge=5)
    min_agreement: float = Field(0.95, ge=0.5, le=1.0)


class ProfileCfg(BaseModel):
    """Company context: trusted, admin-written. Feeds the AI as context and labels off-hours activity."""
    organisation: str = ""
    industry: str = ""
    business_hours: str = "08:00-18:00"
    business_days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])   # Monday = 0
    timezone: str = "UTC"
    normal_activity: list[str] = Field(default_factory=list)
    critical_services: list[str] = Field(default_factory=list)


class TeamsCfg(BaseModel):
    enabled: bool = False
    webhook_env: str = "SIEVE_TEAMS_WEBHOOK"


class PagerDutyCfg(BaseModel):
    enabled: bool = False
    routing_key_env: str = "SIEVE_PAGERDUTY_KEY"
    min_band: BandName = "critical"


class OidcCfg(BaseModel):
    enabled: bool = False
    # e.g. https://login.microsoftonline.com/<tenant>/v2.0, https://accounts.google.com, a Keycloak realm URL
    issuer: str = ""
    client_id: str = ""
    client_secret_env: str = "SIEVE_OIDC_CLIENT_SECRET"
    groups_claim: str = "groups"
    admin_groups: list[str] = Field(default_factory=list)
    analyst_groups: list[str] = Field(default_factory=list)
    default_role: Literal["viewer", "analyst", "admin", "none"] = "viewer"
    button_label: str = "Sign in with SSO"


class PluginState(BaseModel):
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)


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
    wazuh: WazuhCfg = Field(default_factory=WazuhCfg)
    plugins: dict[str, PluginState] = Field(default_factory=dict)
    sla: SlaCfg = Field(default_factory=SlaCfg)
    webhooks: list[WebhookCfg] = Field(default_factory=list)
    jira: JiraCfg = Field(default_factory=JiraCfg)
    thehive: TheHiveCfg = Field(default_factory=TheHiveCfg)
    retention: RetentionCfg = Field(default_factory=RetentionCfg)
    require_2fa_for_admins: bool = False
    floors: list[Floor] = Field(default_factory=_default_floors)
    routes: list[Route] = Field(default_factory=list)
    autoclose: AutoCloseCfg = Field(default_factory=AutoCloseCfg)
    profile: ProfileCfg = Field(default_factory=ProfileCfg)
    teams: TeamsCfg = Field(default_factory=TeamsCfg)
    pagerduty: PagerDutyCfg = Field(default_factory=PagerDutyCfg)
    oidc: OidcCfg = Field(default_factory=OidcCfg)
    require_evidence_review: bool = True   # High/Critical: open the evidence before closing
    resummarise_growth: float = Field(1.5, ge=1.1, le=10)
    tripwire_threshold: float = Field(1.0, gt=0)
    shadow_mode: bool = False           # triage and record, but send no notifications
    allow_active_response: bool = False  # human-approved Wazuh active response; off by default
    simple_mode_default: bool = True

    @field_validator("bind_host")
    @classmethod
    def _bind(cls, v: str) -> str:
        return v.strip() or "127.0.0.1"

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "sieve.db"

    @property
    def override_path(self) -> Path:
        return Path(self.data_dir) / "settings.override.yaml"

    def criticality(self, agent_name: str | None) -> float:
        for a in self.assets:
            if a.agent_name == agent_name:
                return {"test": 0.0, "normal": 0.5, "critical": 1.0}[a.criticality]
        return 0.5

    def criticality_label(self, agent_name: str | None) -> str:
        for a in self.assets:
            if a.agent_name == agent_name:
                return a.criticality
        return "normal"


# Sections an admin may change from the UI (PUT /api/settings). Bootstrap values such as data_dir,
# bind_host, port and the generated secrets are deliberately excluded.
EDITABLE_SECTIONS = (
    "weights", "bands", "grouping", "filter", "llm", "notify", "assets", "intel", "wazuh", "plugins",
    "tripwire_threshold", "shadow_mode", "allow_active_response", "simple_mode_default",
    "sla", "webhooks", "jira", "thehive", "retention", "require_2fa_for_admins",
    "floors", "routes", "autoclose", "profile", "teams", "pagerduty", "oidc", "require_evidence_review",
    "resummarise_growth",
)
# allow_active_response can only be turned on from the config file, never from the browser.
UI_FORBIDDEN_ENABLE = ("allow_active_response",)


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


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _read_yaml(p: Path) -> dict:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise SieveError(CONFIG_INVALID, f"Config file {p} is not valid YAML: {e}",
                         "Fix the YAML syntax, or copy config/sieve.example.yaml again.") from e


def _validation_message(e: ValidationError) -> str:
    first = e.errors()[0]
    loc = ".".join(str(x) for x in first["loc"])
    return f"{loc}: {first['msg']}"


def load_settings(path: str | None = None) -> Settings:
    path = path or os.environ.get("SIEVE_CONFIG", "config/sieve.yaml")
    raw: dict = {}
    p = Path(path)
    if not p.exists() and (p.parent / "sieve.example.yaml").exists():
        p = p.parent / "sieve.example.yaml"  # first run: start from the documented defaults
    if p.exists():
        raw = _read_yaml(p)
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
    data_dir = Path(raw.get("data_dir", "./data"))
    override = data_dir / "settings.override.yaml"
    if override.exists():
        over = {k: v for k, v in _read_yaml(override).items() if k in EDITABLE_SECTIONS}
        if not raw.get("allow_active_response"):
            over.pop("allow_active_response", None)
        raw = _deep_merge(raw, over)
    if os.environ.get("SIEVE_SHADOW_MODE", "").lower() in ("1", "true", "yes"):
        raw["shadow_mode"] = True
    try:
        s = Settings(**raw)
    except ValidationError as e:
        raise SieveError(CONFIG_INVALID, f"Config is invalid: {_validation_message(e)}",
                         "Compare your file with config/sieve.example.yaml.") from e
    d = Path(s.data_dir)
    if not s.secret_key:
        s.secret_key = _secret_file(d, ".secret_key")
    if not s.ingest_token:
        s.ingest_token = _secret_file(d, ".ingest_token")
    return s


def public_view(s: Settings) -> dict:
    """Settings as the UI sees them: editable sections only, no secrets (they are never in Settings)."""
    d = s.model_dump(include=set(EDITABLE_SECTIONS))
    d["config_path"] = os.environ.get("SIEVE_CONFIG", "config/sieve.yaml")
    return d


def apply_update(s: Settings, patch: dict) -> tuple[Settings, dict]:
    """Validate a partial update against the full model and return (new_settings, applied_patch).

    Raises SieveError(CONFIG_INVALID) with the field path on any validation problem, so nothing is
    half-applied. Lists are replaced, mappings are merged.
    """
    unknown = sorted(set(patch) - set(EDITABLE_SECTIONS))
    if unknown:
        raise SieveError(CONFIG_INVALID, f"These settings cannot be changed from the UI: {', '.join(unknown)}",
                         "Change bootstrap settings in the config file and restart Sieve.", status=422)
    for k in UI_FORBIDDEN_ENABLE:
        if patch.get(k) and not getattr(s, k):
            raise SieveError(CONFIG_INVALID, "Active response can only be enabled in the config file.",
                             "Set allow_active_response: true in config/sieve.yaml and restart.", status=422)
    merged = _deep_merge(s.model_dump(), patch)
    try:
        new = Settings(**merged)
    except ValidationError as e:
        raise SieveError(CONFIG_INVALID, f"Invalid setting {_validation_message(e)}",
                         "Fix the highlighted value and save again.", status=422) from e
    return new, patch


_write_lock = threading.Lock()


def save_override(s: Settings, patch: dict) -> None:
    """Merge the patch into the override file atomically (write temp, then rename)."""
    p = s.override_path
    with _write_lock:
        current = _read_yaml(p) if p.exists() else {}
        merged = _deep_merge(current, patch)
        tmp = p.with_suffix(".tmp")
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(yaml.safe_dump(merged, sort_keys=False))
            os.chmod(tmp, 0o600)
            tmp.replace(p)
        except OSError as e:
            raise SieveError(CONFIG_READONLY, f"Could not save settings: {e.strerror}", status=500) from e

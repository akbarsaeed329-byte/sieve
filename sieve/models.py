"""Core data model (see research doc, Section 10.2)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(d: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; everything in Sieve is UTC."""
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


class QueueItem(Base):
    """Durable inbox: every raw alert lands here before any processing."""
    __tablename__ = "queue"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|done|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="wazuh")  # wazuh|pull|restore|selftest|demo|cli
    bypass_filter: Mapped[bool] = mapped_column(Boolean, default=False)  # set only for analyst-restored alerts


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grouping_key: Mapped[str] = mapped_column(String(300), index=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    score: Mapped[float] = mapped_column(Float, default=0)
    band: Mapped[str] = mapped_column(String(16), default="low", index=True)
    breakdown: Mapped[list] = mapped_column(JSON, default=list)
    overrides: Mapped[list] = mapped_column(JSON, default=list)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tripwire: Mapped[bool] = mapped_column(Boolean, default=False)
    tripwire_hits: Mapped[list] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notified_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    notify_ref: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    playbook: Mapped[str | None] = mapped_column(String(40), nullable=True)
    partial_context: Mapped[bool] = mapped_column(Boolean, default=False)
    context_notes: Mapped[list] = mapped_column(JSON, default=list)
    novelty: Mapped[bool] = mapped_column(Boolean, default=False)
    intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    human_band: Mapped[str | None] = mapped_column(String(16), nullable=True)   # shadow-mode validation
    human_band_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_selftest: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    sla_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    merged_into: Mapped[int | None] = mapped_column(Integer, nullable=True)
    maintenance: Mapped[str | None] = mapped_column(String(300), nullable=True)
    explained_count: Mapped[int] = mapped_column(Integer, default=0)
    correlations: Mapped[list] = mapped_column(JSON, default=list)
    ticket_ref: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    team: Mapped[str | None] = mapped_column(String(80), nullable=True)
    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", order_by="Alert.timestamp")
    explanations: Mapped[list[Explanation]] = relationship(back_populates="incident",
                                                          order_by="Explanation.created_at")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wazuh_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    level: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    groups: Mapped[list] = mapped_column(JSON, default=list)
    mitre_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)
    untrusted: Mapped[dict] = mapped_column(JSON, default=dict)
    full_log: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")


class Suppression(Base):
    __tablename__ = "suppressions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    wazuh_id: Mapped[str] = mapped_column(String(120), index=True)
    rule_id: Mapped[str] = mapped_column(String(32))
    level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # kept so a reviewer can restore it
    sampled: Mapped[bool] = mapped_column(Boolean, default=False)
    sample_week: Mapped[str | None] = mapped_column(String(10), nullable=True, index=True)  # ISO week, 2026-W42
    review_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)  # noise|restored
    reviewed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    restored_queue_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Explanation(Base):
    __tablename__ = "explanations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="summary")  # summary|investigation|nis2
    provider: Mapped[str] = mapped_column(String(80))
    model: Mapped[str] = mapped_column(String(120))
    summary: Mapped[dict] = mapped_column(JSON)
    validation: Mapped[dict] = mapped_column(JSON)
    hypotheses: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    steps_taken: Mapped[int] = mapped_column(Integer, default=0)
    budget_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    prompt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident: Mapped[Incident] = relationship(back_populates="explanations")


class Baseline(Base):
    """First-seen memory: (entity, feature) pairs, e.g. ('user:deploy@web-01', 'srcip:203.0.113.45')."""
    __tablename__ = "baselines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(250), index=True)
    feature: Mapped[str] = mapped_column(String(250), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    count: Mapped[int] = mapped_column(Integer, default=1)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin|analyst|viewer
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(200), nullable=True)   # encrypted, see secrets_store
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    trainee: Mapped[bool] = mapped_column(Boolean, default=False)
    sso_subject: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Invite(Base):
    """One-time invite. Only a SHA-256 of the token is stored."""
    __tablename__ = "invites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by: Mapped[str | None] = mapped_column(String(80), nullable=True)


class ChecklistTick(Base):
    __tablename__ = "checklist"
    __table_args__ = (UniqueConstraint("incident_id", "user_id", "step_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    step_id: Mapped[str] = mapped_column(String(40))
    checked: Mapped[bool] = mapped_column(Boolean, default=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelCache(Base):
    __tablename__ = "intel_cache"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    indicator: Mapped[str] = mapped_column(String(120), index=True)
    data: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelUsage(Base):
    __tablename__ = "intel_usage"
    __table_args__ = (UniqueConstraint("source", "day"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(40))
    day: Mapped[str] = mapped_column(String(10))   # YYYY-MM-DD (UTC)
    count: Mapped[int] = mapped_column(Integer, default=0)


class Notification(Base):
    """One row per delivery attempt; drives the metrics page and the 'channel failing' banner."""
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    channel: Mapped[str] = mapped_column(String(32))
    phase: Mapped[str] = mapped_column(String(8), default="send")   # send|edit|digest|test
    band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    shadow: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)   # alert received -> message sent
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class LlmCall(Base):
    __tablename__ = "llm_calls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(80))
    model: Mapped[str] = mapped_column(String(120), default="")
    purpose: Mapped[str] = mapped_column(String(24), default="summary")
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    error_code: Mapped[str | None] = mapped_column(String(24), nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class TestResult(Base):
    """Detection test outcomes (Atomic Red Team replays, benchmark runs) for the coverage map."""
    __tablename__ = "test_results"
    __test__ = False  # not a pytest class
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique: Mapped[str] = mapped_column(String(16), index=True)
    outcome: Mapped[str] = mapped_column(String(16))   # detected|missed
    source: Mapped[str] = mapped_column(String(40), default="atomic-red-team")
    detail: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class KV(Base):
    """Small app-state store (setup progress, last digest time). Not for secrets."""
    __tablename__ = "kv"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class SecretRecord(Base):
    """Encrypted secrets entered in the UI (Fernet, key derived from data/.secret_key). Never returned."""
    __tablename__ = "secrets"
    name: Mapped[str] = mapped_column(String(80), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(80), default="")


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    author: Mapped[str] = mapped_column(String(80))
    body: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertException(Base):
    """An approved, scoped, expiring exception: matching alerts are suppressed with this reason.
    Created by a human (often from a false-positive verdict). Tripwire hits are never excepted."""
    __tablename__ = "exceptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    srcip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    from_incident: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class MaintenanceWindow(Base):
    """Approved maintenance. Alerts are kept and labelled; only non-critical notifications are held."""
    __tablename__ = "maintenance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_name: Mapped[str] = mapped_column(String(200))      # exact name, or * for all hosts
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(300))
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiToken(Base):
    """Bearer tokens for automation. Only a SHA-256 is stored; the token is shown once."""
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(12))
    role: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class CorrelationRule(Base):
    """User-defined sequence rule: FIRST then THEN, on the same entity, within N minutes -> band."""
    __tablename__ = "correlation_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    first: Mapped[dict] = mapped_column(JSON)          # {"rule_ids": [...], "groups": [...], "min_count": 1}
    then: Mapped[dict] = mapped_column(JSON)
    same: Mapped[list] = mapped_column(JSON, default=list)   # any of srcip, user, agent_name
    within_minutes: Mapped[int] = mapped_column(Integer, default=10)
    band: Mapped[str] = mapped_column(String(16), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits: Mapped[int] = mapped_column(Integer, default=0)


class PracticeAttempt(Base):
    """Training mode: a trainee's blind verdict on a closed incident, compared with the real outcome."""
    __tablename__ = "practice"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(24))     # real|false_positive
    band: Mapped[str] = mapped_column(String(16))
    correct_verdict: Mapped[bool] = mapped_column(Boolean)
    correct_band: Mapped[bool] = mapped_column(Boolean)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Append-only: triggers in db.py reject UPDATE and DELETE."""
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)



# Changelog

## 0.4.0 (2026-10-18)
### Added
- Pilot report (before/after on your data, agreement with analysts, hours saved with your assumption) and an
  injection self-test that poisons copies of your own incidents in memory.
- AI governance page (what each model receives and never receives, recent AI calls) and scoped, per-tenant,
  rate-limited API tokens: an MCP gateway.
- Multi-tenancy for MSSPs: agent-to-customer mapping from Wazuh agent groups or host patterns, strict isolation
  (404 on every incident route across tenants, no cross-tenant grouping or exceptions), cross-customer attacker view,
  white-label reports, usage counters, customer switcher.
- Regulatory clocks per incident (NIS2, DORA with RTS 2024/1772 classification helper and 4 h / 24 h cap, GDPR 72 h)
  and a sealed (SHA-256 + HMAC) evidence pack with verification.
- Workflow rules (assign, tag, team, notify, page on-call, webhook, Jira), investigation report export, stale-summary badge.
- Vulnerability term in the score from Wazuh vulnerability data; silent-source incidents judged against each agent's
  rhythm; rules that went quiet; reviewed rule drafts for coverage gaps with backtest.
- MISP (lookup and sightings), AlienVault OTX and abuse.ch ThreatFox enrichers.
- Telegram and Slack buttons (verified webhooks, one-time account linking), installable PWA with Web Push, on-call rotations.
### Fixed
- Leftovers of an interrupted earlier attempt (duplicate tables, fields and settings; calls to missing functions).
- Compliance column missing on incidents; provider-only pages shown to customers; five pages crashing on refused requests.

## 0.3.0 (2026-10-18)
Built from what users of Wazuh, the Wazuh Alert Manager plugin, AI SOC tools and SOAR platforms ask for.
### Added
- Severity floors: Wazuh level 12+, account creation on critical assets, credential dumping (High); ransomware-like impact (Critical).
- Correlation rules ("A then B, same entity, within N minutes") with a 30-day backtest before saving.
- Precedent panel: how similar incidents were closed before, by whom, with their notes.
- Team routing by host pattern or asset tag, with per-team Telegram/Slack/email and auto-assignment.
- Graduated auto-close: per rule, only after 30+ verdicts at 95%+ agreement, never for tripwire/override/correlation; reopening revokes it.
- Weight-tuning suggestions from your verdicts (never lose a real notification; admin applies).
- Re-summarise incidents that grow by 50%; company profile (AI context, off-hours facts).
- Verify-before-close for High/Critical; decision-trace export for audits.
- Ask Sieve (deterministic answers, guarded AI phrasing) and a read-only MCP server (`sieve mcp`).
- Training mode (blind practice on closed incidents).
- Microsoft Teams, PagerDuty (trigger and auto-resolve), Jira two-way sync, Wazuh dashboard deep links.
- OIDC single sign-on (Entra ID, Google, Okta, Keycloak) with PKCE, nonce and JWKS verification; group-to-role mapping.
- Batched ingest; load test (~190 alerts/s per worker on SQLite); signed releases with SBOM and provenance.
### Fixed
- Weight-search could get stuck when the fix needed two coordinated changes (found by its own test).

## 0.2.0 (2026-10-18)
Driven by market research and user feedback (docs/COMPARISON.md) and a full QA pass (docs/QA_REPORT.md).
### Added
- Case management: owner, notes, tags, SLA timers per band, one escalation when overdue, merge, shift handover.
- Feedback loop: a false-positive verdict proposes a narrow, expiring exception; Tuning page ranks noisy rules.
- Approved maintenance windows (labels alerts, holds non-critical notifications; critical still notifies).
- Executive report (printable), email notifier, signed webhooks, Jira issues, TheHive alerts.
- API tokens, TOTP two-factor sign-in with optional admin requirement, per-IP rate limits.
- Wazuh indexer pull mode, data retention, `sieve backup` and `sieve purge`.
### Fixed
- Repeat tripwire hits re-notified; tripwire hits were not linked to their alerts.
- Layout overflow on Coverage, Metrics (phone) and long values on the incident page.

## 0.1.0.dev0 (2026-10-17)

### Fixed (starter defects)
- Brute force followed by a successful login now becomes one Critical incident (grouping, chain linking,
  tactic normalisation, overrides). The starter produced two High incidents.
- Removed the duplicate, non-importable implementation (`api/app.py`, `engine.py`, `scoring.py`,
  `providers.py`); see ADR-003.
- One notification per incident per band instead of one per alert.
- Demo alerts now go through the durable queue.
- Wazuh `ossec.conf` snippet used `<n>` instead of `<name>`.
- `mask_for_cloud` was documented but not implemented.

### Added
- Everything in MASTER_AI_PROMPT Phase 2 (2.1 to 2.10) and Phase 3 items 3.1 to 3.6; see docs/STATUS.md.
- Validation: number, IP, echo-of-attacker-text and tripwire checks on model output; strict ATT&CK catalogue.
- CSRF, invites, last-admin protection, encrypted secret store, append-only audit enforced by the database.
- 163 tests at 0.1 (206 at 0.2; 88% coverage on pipeline and llm), PoisonedLogs harness, CI jobs for web budget and benchmark.

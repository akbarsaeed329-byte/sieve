# Changelog

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

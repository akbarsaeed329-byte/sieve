# Changelog

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
- 163 tests (88% coverage on pipeline and llm), PoisonedLogs harness, CI jobs for web budget and benchmark.

# Status: what exists vs. the plan (v0.2.0, 2026-10-18)

done = works and is tested; partial = works with stated limits; todo = not started. Item numbers refer to
MASTER_AI_PROMPT.md.

| Area | State | Notes |
| --- | --- | --- |
| Durable queue, idempotent replay, retries (5) | done | contract 4; crash/restart test |
| Normalise + untrusted tagging (IP/user validation, rule.description untrusted) | done | |
| Tripwire (rules), never suppressed, its own notification | done | ADR-010; classifier is todo |
| Filter with reasons; context-aware level filter | done | |
| Grouping by alert time + chain linking | done | ADR-003 |
| Deterministic severity + overrides (score.py only) | done | V (vulnerability) term is todo: needs Wazuh vuln API |
| 2.1 Web UI: setup wizard, Overview, Incidents, Incident detail | done | J/K/A/E keys; verified in headless Chromium |
| 2.1 Settings: Integrations, Models, Plugins, Rules, Users, Audit | done | drag + keyboard reorder, schema forms |
| 2.1 Health, Metrics (/reports), Coverage map, Suppression audit | done | |
| 2.1 Dark mode | partial | follows the OS setting; no manual toggle |
| 2.2 Playbook loader, routes, per-user checklist, templating | done | |
| 2.3 Suppressions sample/review/restore, baselines, audit, users, invites, settings | done | |
| 2.4 AbuseIPDB enricher (cache, daily limit, partial context) | done | OTX and abuse.ch todo |
| 2.5 Rolling 14-day novelty (logins, processes) | done | country and quiet-hour baselines todo |
| 2.6 Hypothesis investigation (templates only, 6-call cap) | done | ADR-009; checks run without AI too |
| 2.7 Slack (Block Kit, bot or webhook), Discord, email | done | |
| 2.8 Wazuh active response (off by default, confirm, audited) | done | tested with mocked Wazuh API only |
| 2.9 NIS2 early-warning draft (24 h / 72 h / 1 month) | done | drafting aid; never sent |
| 2.10 Shadow mode + human band + agreement (kappa) | done | |
| 3.1 Rule backtest (Sigma subset, single Wazuh rule) | partial | local store only; indexer backtest todo |
| 3.2 Coverage map | done | rules from Wazuh API, else observed alerts |
| 3.3 Benchmark harness, CI with mock model | done | seed dataset is synthetic; lab dataset todo |
| 3.4 Entity graph (Cytoscape, bundled, lazy) | done | |
| 3.5 STIX 2.1 export | done | TheHive / MISP plugins todo |
| 3.6 Manager and technical digest (daily) | done | |
| Case management: owner, notes, tags, SLA, escalation, merge | done | v0.2 |
| False-positive feedback → scoped expiring exceptions; tuning page | done | v0.2 |
| Maintenance windows | done | v0.2 |
| Executive report, shift handover | done | v0.2 |
| Signed webhooks, Jira, TheHive, email, API tokens | done | v0.2 |
| 2FA (TOTP), admin 2FA policy, rate limits, retention, backup command | done | v0.2 |
| Wazuh indexer pull mode | done | v0.2 |
| Plugin SDK out-of-process | todo | ADR-006 (in-process with containment for now) |
| SSO (OIDC/SAML) | todo | |
| Alembic migrations | todo | ADR-005 (additive migrations for 0.x) |
| Real-model benchmark, ablations, usability study | todo | needs the Phase-0 lab |

Open question for maintainers: default weights notify only 58% of seed true attacks (single-alert attacks score
Medium). Tune on lab data or lower `notify.min_band`; see docs/EVALUATION.md.

| Multi-tenant (MSSP) | todo | |

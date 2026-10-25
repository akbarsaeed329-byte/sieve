# Status: what exists vs. the plan (v0.5.0, 2026-10-18)

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
| Severity floors (level 12+, account creation on critical assets, credential dumping, ransomware) | done | v0.3; closes the single-alert notification gap |
| Correlation rules with 30-day backtest | done | v0.3 |
| Precedent panel ("seen before") | done | v0.3 |
| Team routing (host patterns, asset tags) with auto-assign | done | v0.3 |
| Graduated auto-close (earned per rule, revocable) | done | v0.3 |
| Weight-tuning suggestions from verdicts | done | v0.3; applied only by an admin |
| Re-summarise when an incident grows | done | v0.3 |
| Company profile (AI context, off-hours facts) | done | v0.3 |
| Verify-before-close for High/Critical | done | v0.3 |
| Decision-trace export | done | v0.3 |
| Ask Sieve (deterministic answers) + MCP server | done | v0.3 |
| Training mode (practice on closed incidents) | done | v0.3 |
| Microsoft Teams, PagerDuty (trigger + resolve), Jira two-way | done | v0.3 |
| Wazuh dashboard deep links (/go/alert/{id}) | done | v0.3; a native dashboard plugin is todo |
| SSO (OIDC with PKCE) | done | v0.3; SAML is todo |
| Signed releases, SBOM, provenance | done | v0.3 release workflow |
| Pilot report and injection self-test on your own data | done | v0.4 |
| AI governance page; scoped, per-tenant, rate-limited tokens (MCP gateway) | done | v0.4 |
| Multi-tenancy (agent groups or host patterns), isolation, cross-customer attackers, white-label reports | done | v0.4 |
| NIS2 / DORA / GDPR clocks, DORA classification helper, sealed evidence pack | done | v0.4 |
| Workflow rules, investigation report, stale-summary badge | done | v0.4 |
| Vulnerability term, silent sources, quiet rules, rule drafts for gaps | done | v0.4 |
| MISP (two-way), OTX, ThreatFox | done | v0.4 |
| Telegram/Slack buttons, PWA push, on-call | done | v0.4; Teams buttons need a Bot Framework app (todo) |
| Explainable UEBA (login hours, volume spikes) | done | v0.5 |
| Risk-based alerting | done | v0.5 |
| Custom dashboards | done | v0.5 |
| Plugin SDK out-of-process | todo | ADR-006 (in-process with containment for now) |
| Alembic migrations | todo | ADR-005 (additive migrations for 0.x; dialect-aware for PostgreSQL) |
| Real-model benchmark, ablations, usability study | todo | needs the Phase-0 lab |

Validation still needed: everything has been tested against stand-ins and a synthetic seed set, not a live Wazuh
lab with real users. See docs/EVALUATION.md.

| High availability (PostgreSQL, multiple workers, leader lock) | done | v0.5; tested with 2 concurrent workers on PostgreSQL 16 |
| Native Wazuh dashboard plugin | todo | |

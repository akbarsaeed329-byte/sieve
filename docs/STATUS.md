# Status: what exists vs. the plan

Legend: done = works and is tested in v0.0.1; partial = started, needs work; todo = not started.

| Area | State | Notes |
| --- | --- | --- |
| Durable SQLite queue, idempotent processing | done | `sieve/worker.py`, retries up to 5 with error kept |
| Wazuh push integration + token-protected ingest | done | `integrations/wazuh/`, `/api/ingest/wazuh` |
| Normalisation, untrusted-field tagging | done | `sieve/pipeline/normalise.py` |
| Tripwire (rule-based) | done | `sieve/pipeline/tripwire.py`; small classifier is todo |
| Filter with recorded reasons, context-aware level filter | done | low events that continue an open incident are kept |
| Grouping + chain linking | done | key (rule, host, actor) then (host, actor) link |
| Deterministic severity + overrides | done | `sieve/pipeline/scoring.py`; vulnerability term V is todo |
| First-seen baseline | partial | successful logins only; process/country/hour baselines todo |
| Threat intel | partial | offline blocklist only; AbuseIPDB/OTX/abuse.ch plugins todo |
| Evidence-linked facts (no AI) | done | `engine.facts()` |
| LLM fencing, masking, validation | done | `sieve/llm/fence.py` |
| Provider chain: retries, 429, circuit breaker, budget | done | Ollama + OpenAI-compatible |
| Hypothesis investigation with read-only query templates | todo | research doc 6.6 |
| Two-phase notifications | done | console + Telegram (send, then edit) |
| Slack, Discord, email, backup channel | todo | |
| Accounts, roles, Argon2, lockout, CSRF, audit log | done | invites, TOTP, SSO todo |
| Web app: setup, login, overview, incident, hidden alerts, health | done | vanilla JS; settings pages todo |
| Settings UI (integrations, models drag-order, plugins, rules, users) | todo | config is YAML for now |
| Plugin SDK with permissions, out-of-process | todo | research doc 10.3 |
| Wazuh indexer/API pull, "Show query" deep link | partial | query string shown; pull mode todo |
| Entity graph, rule backtesting, coverage map, shadow mode | todo | Phase 4 |
| PoisonedLogs benchmark + harness | todo | docs/EVALUATION.md |
| NIS2 deadline helper, manager digest | todo | Phase 4 |
| Docker image, compose, CI | done | not yet published to GHCR |

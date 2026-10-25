# Master AI Coding Prompt — Sieve (read this before touching a single file)

You are completing **Sieve**, a free, open-source, local-first security alert triage
tool for Wazuh.  Everything designed, researched and prototyped is already in this
repository.  Your job is to build it to completion — full production quality, not
demo quality.  Read every file in `sieve/`, `tests/`, `docs/adr/` and `config/`
before writing a single line.

---

## Non-negotiable design contracts (do not break these, ever)

1. **The LLM never decides severity, band or response actions.**
   Severity comes from `sieve/pipeline/score.py` only.
   If you find yourself writing `severity = llm_response["severity"]` anywhere, stop.

2. **Every attacker-controlled field is treated as hostile.**
   The list is `UNTRUSTED_PATHS` in `sieve/pipeline/normalise.py`.
   If you add any new field that a remote party can write, add it to that list too.
   Never concatenate an untrusted field directly into a prompt string.
   Always go through `sieve/llm/fence.py`.

3. **Tripwire hits are never suppressed.**
   `sieve/pipeline/filter.py::suppression_reason` returns `None` when
   `tripwire_hit=True`.  Do not add a condition that overrides this.

4. **No alert is ever lost.**
   Every incoming alert is written to the `queue` table BEFORE processing.
   On restart the worker replays pending items.  Do not skip this write.

5. **Phase-1 notification is always sent, even if the LLM fails.**
   `sieve/notify/dispatch.py::send_instant` must never wait on the LLM.
   The LLM edit is a separate async step in `edit_with_ai`.

6. **Graceful degradation everywhere.**
   Every external call (Wazuh API, LLM, threat intel, Telegram) must be wrapped
   in try/except with a recorded error and a fallback.  A broken plugin must not
   crash the main pipeline.

7. **Every error has a stable code and a human-readable fix.**
   Error codes are in `sieve/errors.py`.  Add new ones there; never invent codes
   inline.  The fix string must tell the user exactly what to do.

8. **Tests must pass before any PR is merged.**
   Run `pytest -v` and `ruff check sieve tests` before pushing.
   Coverage target: 80 %+ on `sieve/pipeline/` and `sieve/llm/`.

---

## What is already built (do not rewrite these)

- `sieve/pipeline/normalise.py` — raw alert → NormAlert, untrusted field tagging
- `sieve/pipeline/tripwire.py` — injection detection rules
- `sieve/pipeline/filter.py` — suppression with recorded reasons
- `sieve/pipeline/group.py` — sliding-window incident grouping + chain scoring
- `sieve/pipeline/score.py` — deterministic severity formula + override rules
- `sieve/llm/fence.py` — prompt construction (trusted / ATTACKER_DATA separation)
- `sieve/llm/validate.py` — post-generation validation (evidence, ATT&CK IDs, playbooks)
- `sieve/llm/client.py` — provider fallback chain, circuit breaker, rate limiter
- `sieve/notify/console.py` — console notifier (always-on fallback)
- `sieve/notify/telegram.py` — Telegram send + edit
- `sieve/notify/dispatch.py` — phase-1 / phase-2 dispatch
- `sieve/worker.py` — async triage worker (queue → pipeline → notify)
- `sieve/auth.py` — Argon2id passwords, session cookies, role guards, lockout
- `sieve/app.py` — FastAPI factory + lifespan
- `sieve/api/ingest.py` — Wazuh webhook endpoint
- `sieve/api/incidents.py` — CRUD + workflow (acknowledge / resolve / FP)
- `sieve/api/auth_routes.py` — login / logout / setup / me
- `sieve/api/health.py` — health endpoint
- `sieve/api/metrics.py` — Prometheus-compatible metrics
- `sieve/cli.py` — serve / demo / ingest / version
- `sieve/demo.py` — self-contained demo with 50 alerts + poisoned variant
- `sieve/models.py` — all SQLAlchemy models
- `sieve/config.py` — YAML + env-var config with Pydantic validation
- `sieve/db.py` — SQLite WAL engine factory
- `sieve/errors.py` — error catalogue
- `sieve/playbooks/PB-BRUTE.yaml`, `PB-NEWADMIN.yaml`
- `integrations/wazuh/custom-sieve.py` — Wazuh integration script
- `tests/test_tripwire.py`, `test_normalise.py`, `test_score.py`, `test_filter.py`
- `docs/adr/ADR-001`, `ADR-002`
- `config/sieve.example.yaml`, `Dockerfile`, `docker-compose.yml`

---

## What you must build next (Phase 2: web UI and remaining features)

Work in this order.  Each item must have tests before you move to the next.

### 2.1 Web UI (SvelteKit, static build served by FastAPI)

Directory: `sieve/web/`

Build every screen from the wireframes and high-fidelity designs.
The design file is at: https://claude.ai/artifact/HRAyfrm2ySabKRncQU5oph
The research document with all specs is at: https://claude.ai/code/artifact/47c827a5-82ba-4d52-9700-87befdce34b2

Screens to build (in priority order):
1. **First-run setup wizard** (5 steps: admin account → Wazuh → AI model → notifications → test alert).
   Each step has a "Test" button that calls the relevant `/api/health` sub-check.
   The wizard must complete in under 10 minutes from a cold machine.
2. **Overview** — "Needs you now" hero cards (critical incidents + any tripwire),
   four KPI tiles (alerts in / notifications / suppressed / median ack time),
   incident queue table with severity pills (colour + text), age, host, user, status.
   Keyboard shortcuts: J/K to move rows, A to acknowledge, E to open evidence.
3. **Incident detail** — tripwire warning banner (shown only when incident.tripwire = true),
   evidence-linked summary (each sentence has a numbered reference that scrolls to the
   log line), hypotheses tested section, score breakdown table, response checklist
   (tickable, persisted per user), timeline, evidence panel with untrusted fields in
   dashed amber box.
4. **Settings pages**: Integrations (Wazuh connection test), Models (fallback chain,
   drag-to-reorder, quota bar, privacy toggle), Plugins (enable/disable, settings form
   generated from plugin manifest), Rules (allowlists, min level, asset criticality tags),
   Users (invite link, role assignment), Audit log (read-only table).
5. **Health page** — status light per component, queue depth, circuit-breaker state.
6. **Metrics page** — charts: alerts in vs notifications out (line), incidents by band
   (bar), LLM calls per day (bar), suppression rate over time.
7. **Coverage map** — MITRE ATT&CK heatmap: grey = no rule, yellow = rule exists,
   green = tested and detected (from benchmark results), red = tested and missed.
8. **Suppression audit** — weekly random sample of 20 suppressed alerts; analyst marks
   each noise or restore; restored ones re-enter the queue.

Design system tokens (from hi-fi screens):
- Font: IBM Plex Sans (UI), IBM Plex Mono (data/code)
- Brand: #0B6E69 (deep teal)
- Neutrals: ink #16201E, muted #56625F, line #D5DBD7, ground #F2F4F1
- Severity pills: critical bg #FBE4E1 text #8F1C13 / high bg #FCE9DA text #8A3D08 /
  medium bg #F6EFD2 text #6B5200 / low bg #E1EAF6 text #1F4677
- Untrusted fields: dashed #B7791F border on #FFF8EA background, labelled with field path
- Spacing: 4 px grid; 8, 16, 24, 32 steps; card radius 12 px; input radius 8 px
- Dark mode: planned; same token structure, inverted neutrals

Accessibility requirements:
- WCAG 2.2 AA contrast on all text
- Severity never conveyed by colour alone (always includes a text label)
- Full keyboard navigation; all interactive elements min 44 px touch target
- Screen reader labels on all charts

### 2.2 Playbook loader and checklist API

- Load all `sieve/playbooks/*.yaml` on startup.
- Add `GET /api/playbooks` and `GET /api/playbooks/{id}` routes.
- Add `POST /api/incidents/{id}/checklist/{step_id}` to tick/untick a step (persisted per user per incident).
- The score module's `allowed_playbooks` comes from the loaded playbook IDs.
- Template variables (`{user}`, `{srcip}`, `{agent_name}`) are substituted from the incident at render time.

### 2.3 Remaining API routes

- `GET /api/suppressions?sampled=true` — weekly sample for the audit page
- `POST /api/suppressions/{id}/review` — body `{"outcome": "noise"|"restore"}`; restore re-enqueues the alert
- `GET /api/baselines?entity=...` — first-seen records for the investigate page
- `GET /api/audit?limit=100&offset=0` — append-only audit log
- `POST /api/users/invite` (admin only) — returns a one-time invite URL
- `POST /api/users/{id}/role` (admin only) — change role
- `PUT /api/settings` (admin only) — update runtime settings and reload config

### 2.4 Threat-intel enrichment (AbuseIPDB plugin)

File: `sieve/plugins/enrichers/abuseipdb.py`

- Implement the plugin interface: `async def enrich(srcip: str, settings) -> dict`
- Cache results in SQLite for 1 hour (table: `intel_cache`)
- Respect the free-tier daily limit (1,000 requests/day); track usage, stop early
- When `SIEVE_ABUSEIPDB_KEY` is set, replace the static blocklist lookup in `worker.py`
- Return `{"ip": ..., "abuse_score": ..., "country": ..., "isp": ..., "reports": ..., "cached": bool}`

### 2.5 Baseline novelty using a rolling 14-day window

- The `Baseline` model in `models.py` already exists.
- In `worker.py::_check_novelty`, update `last_seen` and return `True` only when the
  feature has not been seen in the last 14 days (not just on first ever occurrence).
- Add `GET /api/baselines` route.

### 2.6 Hypothesis investigation (critical incidents only)

File: `sieve/llm/investigate.py`

- For `band == "critical"` incidents, run a bounded investigation loop (max 6 steps).
- The model may only call functions from a fixed template list:
  `FIRST_SEEN_LOGIN`, `HOST_ACTIVITY_NEXT_HOUR`, `OTHER_HOSTS_SAME_IP`,
  `RECENT_ALERTS_SAME_USER`, `SCHEDULED_JOBS_ON_HOST`
- Each template expands to a Wazuh indexer query with validated parameters (no raw query strings from the model).
- Results are stored as `hypotheses` in the `Explanation` model and shown in the UI.
- Budget: hard-stop at 6 LLM calls per investigation; store `steps_taken` and `budget_hit` flags.

### 2.7 Slack and Discord notifiers

Files: `sieve/notify/slack.py`, `sieve/notify/discord.py`

Both follow the same `send / edit` interface as `telegram.py`.
Use Slack Block Kit for rich formatting; Discord webhook for Discord.
The untrusted-field amber box must appear in both.
Test with a mock HTTP server (do not make real API calls in tests).

### 2.8 Wazuh active-response integration (off by default, human-approved)

File: `sieve/integrations/wazuh_response.py`

- Add `POST /api/incidents/{id}/response/{action}` (admin only)
- Actions: `firewall-drop` (block srcip), `disable-account` (lock user)
- Requires a second confirmation field `{"confirm": true}` in the body
- Calls Wazuh PUT /active-response endpoint with appropriate body
- Logs every execution to the audit table including the approving user
- Default: entirely disabled unless `allow_active_response: true` in config

### 2.9 NIS2 incident-reporting helper (Belgium / EU)

File: `sieve/api/nis2.py`

- Add `GET /api/incidents/{id}/nis2-draft` route
- Returns a JSON object with pre-filled fields for the CCB early-warning form:
  `incident_date`, `affected_systems`, `estimated_impact`, `initial_indicators`,
  `reporting_deadline` (24 h from `opened_at`), `draft_text`
- The draft text is generated by the LLM but is clearly labelled as a draft for human review.
- Never send to CCB automatically; this is a drafting aid only.

### 2.10 Shadow mode

- Add `shadow_mode: true` to config.
- When enabled: triage normally, record all verdicts, but send NO notifications.
- Add `GET /api/shadow/agreement?since=<iso_date>` which compares Sieve's bands
  against any human-recorded bands (via `POST /api/incidents/{id}/human-band`).
- Use this to validate the tool on a new environment before trusting it.

---

## Phase 3: professional features (after Phase 2 is merged)

### 3.1 Detection-rule backtest
Given a proposed Wazuh rule (Sigma format or raw rule XML), query the Wazuh indexer
against the last N days of alerts and report: how many times would it have fired,
what percentage were incidents vs. benign, and which known attacks would it have caught.

### 3.2 Coverage map
Build the MITRE ATT&CK heatmap widget (SVG or a JS library) showing:
- Grey: no Wazuh rule maps to this technique
- Yellow: at least one rule maps to it
- Green: tested via Atomic Red Team and detected in the last 30 days
- Red: tested and missed
Data source: Wazuh rule MITRE IDs + a `test_results` table populated by scheduled Atomic Red Team replays.

### 3.3 PoisonedLogs benchmark harness
File: `benchmark/run.py`

- Replay the labelled dataset in `benchmark/data/` against all four systems:
  B0 (raw Wazuh), B1 (naive LLM), Sieve-no-AI, Sieve-full
- Measure and export: notifications per 1,000 alerts, recall, injection success rate,
  tripwire detection rate, tripwire false-alarm rate, time-to-first-notification (p50/p95),
  LLM calls per 1,000 alerts, ECE (calibration), unsupported-claim rate
- Output: Markdown table + JSON for CI comparison
- The benchmark must be runnable in CI with a mock LLM (configurable)

### 3.4 Entity graph (Investigate screen)
Use Cytoscape.js (loaded from cdnjs.cloudflare.com) to render users, hosts, IPs and
processes as nodes connected by what happened between them in a 24-hour window.
Click a node to see all incidents involving it; highlight the blast radius.

### 3.5 STIX export and TheHive/MISP integration
Add `GET /api/incidents/{id}/stix` returning a STIX 2.1 bundle with the incident as
a `sighting` and indicators as `indicator` objects.
Add an optional plugin for TheHive case creation and MISP event creation.

### 3.6 Manager digest (two versions)
Daily report email / Telegram message:
- **Technical version**: incidents by band, mean ack time, top source IPs, top targeted
  hosts, detection coverage delta, suppression sample results.
- **Manager version**: "Your systems were probed 4,812 times. 4,806 were handled
  automatically. 6 needed a decision. Oldest open incident: 38 minutes."
The manager version must use no jargon, no IP addresses, no ATT&CK IDs.

---

## Coding standards (enforce strictly)

- Python 3.11+, type-annotated throughout (`from __future__ import annotations`)
- `ruff` for linting and formatting (config in `pyproject.toml`)
- SQLAlchemy 2.x ORM only; no raw SQL strings except in read-only query templates for the investigation loop
- All database writes go through `SessionLocal()` context manager; never hold a session across an `await`
- Secrets: read from environment variables via `os.environ.get(...)`; never from config YAML; never logged
- HTTP clients: `httpx.AsyncClient` only; always set a timeout; always handle `httpx.TimeoutException`
- Logging: `logging.getLogger("sieve.<module>")` everywhere; use structured fields not f-strings in `log.error`
- No `print()` in production code except `sieve/notify/console.py`
- Test files: one per module under test; use `pytest`, not `unittest`; use `pytest.mark.asyncio` for async tests
- Every new API endpoint needs: a route test, an auth test (unauthenticated → 401), a role test (wrong role → 403)

## File-naming conventions

- Pipeline modules: `sieve/pipeline/<stage>.py`
- Plugins: `sieve/plugins/<type>/<name>.py` (e.g. `enrichers/abuseipdb.py`, `notifiers/slack.py`)
- API routes: `sieve/api/<resource>.py`
- Tests: `tests/test_<module>.py`
- Playbooks: `sieve/playbooks/PB-<NAME>.yaml`
- ADRs: `docs/adr/ADR-<NNN>-<slug>.md`

## When you are unsure about a design decision

1. Check the research document first (Section 6 for pipeline, Section 9 for UI, Section 10 for stack)
2. Check the existing ADRs in `docs/adr/`
3. If still unsure, write a new ADR proposing the decision and ask for review before implementing

## Definition of done for each feature

- [ ] Code written and linted (`ruff check`)
- [ ] Tests pass (`pytest -v`, including new tests for the feature)
- [ ] Error handling follows the contract in Section 10.4 of the research document
- [ ] Any new untrusted field added to `UNTRUSTED_PATHS`
- [ ] Any new LLM prompt goes through `llm/fence.py`
- [ ] ADR written if the feature involves a significant design choice
- [ ] README updated if the feature changes the user-facing behaviour

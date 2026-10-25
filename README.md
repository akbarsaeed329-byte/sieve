<h1 align="center">Sieve</h1>
<p align="center">
  Free, local-first, injection-hardened triage layer for Wazuh.<br>
  <strong>Turns thousands of raw alerts into a few evidence-backed incidents, and cannot be talked out of a severity.</strong>
</p>

---

## What Sieve does

Sieve sits between Wazuh and your team. It:

1. **Filters and groups** raw alerts into incidents, and links chains such as "brute force, then a successful login".
2. **Scores severity with rules.** The AI explains; it never decides the band or any action.
3. **Treats every log field as hostile.** Attacker text that tries to steer the AI trips a wire and becomes its own alert.
4. **Shows its work.** Every sentence cites the log lines behind it; every suppressed alert has a reason and can be restored.
5. **Notifies at once** (Telegram, Slack, Discord, email) and edits the same message when the checked AI summary is ready.
6. **Learns from your verdicts.** A false positive becomes a narrow, expiring exception; noisy rules rise to the top.
7. **Runs the case.** Owner, notes, SLA timers and escalation, maintenance windows, shift handover, executive report,
   Jira / TheHive / signed webhooks.
8. **Gets smarter with your team.** Correlation rules you can test on history, "seen before" precedents, weight
   suggestions from your verdicts, auto-close that a rule has to earn, team routing, and a practice mode for juniors.
9. **Fits your stack.** Teams, PagerDuty, Jira (two-way), TheHive, webhooks, SSO, Wazuh dashboard links, and a
   read-only MCP server for your own AI assistant. Ask it questions in plain English.
10. **Works with no AI at all**, with a local model (Ollama), or with a cloud model (masked by default).

## How it compares (details and sources: [docs/COMPARISON.md](docs/COMPARISON.md))

| | Enterprise SIEM | AI SOC analyst SaaS | **Sieve** |
|---|---|---|---|
| Typical cost | per-GB, often six figures a year | from about $36k a year | **free, open source** |
| Where your logs go | vendor cloud or your cluster | vendor cloud | **stays on your machine** |
| Can the AI change severity? | n/a | model verdict | **no: rules decide; model output is evidence-checked** |
| Feedback loop, exceptions, SLA | add-ons / SOAR | varies | **built in** |
| Setup | weeks | hours | **minutes (wizard with live tests)** |

## Measured on the PoisonedLogs seed set (worst-case, obedient mock model)

| | Raw Wazuh | Naive LLM triage | **Sieve** |
|---|---|---|---|
| Notifications per 1,000 alerts | 449 | 688 | **31** |
| Injections that lowered a severity | – | 43% | **0%** |
| Poisoned alerts caught by the tripwire | – | – | **100%** |
| True attacks notified | 50% | 100% | **100%** |
| False alarms on benign scenarios | 40% | 80% | **0%** |

Synthetic seed data: these numbers check the design guarantees, not real-world accuracy. Details and caveats in
[docs/EVALUATION.md](docs/EVALUATION.md). Similar open-source projects, and how Sieve differs, are listed in
[docs/COMPARISON.md](docs/COMPARISON.md).

## Quick start

### Demo (no Wazuh, no AI)
```bash
pip install -e .
make demo          # loads demo alerts, serves http://localhost:8080
```
Open the page, create the admin account, and explore the incident with the poisoned username.

### Docker
```bash
make up            # Sieve only, on 127.0.0.1:8080
make up-ai         # Sieve + Ollama (pulls llama3.1:8b, about 5 GB)
docker compose --profile demo up   # optional: load demo alerts
```
The first visit opens a five-step setup wizard: admin, Wazuh, AI, notifications, test alert. Each step tests its
own connection and can be skipped.

## Connect Wazuh
1. Copy `integrations/wazuh/custom-sieve` and `custom-sieve.py` to `/var/ossec/integrations/` on the manager;
   `chmod 750` and `chown root:wazuh` both.
2. Print the token: `make token` (or `sieve token`).
3. Add `integrations/wazuh/ossec.conf.snippet.xml` to `ossec.conf` with your Sieve address and the token.
4. `systemctl restart wazuh-manager`.

Optional read-only API credentials (Settings, Integrations) add "Show query" links, investigation checks against
the indexer, the full coverage map, and human-approved active response.

## Safety model in one paragraph
Only `sieve/pipeline/score.py` sets severity. Model input is fenced (per-prompt fence ID, escaped, masked for
cloud) and model output is validated: sentences need real evidence, may not mention unknown IPs or invented
numbers, may not echo attacker text, and ATT&CK IDs must exist. Active response is off by default and every run
needs an admin to confirm it. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Project layout
```
sieve/
  pipeline/      normalise · tripwire · filter · group · score · facts · playbooks
  llm/           fence · validate · client (fallback chain) · explain · investigate · attack
  notify/        console · telegram · slack · discord · dispatch
  api/           ingest · auth · incidents · nis2 · admin · data · health · metrics
  plugins/       registry · enrichers/abuseipdb
  integrations/  wazuh (read-only) · wazuh_response (active response)
  web/           SvelteKit app (src/) and its build (build/)
benchmark/       generate.py (PoisonedLogs seed) · run.py (four-system harness)
docs/            ARCHITECTURE · STATUS · EVALUATION · ERROR_CODES · PLUGINS · adr/
```

## Develop
```bash
pip install -e ".[dev]"
make lint test     # 240 tests; 80%+ coverage required on pipeline and llm
make web           # rebuild the UI (Node 20+)
make bench         # PoisonedLogs harness
```
Read [MASTER_AI_PROMPT.md](MASTER_AI_PROMPT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before changing the LLM,
auth or plugin layers.

## Licence
Apache 2.0. Sieve talks to Wazuh's API and copies none of its GPL code.

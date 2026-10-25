# Architecture (short)

```
Wazuh manager --(integration push, token)--> /api/ingest/wazuh --> durable queue (SQLite)
   worker: normalise -> tripwire -> filter(reason) -> group/link -> score+context -> notify(send)
                                                                       \-> LLM gate -> fence -> provider chain -> validate -> notify(edit)
browser <-> FastAPI (session cookie + CSRF) <-> SQLite
```

Trust boundary: everything from Wazuh is attacker-influenced. Only `pipeline/scoring.py` sets severity. The LLM sees
untrusted text only inside nonce fences, can only reference evidence IDs and playbook step IDs that exist, and its output is
validated before anyone sees it.

## Threat model (STRIDE summary)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Tampering via poisoned log fields | fencing, structured output, validation, deterministic severity, tripwire | summary wording may still be skewed |
| LLM triggers an action | no action tools; active response is todo and will require human approval | low |
| Logs sent to a cloud LLM | local default, privacy notice, masking | user choice |
| Key theft | env vars only, never logged; non-root, read-only container | host compromise |
| Web UI access | localhost bind, Argon2, lockout, HttpOnly SameSite=Strict cookie, CSRF, CSP, XSS-safe rendering | weak admin password |
| Alert storm exhausts quotas | grouping, hourly LLM budget, circuit breakers | delayed AI summaries |
| Settings changed to hide alerts | append-only audit table, suppression reasons, random sample review | admin with host access |

Full design: the research document "AI-Assisted Wazuh Triage: Research, Design and Build Plan".

# Architecture

```
Wazuh manager --(integration push, Bearer token)--> /api/ingest/wazuh --> durable queue (SQLite, WAL)
   worker: normalise (tag untrusted, validate IP/user) -> tripwire -> filter (reason) -> group / chain-link
           -> enrich (assets, AbuseIPDB, 14-day baselines, 24 h host tactics) -> score.py (severity, bands, overrides)
           -> notify phase 1 (Telegram / Slack / Discord / console; shadow mode records only)
           -> background: LLM gate -> fence.py -> provider chain -> validate.py -> notify phase 2 (edit)
                          critical: read-only investigation checks (+ model loop if AI is on)
browser (SvelteKit static) <-> FastAPI (HttpOnly session + CSRF + roles) <-> SQLite
                                    \-> Wazuh API / indexer (read-only)  \-> active response (admin, confirmed, audited)
```

Trust boundary: everything from Wazuh is attacker-influenced, including rule descriptions (Wazuh can interpolate
log fields into them). Only `pipeline/score.py` sets severity. The model sees untrusted text only inside the
fenced ATTACKER_DATA block (per-prompt fence id; masked for cloud providers), can cite only evidence IDs and
playbook step IDs that exist, and its output is validated (evidence, IPs, numbers, ATT&CK catalogue, echo of
attacker text, tripwire on its own sentences) before anyone sees it.

## Threat model (STRIDE summary; full table in the research document, section 8)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Tampering via poisoned log fields | fencing, masking, validation incl. echo check, deterministic severity, tripwire | wording of a kept sentence may still be skewed |
| LLM triggers an action | the model has no tools; active response is admin-only, off by default, needs `confirm: true` | low |
| Logs sent to a cloud LLM | local default, privacy notice, masking on by default | user choice |
| Key theft | env or encrypted store, never logged or returned; non-root, read-only container, cap_drop ALL | host compromise |
| Web UI access | localhost bind, Argon2id, lockout, HttpOnly SameSite=Strict cookie, CSRF, strict CSP with hashes | weak admin password |
| Alert storm exhausts quotas | grouping, hourly LLM budget, circuit breakers, per-band notification dedup | delayed AI summaries |
| Settings changed to hide alerts | append-only audit (DB triggers), suppression reasons, weekly random sample, restore + flag | admin with host access |
| Malicious plugin | permission approval, containment wrapper | in-process until ADR-006 follow-up |

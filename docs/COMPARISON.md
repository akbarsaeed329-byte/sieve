# Where Sieve fits: market research and requirements (October 2026)

## What the market charges and what users complain about
* **Enterprise SIEM.** Per-GB pricing dominates. Published comparisons put Microsoft Sentinel pay-as-you-go
  around $5 per GB and Splunk ES deals for mid-size estates in the hundreds of thousands of dollars per year.
  Reviews on G2 and AWS Marketplace repeatedly name cost, complex licensing and query languages (SPL, KQL)
  as the barrier for new analysts; buyer guides call untuned SIEMs an alert-fatigue machine whose biggest hidden
  cost is analyst time.
* **Wazuh** (what Sieve sits on). Reviewers praise the price and rules but report noisy defaults and false
  positives, complex alerting, a UI that could be better, weak reporting for executives, no AI or ML, and
  case management that has to be bolted on (TheHive, MISP, Cortex).
* **AI SOC analysts** (Dropzone, Prophet, 7AI, Radiant) and **hyperautomation** (Torq, Tines, Swimlane).
  Strong at autonomous triage and visible reasoning; buyer comparisons list Dropzone from about $36k per year
  and Torq HyperSOC around $450k per year. Focused triage tools leave response and case management to other
  products. Practitioner guides stress that verdicts must be explainable and that feedback must tune
  detection.
* **Research.** SANS 2025 reports 66% of SOC teams cannot keep pace with alert volume; a USENIX study of SOC
  analysts found context and baselining matter most; an arXiv survey highlights trust problems with black-box
  AI verdicts.

## Genuine requirements we extracted, and how Sieve meets them

| Requirement (source of the need) | Typical market answer | Sieve |
| --- | --- | --- |
| Fewer, better alerts (alert fatigue everywhere) | ML scoring, paid tiers | grouping + chain linking + rule-based score; 18 notifications per 1,000 alerts on the seed set |
| Explainable verdicts (trust in AI) | "visible reasoning" | every sentence cites evidence or is dropped; score breakdown shown point by point |
| AI that cannot be manipulated (new risk) | rarely addressed explicitly | fencing, masking, evidence/number/IP/echo validation, tripwire; severity never from the model |
| Feedback loop that tunes detection | adaptive models | false positive → scoped, expiring exception; tuning page ranks noisy rules |
| Approved exceptions, maintenance windows | SOAR playbooks | first-class records; a log line *claiming* maintenance changes nothing |
| Ownership, SLAs, escalation, handoffs | case management modules | owner, notes, tags, SLA timers, one escalation, shift-handover report, merge |
| Ticketing and SOAR hand-off | 90–300 integrations | signed webhooks, Jira, TheHive, STIX 2.1, API tokens |
| Reporting for executives (Wazuh gap) | dashboards | plain-language executive report and daily manager digest |
| Privacy (logs to vendors' clouds) | SaaS | local-first; local model default; masking for cloud models |
| Cost | $36k–$500k+/yr | free, open source (Apache 2.0) |
| Easy setup | weeks of tuning | 5-step wizard with live connection tests; pull mode needs nothing on the Wazuh manager |
| Security of the tool itself | varies | Argon2id, 2FA, CSRF, strict CSP, append-only audit, encrypted secrets, rate limits, non-root read-only container |

## Open-source tools in the same space (be fair to them)
* **Emerole7/llm-alert-triage**: pulls Wazuh alerts, asks Claude Haiku for a verdict behind deterministic guardrails,
  with prompt-injection defence and an evaluation harness. Closest in spirit. Difference: there the model gives a
  verdict and guardrails limit it; in Sieve the model never sets severity, and its text is evidence-checked.
* **Wazuh Alert Manager** (OpenSearch Dashboards plugin): alert lifecycle, cases, automation rules, deterministic
  "seen before" and related alerts, SLA reporting, optional AI. Advantage: lives inside the Wazuh dashboard.
  Sieve answers that with deep links (`/go/alert/{id}`); a native plugin is on the roadmap.
* **VIGIL (mini-soc-ai-triage)**: local Ollama triage with guardrails and human approval of responses.
* **SOCFortress CoPilot**: multi-tenant Wazuh/Velociraptor console with an AI chat agent over MCP.
* **Tracecat** and **Shuffle**: open-source SOAR with 100+ / 200+ integrations; Tracecat includes SSO and AI agents.
  Sieve is not a SOAR: it feeds them clean, evidence-checked incidents through signed webhooks.

## What users of those tools asked for, and what Sieve added in v0.3
Correlation of different alerts (Wazuh issues #3852, #21635) → correlation rules with backtest. Routing by agent
group (#4526, closed as not planned) → team routing. "Seen before" (Alert Manager) → precedent panel. Transparency
(9 in 10 leaders need it, Torq 2026 report) → decision trace. Learning (92%) → weight suggestions. Limited autonomy
on medium and below (72%) → earned, revocable auto-close. Overtrust warnings → verify-before-close. Junior skills →
training mode. Plus Teams, PagerDuty, Jira two-way, SSO and an MCP server.

## What Sieve deliberately does not do
It is not a SIEM: it does not store or search all logs (Wazuh does). It does not run autonomous response: the
two Wazuh active-response actions need an admin's explicit confirmation. It does not yet offer multi-tenancy
for MSSPs or 90+ integrations; plugins and webhooks are the extension path.

# QA report, v0.4.0 (2026-10-18)

Method: 266 automated tests (unit, API, role matrix, pipeline, injection), the PoisonedLogs benchmark, and a
scripted browser pass over every page as admin, analyst and viewer at 1366 px and 390 px, with alerts carrying
XSS payloads (`<script>`, `onerror`, `onload`) in every field that reaches the screen. The browser pass checks
for executed script, JavaScript dialogs, console errors, horizontal overflow, open redirect, path traversal,
security headers and cookie flags. Final run: **no issues**.

## Bugs found and fixed

| # | Severity | Found by | Bug | Fix |
| --- | --- | --- | --- | --- |
| 1 | Critical | demo run | Brute force + successful login produced two High incidents (grouping on exact rule, tactic case mismatch, overrides could never fire) | ADR-003: chain linking, tactic normalisation, same-source ordered override |
| 2 | Critical | import check | `sieve/api/app.py` could not import; web UI called endpoints that did not exist | duplicate stack removed; one app factory |
| 3 | High | demo run | One notification per alert instead of per incident | per-band notification de-duplication |
| 4 | High | code review | `mask_for_cloud` documented but not implemented | Masker in `llm/fence.py`, tested round trip |
| 5 | High | benchmark | Hijacked model sentence "approved maintenance … marked benign" passed validation | echo check against attacker text; tripwire verb forms (`marked`, `classified`) |
| 6 | High | browser QA | Repeat tripwire hits re-notified (alert IDs on hits lost by a refresh before flush) | flush before refresh; regression test |
| 7 | High | demo recording | Tripwire hit on an already-notified incident sent nothing | first tripwire hit always notifies (ADR-010) |
| 8 | Medium | config review | Wazuh `ossec.conf` snippet used `<n>` instead of `<name>` | corrected |
| 9 | Medium | browser QA | UI metrics page collided with Prometheus `/metrics` | UI moved to `/reports` |
| 10 | Medium | video QA | Sidebar health stayed "Checking…" up to 30 s after sign-in | refresh on sign-in |
| 11 | Medium | video QA | Duplicate investigation when two background tasks raced | in-flight guard |
| 12 | Medium | benchmark | 1.3 s "latency" was queue wait from batch replay | live-like replay; p95 14 ms |
| 13 | Medium | browser QA | Coverage map, charts and long values scrolled the page sideways | min-width guards; `.sr-only` containment; wrapping |
| 14 | Low | demo recording | "1 logins … in 0 seconds" wording | singular form, no zero span |
| 15 | Low | review | Benchmark reported a hard-coded "0.0" unsupported-claim metric | removed (no fabricated metrics) |
| 17 | High | tutorial recording | Setup-wizard test alert scored Medium and never notified, so it did not prove the channel worked | self-test always notifies; test added |
| 18 | Medium | tutorial recording | Pull mode had no switch in Settings (config file only) | checkbox and interval in Settings › Integrations |
| 19 | Low | marketing recording | Escalation said "0 min past its SLA" | "has just passed its SLA" |
| 20 | Low | tutorial review | "(s)" plurals in reports, overview banner and validation note | proper singular and plural wording |
| 21 | Medium | v0.3 tests | Weight-tuning search stuck when two weights had to move together | separation-aware search; test |
| 22 | Low | load test | Ingest committed each alert separately (~1,600/s) | batched transaction for lists and pull mode |
| 23 | High | v0.4 build | Duplicate tables/fields/settings and calls to missing functions left by an interrupted attempt | reconciled; AST duplicate check |
| 24 | High | v0.4 tests | Compliance column missing on incidents | added; regression test |
| 25 | Medium | browser QA (customer user) | Provider-only pages shown to customers; 5 pages crashed on refused requests | nav filtered; loads guarded |
| 16 | Low | tests | Login rate limit (10/min/IP) fired before the per-account lockout and would hit offices behind one NAT | 20/min/IP; lockout stays at 10 failures/account |

## Known limitations (not bugs)
* Severity floors were added knowing which seed scenarios had been missed; they follow Wazuh's level semantics and
  common high-impact techniques, but only a live lab can confirm the recall on real traffic.
* Plugins run in-process with containment (ADR-006). No multi-tenant (MSSP) mode yet.

# ADR-009: Investigation picks templates, never queries; checks run with or without AI

**Date:** 2026-10-17 · **Status:** Accepted

The model may only name one of five templates (`FIRST_SEEN_LOGIN`, `HOST_ACTIVITY_NEXT_HOUR`,
`OTHER_HOSTS_SAME_IP`, `RECENT_ALERTS_SAME_USER`, `SCHEDULED_JOBS_ON_HOST`). Parameters are filled by Sieve from
the incident's validated entities, so the model cannot choose what to query for. Query results contain log data
and go back to the model inside the ATTACKER_DATA fence. Hard cap: 6 model calls; `steps_taken` and `budget_hit`
are stored. All five checks run deterministically for every critical incident even with AI off: they are useful
evidence on their own, and the UI shows them without verdicts. When the Wazuh indexer is not configured, the
same templates run against Sieve's own alert store.

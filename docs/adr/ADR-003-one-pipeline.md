# ADR-003: One pipeline, one severity module

**Date:** 2026-10-17 · **Status:** Accepted

## Context
The v0.0.1 starter contained two partly merged implementations: `pipeline/engine.py` + `pipeline/scoring.py`
+ `api/app.py`, and `pipeline/group.py` + `pipeline/score.py` + `worker.py` + router modules. `api/app.py`
could not import; the web app called endpoints only it defined. In the code that ran, grouping keyed on the
exact rule ID, so "brute force, then a successful login" became two incidents, and tactic names were compared
in different letter cases, so neither override rule could fire. The flagship scenario produced two High
incidents instead of one Critical.

## Decision
Keep the module names MASTER_AI_PROMPT designates (`score.py` is the only place severity is set) and delete
the duplicates. Port the working ideas from the deleted code: chain linking by (host, actor) inside the
window, the context-aware level filter, and the same-source, ordered brute-force check. Fix tactic
normalisation and use the research doc's chain term (distinct tactics / 4). An override escalates the
**band** to critical but leaves the **score** as calculated, so the breakdown the analyst sees stays honest
(matching the hi-fi design: "score 89, override: always critical").

## Consequences
`tests/test_score.py` changed one assertion (score is no longer forced to 100). The demo now yields one
Critical incident of 47 alerts.

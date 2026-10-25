# ADR-001: LLM explains only; deterministic logic decides severity

**Date:** 2026-10-16  
**Status:** Accepted

## Context

LLM-based alert triage is subject to log-borne prompt injection: text an attacker
plants in log fields can instruct the model to downgrade the severity of the alert
that reports their own attack.  If the LLM controls severity, a successful injection
silences the detection entirely.

## Decision

The LLM is permitted to write summaries, propose hypotheses and suggest playbook
steps.  It is structurally prohibited from influencing severity, band or any
automated response action.  The severity formula (Section 6.3 of the research
document) runs on structured, type-validated fields.  The LLM output is validated
before use, and any sentence without a grounded evidence reference is dropped.

## Consequences

- Injection can still affect the wording of an explanation.  Mitigated by showing
  attacker-controlled fields in a clearly labelled untrusted box.
- Explanations are less "creative" than unconstrained model output.  Accepted: we
  prefer accuracy over fluency for a security tool.
- The constraint is simple enough to audit and test.  A test suite in
  `tests/test_tripwire.py` and the PoisonedLogs benchmark measure compliance.

# ADR-002: "No AI" is always the last fallback; the tool works without any model

**Date:** 2026-10-16  
**Status:** Accepted

## Context

Users with modest hardware cannot run a local model.  Free cloud tiers have quotas
and can disappear.  A security tool that silently stops notifying when the AI is
unavailable is more dangerous than one with less explanation.

## Decision

The LLM provider list is a chain.  If every provider is unavailable or rate-limited,
the deterministic notification is still sent, labelled "AI summary not available."
No alert is ever held back waiting for an LLM response.

## Consequences

- The tool is useful even with `llm.enabled: false`.
- Phase-1 (instant) and phase-2 (AI edit) are separate: phase 1 always runs.
- This means the provider fallback chain must be exercised in tests.

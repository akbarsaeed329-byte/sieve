# ADR-006: Plugins run in-process with containment for v0.1; out-of-process before v1.0

**Date:** 2026-10-17 · **Status:** Accepted (interim)

## Context
Research doc 10.3 asks for plugins in a separate worker process over a local socket. MASTER_AI_PROMPT 2.4
asks for the AbuseIPDB enricher and a schema-driven Plugins page now.

## Decision
Ship the manifest contract now (type, version, permissions, JSON Schema settings, secret fields) and the
Plugins page that renders forms from it. Enabling a plugin requires explicit approval of its declared
permissions, recorded in the audit log. Calls go through `plugins.call_safely` (timeout, exception
containment), so a failing plugin yields "partial context", never a lost alert.

## Consequences
A malicious plugin is not yet isolated from the core process. Only first-party plugins ship in 0.1. The
out-of-process runner (T8 in docs/MASTER_PROMPT.md) keeps this manifest unchanged.

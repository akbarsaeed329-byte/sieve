# ADR-004: Encrypted secret store for credentials entered in the UI

**Date:** 2026-10-17 · **Status:** Accepted

## Context
The setup wizard must finish in under 10 minutes, which means pasting a Telegram token or Wazuh password in
the browser. The coding standard forbids secrets in config YAML; the research doc (10.2, 8) specifies keys
encrypted at rest and never shown after save.

## Decision
Secrets typed in the UI go to the `secrets` table, encrypted with Fernet; the key is derived with HKDF-SHA256
from `data/.secret_key` (0600). Resolution order is always: environment variable, then store. No API returns
a value, only `env | stored | unset`. The audit log records that a secret changed, never its value. Values
are never logged or placed in prompts.

## Consequences
Residual risk, as in the threat model: whoever can read the data directory can decrypt. Operators who prefer
env-only can ignore the store; env always wins.

# ADR-005: Additive schema changes in 0.x; Alembic before 1.0

**Date:** 2026-10-17 · **Status:** Accepted

`init_db` creates new tables and adds missing nullable or defaulted columns to existing ones. That covers every
change in 0.x and keeps "one container, zero setup". Destructive or renaming changes are not allowed until
Alembic is introduced (planned before v1.0, research doc 10.1). The audit table gets SQLite triggers that reject
UPDATE and DELETE, so append-only is enforced by the database, not just by convention.

# ADR-017: High availability with PostgreSQL and leased work

**Date:** 2026-10-18 · **Status:** Accepted

SQLite stays the default (one container, zero setup). With `SIEVE_DATABASE_URL` Sieve uses PostgreSQL: JSON columns
become JSONB (needed for equality and DISTINCT), audit immutability uses a plpgsql trigger, and additive migrations
render dialect-correct defaults. Workers claim queue items with `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP
LOCKED) RETURNING`, with a 120-second lease; expired leases are reclaimed, so a crashed worker loses nothing.
Incident creation takes `pg_advisory_xact_lock(hashtext('sieve:'||agent))` so concurrent workers never create
duplicate incidents for one host. Periodic jobs run only on the worker holding a renewable leader lease in the KV
table. Verified: the whole test suite on PostgreSQL 16 and two concurrent workers processing 300 alerts exactly once.

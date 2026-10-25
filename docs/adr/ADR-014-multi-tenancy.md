# ADR-014: Multi-tenancy by agent mapping, enforced at the query layer

**Date:** 2026-10-18 · **Status:** Accepted

Wazuh alerts do not carry agent-group membership, so Sieve keeps an agent → tenant map from the Wazuh API
(`/agents?select=name,group`) or tenant host patterns, and stamps `tenant_id` on every alert, suppression and incident
at ingest. Isolation rules: `get_incident(db, id, user)` returns 404 for other tenants (existence is not revealed); list
endpoints filter with `scoped()`; provider-level pages use the `p_*` dependencies and refuse customer users and tokens;
grouping and exceptions never cross tenants; customer users and tokens can never be admin. A test hits all incident
sub-routes of another tenant's incident and requires 404. One database per deployment (shared schema); per-tenant
databases are not needed for the target size and would complicate cross-customer attacker views.

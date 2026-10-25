# ADR-012: Ask Sieve and MCP are read-only, and deterministic at the core

**Date:** 2026-10-18 · **Status:** Accepted

Ask Sieve parses intent and entities with regular expressions against entities Sieve already knows, and answers with
fixed read-only queries. A model may only phrase a two-sentence summary of the result; the summary is dropped if it
contains a number or IP that is not in the result. The MCP server exposes four read-only tools through the public API
with a viewer token, and prefixes every result with a note that the content is attacker-influenced data.

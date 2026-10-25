# ADR-011: Severity floors, and autonomy that has to be earned

**Date:** 2026-10-18 · **Status:** Accepted

**Floors.** v0.2 notified only 58% of seed true attacks: one high-impact alert (new admin account, encoded
PowerShell) scored Medium. Floors are deterministic rules in `score.py` (the only severity module): Wazuh level 12+
("high importance" in Wazuh's own scale), account creation on critical assets and credential dumping reach High;
ransomware-like impact reaches Critical. They are configurable, visible as overrides, and never lower a band.

**Auto-close.** Leaders accept autonomy on medium and below, but trust is low. So auto-close is off by default, per rule,
approved by an admin, and only while the rule keeps a record (30+ verdicts, 95%+ agreement). It never applies to
tripwire, override or correlation incidents. Auto-closed incidents remain reviewable; reopening one revokes the rule.

**Weights.** Suggestions come from re-scoring closed incidents; a change is proposed only if no real incident loses its
notification, and it is applied only by an admin, with the before/after counts in the audit log.

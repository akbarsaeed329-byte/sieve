# ADR-015: Regulatory clocks are computed, decisions are recorded, evidence is sealed

**Date:** 2026-10-18 · **Status:** Accepted

Deadlines: NIS2 Art. 23 (24 h / 72 h / 1 month from awareness), DORA Art. 19 with RTS 2025/301 (initial 4 h after
classification as major and no later than 24 h after awareness; intermediate 72 h after the initial; final one month
after the intermediate), GDPR Art. 33 (72 h). The DORA helper applies RTS 2024/1772 (critical services affected and
either malicious access with data loss or two more criteria) as a suggestion; the classification is a recorded human
decision with its timestamp. Evidence packs contain the report, decision trace and raw alerts with a SHA-256 manifest
sealed by an HMAC of the server key; `POST /api/evidence/verify` detects any change.

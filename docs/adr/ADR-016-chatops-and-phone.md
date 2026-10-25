# ADR-016: Act from the phone, safely

**Date:** 2026-10-18 · **Status:** Accepted

Chat buttons can only acknowledge or assign. Telegram updates are accepted only with the secret token Telegram echoes
in `X-Telegram-Bot-Api-Secret-Token`; Slack actions are verified with the signing secret (v0 HMAC, 5-minute window).
A chat identity does nothing until linked to a Sieve user with a single-use code, and the action runs under that
user's role and tenant. Web Push uses VAPID keys generated once (private key encrypted with the secret store) and the
service worker caches no security data. On-call rotations page by push and email when an SLA is missed.

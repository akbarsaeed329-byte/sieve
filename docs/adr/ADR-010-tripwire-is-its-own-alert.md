# ADR-010: A first tripwire hit notifies, even when the band is unchanged

**Date:** 2026-10-17 · **Status:** Accepted

Notifications are de-duplicated per incident and band. Testing showed a poisoned alert arriving after an
incident was already notified produced no new message. Research doc 6.4 says a tripwire hit raises its own
alert, so the first hit on an incident always sends a message showing the untrusted field. Later hits on the
same incident do not, to avoid a flooding vector.

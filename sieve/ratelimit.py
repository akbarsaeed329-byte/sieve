"""Small in-process sliding-window rate limiter (per client IP and bucket)."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from .errors import SieveError

_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_lock = threading.Lock()
LIMITS = {"login": (20, 60), "ingest": (600, 60), "invite": (20, 60), "totp": (10, 60)}


def check(bucket: str, key: str) -> None:
    n, window = LIMITS[bucket]
    now = time.monotonic()
    with _lock:
        q = _hits[(bucket, key)]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= n:
            raise SieveError("SIEVE-RATE-429", "Too many requests. Slow down and try again in a minute.",
                             "Wait a minute. If this is a busy Wazuh manager, batch alerts in one request.", status=429)
        q.append(now)


def reset() -> None:
    with _lock:
        _hits.clear()

"""Model providers with retries, rate-limit handling, circuit breakers and a fallback chain.

Failure policy (research doc 10.4):
- timeout / 5xx: retry 3x with exponential backoff + jitter, then next provider
- 429: honour Retry-After (capped), mark throttled, next provider
- 401/403: no retry; provider marked failed with a fix message
- 3 consecutive failures: circuit opens for 5 minutes, then one half-open test call
- every provider failed: return None -> caller sends the plain alert ("AI summary unavailable")
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from collections import deque
from dataclasses import dataclass, field

import httpx

from ..config import Provider
from ..errors import LLM_AUTH, LLM_RATE_LIMIT, LLM_TIMEOUT, SieveError

OPEN_SECONDS = 300
FAIL_THRESHOLD = 3


@dataclass
class Health:
    state: str = "unknown"          # ok | throttled | failing | open | unknown
    consecutive_failures: int = 0
    open_until: float = 0
    last_error: dict | None = None
    calls: int = 0
    tokens: int = 0


@dataclass
class Completion:
    text: str
    provider: str
    model: str
    latency_ms: int
    tokens: int = 0


class ProviderClient:
    def __init__(self, cfg: Provider):
        self.cfg = cfg
        self.health = Health()

    def available(self) -> bool:
        return not (self.health.state == "open" and time.monotonic() < self.health.open_until)

    def _key(self) -> str | None:
        return os.environ.get(self.cfg.api_key_env) if self.cfg.api_key_env else None

    async def _call(self, client: httpx.AsyncClient, system: str, user: str) -> Completion:
        t0 = time.monotonic()
        if self.cfg.kind == "ollama":
            r = await client.post(f"{self.cfg.base_url.rstrip('/')}/api/chat", json={
                "model": self.cfg.model, "stream": False, "format": "json",
                "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            self._raise_for(r)
            j = r.json()
            text = j.get("message", {}).get("content", "")
            tokens = int(j.get("eval_count", 0)) + int(j.get("prompt_eval_count", 0))
        else:
            headers = {"Authorization": f"Bearer {self._key()}"} if self._key() else {}
            r = await client.post(f"{self.cfg.base_url.rstrip('/')}/chat/completions", headers=headers, json={
                "model": self.cfg.model, "temperature": 0, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            self._raise_for(r)
            j = r.json()
            text = j["choices"][0]["message"]["content"]
            tokens = int((j.get("usage") or {}).get("total_tokens", 0))
        return Completion(text, self.cfg.name, self.cfg.model, int((time.monotonic() - t0) * 1000), tokens)

    def _raise_for(self, r: httpx.Response) -> None:
        if r.status_code in (401, 403):
            raise SieveError(LLM_AUTH, f"{self.cfg.name} rejected the API key (HTTP {r.status_code}).",
                             f"Check the key in environment variable {self.cfg.api_key_env}.", retryable=False)
        if r.status_code == 429:
            wait = min(float(r.headers.get("retry-after", "10") or 10), 30)
            raise SieveError(LLM_RATE_LIMIT, f"{self.cfg.name} rate limit reached; retry after {wait:.0f}s.",
                             "Lower llm.calls_per_hour or add another provider to the fallback chain.",
                             status=429, retryable=False)
        if r.status_code >= 500:
            raise SieveError(LLM_TIMEOUT, f"{self.cfg.name} server error HTTP {r.status_code}.",
                             "Usually temporary; Sieve retries automatically.", status=502, retryable=True)
        r.raise_for_status()

    async def complete(self, system: str, user: str) -> Completion:
        delay = 1.0
        last: Exception | None = None
        async with httpx.AsyncClient(timeout=self.cfg.timeout_s) as client:
            for _ in range(3):
                try:
                    c = await self._call(client, system, user)
                    self.health = Health(state="ok", calls=self.health.calls + 1,
                                         tokens=self.health.tokens + c.tokens)
                    return c
                except SieveError as e:
                    last = e
                    if not e.retryable:
                        break
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last = SieveError(LLM_TIMEOUT, f"{self.cfg.name} did not answer: {type(e).__name__}.",
                                      f"Check that {self.cfg.base_url} is reachable from Sieve.", retryable=True)
                await asyncio.sleep(delay + random.uniform(0, delay / 2))
                delay *= 2
        self._fail(last)
        raise last  # type: ignore[misc]

    def _fail(self, e: Exception | None) -> None:
        h = self.health
        h.consecutive_failures += 1
        h.last_error = e.to_dict() if isinstance(e, SieveError) else {"message": str(e)}
        h.state = "throttled" if isinstance(e, SieveError) and e.code == LLM_RATE_LIMIT else "failing"
        if h.consecutive_failures >= FAIL_THRESHOLD:
            h.state, h.open_until = "open", time.monotonic() + OPEN_SECONDS


@dataclass
class Budget:
    per_hour: int
    calls: deque = field(default_factory=deque)

    def take(self) -> bool:
        now = time.monotonic()
        while self.calls and now - self.calls[0] > 3600:
            self.calls.popleft()
        if len(self.calls) >= self.per_hour:
            return False
        self.calls.append(now)
        return True


class Chain:
    def __init__(self, providers: list[Provider], per_hour: int):
        self.clients = [ProviderClient(p) for p in providers]
        self.budget = Budget(per_hour)

    def status(self) -> list[dict]:
        return [{"name": c.cfg.name, "kind": c.cfg.kind, "model": c.cfg.model, "cloud": c.cfg.is_cloud,
                 "state": c.health.state, "last_error": c.health.last_error, "calls": c.health.calls,
                 "tokens": c.health.tokens} for c in self.clients]

    async def complete(self, build_prompt) -> tuple[Completion, object] | None:
        """build_prompt(is_cloud) -> Prompt. Returns (completion, prompt) or None if no AI is available."""
        if not self.budget.take():
            return None
        for c in self.clients:
            if not c.available():
                continue
            p = build_prompt(c.cfg.is_cloud)
            try:
                return await c.complete(p.system, p.user), p
            except SieveError:
                continue
        return None

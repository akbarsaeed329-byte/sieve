"""LLM client: fallback chain, hourly budget, circuit breaker, structured JSON output.

Failure policy (research doc 10.4):
* timeout / connection error / HTTP 5xx: retry 3x with exponential backoff + jitter, then next provider
* HTTP 429: honour Retry-After (capped at 5 min), mark the provider throttled, go to the next provider
* HTTP 401/403: no retry; provider marked failing with a fix message, next provider
* 3 consecutive failures: circuit opens for 5 minutes, then one half-open test call
* every provider failed or the hourly budget is used: return None -> the caller keeps the plain,
  rule-based alert ("AI summary unavailable"). Nothing ever waits on a model to notify.

Every prompt comes from ``llm/fence.py``; every answer goes through ``llm/validate.py`` (callers).
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from .. import secrets_store
from ..config import Provider, Settings
from ..db import SessionLocal
from ..errors import LLM_AUTH, LLM_BAD_OUTPUT, LLM_RATE_LIMIT, LLM_TIMEOUT, SieveError
from ..models import LlmCall
from .fence import Prompt

log = logging.getLogger("sieve.llm")

OPEN_SECONDS = 300
FAIL_THRESHOLD = 3
MAX_RETRY_AFTER = 300
_sleep = asyncio.sleep                                # tests replace with a no-op


@dataclass
class _ProviderState:
    state: str = "unknown"          # ok | throttled | failing | open | unknown
    failures: int = 0
    open_until: float = 0.0
    last_error: dict | None = None
    calls: int = 0
    tokens: int = 0
    last_latency_ms: int = 0


@dataclass
class _Budget:
    calls: deque = field(default_factory=deque)

    def used(self) -> int:
        now = time.monotonic()
        while self.calls and now - self.calls[0] > 3600:
            self.calls.popleft()
        return len(self.calls)

    def take(self, per_hour: int) -> bool:
        if self.used() >= per_hour:
            return False
        self.calls.append(time.monotonic())
        return True


_states: dict[str, _ProviderState] = {}
_budget = _Budget()


def set_transport(t: httpx.AsyncBaseTransport | None) -> None:
    _transport_holder[0] = t


_transport_holder: list = [None]


def reset_state() -> None:
    _states.clear()
    _budget.calls.clear()


def _state(name: str) -> _ProviderState:
    return _states.setdefault(name, _ProviderState())


def available(name: str) -> bool:
    st = _state(name)
    if st.state in ("open", "throttled") and st.open_until:
        if time.monotonic() < st.open_until:
            return False
        st.state = "half-open"
    return True


def status(settings: Settings) -> dict:
    out = []
    for p in settings.llm.providers:
        st = _state(p.name)
        remaining = max(0, int(st.open_until - time.monotonic())) if st.open_until else 0
        out.append({"name": p.name, "kind": p.kind, "model": p.model, "cloud": p.is_cloud, "enabled": p.enabled,
                    "state": st.state if p.enabled else "disabled", "circuit": _circuit(st),
                    "retry_in_s": remaining, "last_error": st.last_error, "calls": st.calls, "tokens": st.tokens,
                    "last_latency_ms": st.last_latency_ms})
    return {"enabled": settings.llm.enabled, "providers": out,
            "budget": {"per_hour": settings.llm.calls_per_hour, "used": _budget.used()}}


def _circuit(st: _ProviderState) -> str:
    if st.state == "open" and time.monotonic() < st.open_until:
        return "open"
    if st.state == "half-open":
        return "half-open"
    return "closed"


def _record(provider: Provider, purpose: str, ok: bool, ms: int, tokens: int, code: str | None,
            incident_id: int | None) -> None:
    try:
        with SessionLocal() as db:
            db.add(LlmCall(provider=provider.name, model=provider.model, purpose=purpose, ok=ok, latency_ms=ms,
                           tokens=tokens, error_code=code, incident_id=incident_id))
            db.commit()
    except Exception:  # noqa: BLE001 - metrics must never break triage
        log.debug("could not record llm call", exc_info=True)


def _fail(name: str, e: SieveError) -> None:
    st = _state(name)
    st.failures += 1
    st.last_error = e.to_dict()
    if e.code == LLM_RATE_LIMIT:
        return  # throttled state already set by the caller
    st.state = "failing"
    if st.failures >= FAIL_THRESHOLD:
        st.state, st.open_until = "open", time.monotonic() + OPEN_SECONDS
        log.warning("circuit breaker open", extra={"provider": name, "seconds": OPEN_SECONDS})


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.I)


def parse_json(content: str) -> dict:
    text = _FENCE_RE.sub("", content or "").strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        text = text[start:end + 1] if start >= 0 < end else text
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise SieveError(LLM_BAD_OUTPUT, "The model did not return valid JSON.") from e
    if not isinstance(data, dict):
        raise SieveError(LLM_BAD_OUTPUT, "The model returned JSON that is not an object.")
    return data


def _raise_for(p: Provider, r: httpx.Response) -> None:
    if r.status_code in (401, 403):
        raise SieveError(LLM_AUTH, f"{p.name} rejected the API key (HTTP {r.status_code}).", retryable=False)
    if r.status_code == 429:
        try:
            wait = float(r.headers.get("retry-after", "60") or 60)
        except ValueError:
            wait = 60.0
        st = _state(p.name)
        st.state, st.open_until = "throttled", time.monotonic() + min(wait, MAX_RETRY_AFTER)
        raise SieveError(LLM_RATE_LIMIT, f"{p.name} rate limit reached; retry after {wait:.0f}s.", status=429)
    if r.status_code >= 500:
        raise SieveError(LLM_TIMEOUT, f"{p.name} server error HTTP {r.status_code}.", status=502, retryable=True)
    if r.status_code >= 400:
        raise SieveError(LLM_BAD_OUTPUT, f"{p.name} refused the request (HTTP {r.status_code}).", status=502)


async def _call(p: Provider, prompt: Prompt) -> tuple[str, int]:
    key = secrets_store.resolve(p.api_key_env) if p.api_key_env else ""
    async with httpx.AsyncClient(timeout=p.timeout_s, transport=_transport_holder[0]) as c:
        if p.kind == "ollama":
            r = await c.post(f"{p.base_url.rstrip('/')}/api/chat", json={
                "model": p.model, "stream": False, "format": "json", "options": {"temperature": 0, "seed": 7},
                "messages": prompt.messages()})
            _raise_for(p, r)
            j = r.json()
            return (j.get("message") or {}).get("content", ""), int(j.get("eval_count", 0)) + int(
                j.get("prompt_eval_count", 0))
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        r = await c.post(f"{p.base_url.rstrip('/')}/chat/completions", headers=headers, json={
            "model": p.model, "temperature": 0, "seed": 7, "response_format": {"type": "json_object"},
            "messages": prompt.messages()})
        _raise_for(p, r)
        j = r.json()
        return j["choices"][0]["message"]["content"], int((j.get("usage") or {}).get("total_tokens", 0))


@dataclass
class Answer:
    data: dict
    provider: str
    model: str
    latency_ms: int
    tokens: int
    prompt: Prompt


async def complete_json(
    build: Callable[[bool], Prompt],
    settings: Settings,
    *,
    purpose: str = "summary",
    incident_id: int | None = None,
) -> Answer | None:
    """Try each enabled provider in order. ``build(is_cloud)`` returns the fenced (maybe masked) prompt."""
    if not settings.llm.enabled:
        return None
    providers = [p for p in settings.llm.providers if p.enabled]
    if not providers:
        return None
    if not _budget.take(settings.llm.calls_per_hour):
        log.warning("llm hourly budget used", extra={"per_hour": settings.llm.calls_per_hour})
        return None
    for p in providers:
        if not available(p.name):
            continue
        prompt = build(p.is_cloud)
        delay = 1.0
        for attempt in range(3):
            t0 = time.monotonic()
            try:
                text, tokens = await _call(p, prompt)
                data = parse_json(text)
                if prompt.masker:
                    data = prompt.masker.unmask_obj(data)
                ms = int((time.monotonic() - t0) * 1000)
                st = _state(p.name)
                st.state, st.failures, st.open_until = "ok", 0, 0.0
                st.calls += 1
                st.tokens += tokens
                st.last_latency_ms = ms
                _record(p, purpose, True, ms, tokens, None, incident_id)
                return Answer(data, p.name, p.model, ms, tokens, prompt)
            except SieveError as e:
                err = e
            except (httpx.TimeoutException, httpx.TransportError) as e:
                err = SieveError(LLM_TIMEOUT, f"{p.name} did not answer ({type(e).__name__}).", retryable=True)
            except (KeyError, IndexError, TypeError, ValueError) as e:
                err = SieveError(LLM_BAD_OUTPUT, f"{p.name} returned an unexpected response ({type(e).__name__}).")
            ms = int((time.monotonic() - t0) * 1000)
            _record(p, purpose, False, ms, 0, err.code, incident_id)
            log.warning("llm provider error", extra={"provider": p.name, "code": err.code, "attempt": attempt + 1})
            if not err.retryable or attempt == 2:
                _fail(p.name, err)
                break
            await _sleep(delay + random.uniform(0, delay / 2))
            delay *= 2
    log.warning("all llm providers failed", extra={"incident": incident_id, "purpose": purpose})
    return None


async def test_provider(p: Provider) -> dict:
    """Connection test for the setup wizard and Settings > Models (no prompt, no log data)."""
    key = secrets_store.resolve(p.api_key_env) if p.api_key_env else ""
    try:
        async with httpx.AsyncClient(timeout=min(p.timeout_s, 10), transport=_transport_holder[0]) as c:
            if p.kind == "ollama":
                r = await c.get(f"{p.base_url.rstrip('/')}/api/tags")
                if r.status_code != 200:
                    _raise_for(p, r)
                models = [m.get("name", "") for m in (r.json().get("models") or [])]
                if p.model not in models and f"{p.model}:latest" not in models:
                    return {"ok": False, "code": "SIEVE-LLM-404",
                            "message": f"Ollama is reachable but model {p.model} is not pulled.",
                            "fix": f"Run: docker exec ollama ollama pull {p.model}", "models": models[:20]}
                return {"ok": True, "message": f"Ollama answered and {p.model} is available."}
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            r = await c.get(f"{p.base_url.rstrip('/')}/models", headers=headers)
            if r.status_code != 200:
                _raise_for(p, r)
            return {"ok": True, "message": f"{p.name} accepted the key."}
    except SieveError as e:
        return {"ok": False, **e.to_dict()}
    except (httpx.TimeoutException, httpx.TransportError) as e:
        err = SieveError(LLM_TIMEOUT, f"Could not reach {p.base_url} ({type(e).__name__}).")
        return {"ok": False, **err.to_dict()}

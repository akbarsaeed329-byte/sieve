"""LLM client: fallback chain, rate limiting, circuit breaker, structured JSON output.

Provider priority: each provider is tried in order. On timeout / rate-limit / error,
the next provider is used. If all fail, 'no AI' mode returns an empty explanation and
the deterministic alert is still sent.

Circuit breaker: after 3 consecutive failures a provider is paused for 5 minutes
then half-open (one test call, re-open on success, stay closed on failure).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field

import httpx

from ..config import Provider, Settings
from ..errors import LLM_ALL_FAILED, LLM_BAD_OUTPUT, LLM_TIMEOUT, SieveError
from .fence import SYSTEM_PROMPT, build_prompt
from .validate import validate

log = logging.getLogger("sieve.llm")

_RATE_LIMIT_WINDOW = 3600  # 1 hour


@dataclass
class _ProviderState:
    failures: int = 0
    open_until: float = 0.0   # epoch seconds; 0 = closed (healthy)
    calls_this_hour: int = 0
    hour_reset: float = field(default_factory=time.time)


_states: dict[str, _ProviderState] = {}


def _state(name: str) -> _ProviderState:
    if name not in _states:
        _states[name] = _ProviderState()
    return _states[name]


def _reset_hour_if_needed(st: _ProviderState) -> None:
    if time.time() - st.hour_reset >= _RATE_LIMIT_WINDOW:
        st.calls_this_hour = 0
        st.hour_reset = time.time()


def _is_available(name: str) -> bool:
    st = _state(name)
    if st.open_until:
        if time.time() < st.open_until:
            return False
        # half-open: allow one test call
        st.open_until = 0.0
    _reset_hour_if_needed(st)
    return True


def _record_success(name: str) -> None:
    st = _state(name)
    st.failures = 0
    st.calls_this_hour += 1


def _record_failure(name: str) -> None:
    st = _state(name)
    st.failures += 1
    if st.failures >= 3:
        st.open_until = time.time() + 300  # pause 5 minutes
        log.warning("Circuit breaker OPEN for provider %s for 5 min", name)


async def _call_provider(provider: Provider, messages: list[dict]) -> dict:
    api_key = ""
    if provider.api_key_env:
        api_key = os.environ.get(provider.api_key_env, "")

    if provider.kind == "ollama":
        url = f"{provider.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": provider.model,
            "messages": messages,
            "stream": False,
            "format": "json",
        }
        headers = {}
    else:
        url = f"{provider.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": provider.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async with httpx.AsyncClient(timeout=provider.timeout_s) as client:
        r = await client.post(url, json=payload, headers=headers)
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "60"))
            raise SieveError("SIEVE-LLM-429", "Rate limited", retryable=True,
                             fix=f"Wait {retry_after}s or reduce call rate")
        r.raise_for_status()
        data = r.json()

    if provider.kind == "ollama":
        content = data["message"]["content"]
    else:
        content = data["choices"][0]["message"]["content"]

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise SieveError(LLM_BAD_OUTPUT, f"Model returned non-JSON: {content[:200]}") from e


async def explain(
    incident_id: int,
    score: float,
    band: str,
    breakdown: list[dict],
    alerts_summary: list[dict],
    untrusted: dict[str, str],
    evidence_refs: list[str],
    playbooks: list[str],
    settings: Settings,
) -> dict | None:
    """Return validated explanation dict or None (no-AI mode)."""
    if not settings.llm.enabled:
        return None

    user_content = build_prompt(
        incident_id, score, band, breakdown,
        alerts_summary, untrusted, evidence_refs, playbooks,
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    for provider in settings.llm.providers:
        if not _is_available(provider.name):
            log.info("Skipping provider %s (circuit breaker open)", provider.name)
            continue

        for attempt in range(3):
            try:
                raw = await _call_provider(provider, messages)
                validated = validate(raw, evidence_refs, playbooks)
                _record_success(provider.name)
                validated["provider"] = provider.name
                validated["model"] = provider.model
                log.info("LLM explanation from %s (%d summary sentences)",
                         provider.name, len(validated["summary"]))
                return validated
            except SieveError as e:
                if not e.retryable:
                    break
                wait = 2 ** attempt
                log.warning("Provider %s attempt %d/%d: %s — retry in %ds",
                            provider.name, attempt + 1, 3, e.code, wait)
                await asyncio.sleep(wait)
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                log.warning("Provider %s timeout/connect: %s", provider.name, e)
                if attempt == 2:
                    _record_failure(provider.name)
                await asyncio.sleep(2 ** attempt)
            except Exception as e:  # noqa: BLE001
                log.error("Provider %s unexpected error: %s", provider.name, e)
                _record_failure(provider.name)
                break

    log.warning("All LLM providers failed for incident %d — no-AI mode", incident_id)
    return None

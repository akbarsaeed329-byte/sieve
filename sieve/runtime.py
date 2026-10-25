"""Process-wide runtime state: the current Settings object.

Everything reads settings through ``current()`` so that a validated change saved from the UI
(PUT /api/settings) takes effect for the worker and the API without a restart.
"""

from __future__ import annotations

import threading

from .config import Settings, load_settings

_lock = threading.Lock()
_settings: Settings | None = None


def current() -> Settings:
    global _settings
    with _lock:
        if _settings is None:
            _settings = load_settings()
        return _settings


def set_current(s: Settings) -> None:
    global _settings
    with _lock:
        _settings = s


def reset() -> None:
    """Forget the cached settings (tests)."""
    global _settings
    with _lock:
        _settings = None

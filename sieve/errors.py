"""Stable, documented error codes. Every user-facing error carries a code, a message and a fix.

See docs/ERROR_CODES.md. Never change the meaning of an existing code; add new ones instead.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SieveError(Exception):
    code: str
    message: str
    fix: str = ""
    status: int = 400
    retryable: bool = False

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "fix": self.fix}


# Catalogue (keep in sync with docs/ERROR_CODES.md)
CONFIG_INVALID = "SIEVE-CFG-001"
INGEST_BAD_TOKEN = "SIEVE-ING-401"
INGEST_BAD_PAYLOAD = "SIEVE-ING-400"
AUTH_BAD_LOGIN = "SIEVE-AUTH-401"
AUTH_LOCKED = "SIEVE-AUTH-423"
AUTH_REQUIRED = "SIEVE-AUTH-403"
SETUP_DONE = "SIEVE-SETUP-409"
LLM_TIMEOUT = "SIEVE-LLM-504"
LLM_RATE_LIMIT = "SIEVE-LLM-429"
LLM_AUTH = "SIEVE-LLM-401"
LLM_BAD_OUTPUT = "SIEVE-LLM-422"
LLM_ALL_FAILED = "SIEVE-LLM-503"
NOTIFY_FAILED = "SIEVE-NTF-502"
NOT_FOUND = "SIEVE-API-404"

"""RFC 6238 TOTP (SHA-1, 30 s, 6 digits), compatible with every authenticator app. No dependency."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def now_code(secret: str, at: float | None = None) -> str:
    return _code(secret, int((at or time.time()) // 30))


def verify(secret: str, code: str, at: float | None = None, window: int = 1) -> bool:
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6 or not secret:
        return False
    t = int((at or time.time()) // 30)
    return any(hmac.compare_digest(_code(secret, t + d), code) for d in range(-window, window + 1))


def uri(secret: str, username: str, issuer: str = "Sieve") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"

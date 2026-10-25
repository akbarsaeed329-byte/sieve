"""Secrets entered in the web UI (bot tokens, API keys, Wazuh passwords).

Resolution order for every secret: environment variable first, then this store. Values are
encrypted at rest with Fernet using a key derived (HKDF-SHA256) from ``data/.secret_key``; they are
never logged, never returned by any API, and never sent to a model. Residual risk (research doc 8):
anyone who can read the data directory can decrypt them, exactly as with an env file on the same
host. See ADR-004.
"""

from __future__ import annotations

import base64
import logging
import os
import re

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .db import SessionLocal
from .models import SecretRecord, utcnow

log = logging.getLogger("sieve.secrets")
NAME_RE = re.compile(r"^SIEVE_[A-Z0-9_]{2,60}$")


def _fernet(secret_key: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sieve-secret-store-v1",
               info=b"fernet").derive(secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def valid_name(name: str | None) -> bool:
    return bool(name and NAME_RE.match(name))


def put(name: str, value: str, secret_key: str, actor: str) -> None:
    if not valid_name(name):
        raise ValueError("secret names must look like SIEVE_SOMETHING")
    token = _fernet(secret_key).encrypt(value.encode()).decode()
    with SessionLocal() as db:
        row = db.get(SecretRecord, name)
        if row is None:
            db.add(SecretRecord(name=name, ciphertext=token, updated_by=actor))
        else:
            row.ciphertext, row.updated_at, row.updated_by = token, utcnow(), actor
        db.commit()


def delete(name: str) -> None:
    with SessionLocal() as db:
        row = db.get(SecretRecord, name)
        if row is not None:
            db.delete(row)
            db.commit()


def get(name: str | None, secret_key: str) -> str:
    """Return the secret or '' when unset. Environment wins over the store."""
    if not name:
        return ""
    env = os.environ.get(name)
    if env:
        return env
    try:
        with SessionLocal() as db:
            row = db.get(SecretRecord, name)
            ct = row.ciphertext if row else None
    except Exception:  # noqa: BLE001 - DB not initialised (CLI, tests): treat as unset
        return ""
    if not ct:
        return ""
    try:
        return _fernet(secret_key).decrypt(ct.encode()).decode()
    except InvalidToken:
        log.error("secret could not be decrypted", extra={"secret": name})
        return ""


def status(names: list[str], secret_key: str) -> dict[str, str]:
    """For the UI: 'env', 'stored' or 'unset' per name. Never the value."""
    out: dict[str, str] = {}
    with SessionLocal() as db:
        for n in names:
            if not n:
                continue
            if os.environ.get(n):
                out[n] = "env"
            elif db.get(SecretRecord, n) is not None:
                out[n] = "stored"
            else:
                out[n] = "unset"
    return out


def resolve(name: str | None) -> str:
    """get() with the running instance's key (env var, else encrypted store, else '')."""
    from . import runtime
    return get(name, runtime.current().secret_key)

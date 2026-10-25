"""ATT&CK technique validation against the official catalogue (research doc 3.3, 6.5).

Sieve ships ``sieve/data/attack_catalogue.json`` (built from mitre/cti by scripts/fetch_attack.py),
so validation is strict by default: an ID the model invents is dropped even if it looks well formed.
A newer catalogue in ``<data_dir>/attack_catalogue.json`` takes precedence when present.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

FMT = re.compile(r"^T\d{4}(\.\d{3})?$")


@lru_cache
def _load() -> dict:
    local = Path(os.environ.get("SIEVE_DATA_DIR", "./data")) / "attack_catalogue.json"
    try:
        if local.exists():
            return json.loads(local.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return json.loads((resources.files("sieve.data") / "attack_catalogue.json").read_text())


def catalogue() -> frozenset[str]:
    return frozenset(_load().get("techniques", {}))


def tactics_order() -> list[str]:
    return list(_load().get("tactics", []))


def info(technique: str) -> dict | None:
    return _load().get("techniques", {}).get(technique)


def valid_technique(t: str) -> bool:
    if not FMT.match(str(t)):
        return False
    cat = catalogue()
    return (t in cat) if cat else True

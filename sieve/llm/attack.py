"""ATT&CK technique validation.

If data/attack_ids.txt exists (created by `python scripts/fetch_attack.py`), IDs must be in it.
Otherwise only the ID format is checked. Run the fetch script in Phase 1 so validation is strict.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

FMT = re.compile(r"^T\d{4}(\.\d{3})?$")


@lru_cache
def catalogue() -> frozenset[str]:
    p = Path(os.environ.get("SIEVE_DATA_DIR", "./data")) / "attack_ids.txt"
    if p.exists():
        return frozenset(x.strip() for x in p.read_text().splitlines() if x.strip())
    return frozenset()


def valid_technique(t: str) -> bool:
    if not FMT.match(t):
        return False
    cat = catalogue()
    return (t in cat) if cat else True

"""Console notifier — always enabled; provides a guaranteed fallback."""
from __future__ import annotations

from ..models import Incident
from .base import Notifier
from .render import model


class ConsoleNotifier(Notifier):
    name = "console"

    async def send(self, incident: Incident, public_url: str) -> dict:
        m = model(incident, public_url)
        lines = [f"\n{'=' * 72}", f"SIEVE {m['icon']} [{m['band_label'].upper()}] {m['ref']} · {m['title']}",
                 f"Host: {m['host']}  Source: {m['srcip'] or '-'}  User: {m['user'] or '-'}  "
                 f"Alerts: {m['alerts']}  Score: {m['score']}"]
        if m["tripwire"]:
            lines.append(f"TRIPWIRE: instruction-like text in {m['untrusted_field']} was treated as data.")
            lines.append(f"  untrusted {m['untrusted_field']}: {m['untrusted_excerpt']!r}")
        lines += [f"Open: {m['url']}", "=" * 72]
        print("\n".join(lines), flush=True)
        return {"type": "console", "ok": True}

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        m = model(incident, public_url, explanation)
        print(f"  [AI summary for {m['ref']}, checked against evidence]: {' '.join(m['summary']) or '(none)'}",
              flush=True)

    async def send_text(self, text: str) -> dict:
        print(text, flush=True)
        return {"type": "console", "ok": True}

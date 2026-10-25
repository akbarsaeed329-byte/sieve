"""Slack notifier (Block Kit). With a bot token: chat.postMessage then chat.update (true edit).
With only an incoming webhook: send works, and the AI version is posted as a follow-up message.
The untrusted field is shown in its own clearly labelled context + code block."""
from __future__ import annotations

from .. import http, secrets_store
from ..config import Settings
from ..errors import NOTIFY_FAILED, SieveError
from ..models import Incident
from .base import Notifier
from .render import model


def esc(text: object) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code(text: object) -> str:
    return esc(text).replace("`", "ˋ")


def blocks(m: dict) -> list[dict]:
    b: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": f"{m['icon']} *{esc(m['band_label'])}* · {esc(m['ref'])}\n"
                                             f"*{esc(m['title'])} on {esc(m['host'])}*"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text":
            f"{m['alerts']} alerts grouped · user `{_code(m['user'] or '-')}` · source `{_code(m['srcip'] or '-')}`"}]},
    ]
    if m["ai"] and m["summary"]:
        b.append({"type": "section", "text": {"type": "mrkdwn", "text":
                  "_AI summary, checked against evidence_\n" + esc(" ".join(m["summary"]))}})
        if m["first_step"]:
            b.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*First step:* {esc(m['first_step'])}"}})
    if m["tripwire"]:
        b.append({"type": "context", "elements": [{"type": "mrkdwn", "text":
                  f":warning: *Tripwire* — untrusted field `{_code(m['untrusted_field'])}` tried to instruct the "
                  "AI. Treated as data; severity comes from rules."}]})
        box = f"*Untrusted: {_code(m['untrusted_field'])}*\n```{_code(m['untrusted_excerpt'])}```"
        b.append({"type": "section", "text": {"type": "mrkdwn", "text": box}})
    els = [{"type": "button", "text": {"type": "plain_text", "text": "Open"}, "url": m["url"], "style": "primary"}]
    if m.get("buttons"):
        inc_id = int(m["ref"].split("-")[1])
        def btn(action: str, label: str, value: str) -> dict:
            return {"type": "button", "action_id": action, "text": {"type": "plain_text", "text": label}, "value": value}
        els += [btn("sieve_ack", "Acknowledge", f"ack:{inc_id}"), btn("sieve_mine", "Assign to me", f"mine:{inc_id}")]
    b.append({"type": "actions", "elements": els})
    return b


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, settings: Settings):
        c = settings.notify.slack
        self._token = secrets_store.resolve(c.token_env)
        self._webhook = secrets_store.resolve(c.webhook_env)
        self._channel = c.channel

    async def _api(self, method: str, body: dict) -> dict:
        async with http.client(timeout=15) as c:
            r = await c.post(f"https://slack.com/api/{method}", json=body,
                             headers={"Authorization": f"Bearer {self._token}"})
        j = r.json() if r.status_code == 200 else {}
        if not j.get("ok"):
            raise SieveError(NOTIFY_FAILED, f"Slack {method} failed ({j.get('error') or r.status_code}).", status=502)
        return j

    async def _hook(self, body: dict) -> None:
        async with http.client(timeout=15) as c:
            r = await c.post(self._webhook, json=body)
        if r.status_code != 200:
            raise SieveError(NOTIFY_FAILED, f"Slack webhook failed with HTTP {r.status_code}.", status=502)

    async def _deliver(self, m: dict, ts: str | None = None) -> dict:
        from .. import runtime
        m = {**m, "buttons": runtime.current().chatops.slack_buttons and bool(self._token)}
        body = {"text": f"{m['band_label']} {m['ref']}: {m['title']}", "blocks": blocks(m),
                "unfurl_links": False}
        if self._token and self._channel:
            if ts:
                await self._api("chat.update", {"channel": self._channel, "ts": ts, **body})
                return {"type": "slack", "ok": True, "ts": ts}
            j = await self._api("chat.postMessage", {"channel": self._channel, **body})
            return {"type": "slack", "ok": True, "ts": j.get("ts"), "channel": j.get("channel")}
        if self._webhook:
            await self._hook(body)
            return {"type": "slack", "ok": True, "webhook": True}
        raise SieveError(NOTIFY_FAILED, "Slack needs a bot token and channel, or a webhook URL.", status=424)

    async def send(self, incident: Incident, public_url: str) -> dict:
        return await self._deliver(model(incident, public_url))

    async def edit(self, ref: dict, incident: Incident, explanation: dict, public_url: str) -> None:
        await self._deliver(model(incident, public_url, explanation), (ref or {}).get("ts"))

    async def send_text(self, text: str) -> dict:
        body = {"text": esc(text)}
        if self._token and self._channel:
            await self._api("chat.postMessage", {"channel": self._channel, **body})
        else:
            await self._hook(body)
        return {"type": "slack", "ok": True}

"""v0.4 routes: tenants (MSSP), agents, compliance clocks, reports and evidence packs, pilot and self-test,
AI governance, automation rules, detection drafts, source health, chat-ops, push and on-call."""

from __future__ import annotations

import json
import re
from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import runtime
from ..auth import analyst, audit, create_api_token, p_admin, p_analyst, p_viewer, viewer
from ..errors import BAD_REQUEST, NOT_FOUND, SieveError
from ..models import (
    AgentState,
    Alert,
    ApiToken,
    AutomationRule,
    LlmCall,
    OnCall,
    PushSubscription,
    Tenant,
    User,
    aware,
    utcnow,
)
from .common import SessionLocal, get_incident, iso, tenant_of

router = APIRouter(tags=["v0.4"])


# ---------------- tenants ----------------
class TenantBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    wazuh_groups: list[str] = Field(default_factory=list, max_length=50)
    host_patterns: list[str] = Field(default_factory=list, max_length=50)
    brand: dict = Field(default_factory=dict)
    contacts: list[dict] = Field(default_factory=list, max_length=20)
    active: bool = True


def _t_out(t: Tenant) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "slug": t.slug,
        "wazuh_groups": t.wazuh_groups,
        "host_patterns": t.host_patterns,
        "brand": t.brand,
        "contacts": t.contacts,
        "active": t.active,
        "created_at": iso(t.created_at),
    }


@router.get("/api/tenants")
def tenants(user=Depends(viewer)):
    with SessionLocal() as db:
        q = select(Tenant).order_by(Tenant.name)
        if tenant_of(user):
            q = q.where(Tenant.id == tenant_of(user))
        return [_t_out(t) for t in db.scalars(q)]


@router.post("/api/tenants", status_code=201)
def add_tenant(b: TenantBody, user=Depends(p_admin)):
    slug = re.sub(r"[^a-z0-9]+", "-", b.name.lower()).strip("-")[:60] or "tenant"
    brand = {k: str(v)[:120] for k, v in (b.brand or {}).items() if k in ("color", "title", "footer")}
    if "color" in brand and not re.fullmatch(r"#[0-9A-Fa-f]{6}", brand["color"]):
        raise SieveError(BAD_REQUEST, "Brand colour must look like #0B6E69.", status=422)
    with SessionLocal() as db:
        if db.scalar(select(Tenant.id).where((Tenant.name == b.name) | (Tenant.slug == slug))):
            raise SieveError(BAD_REQUEST, "A tenant with that name exists.", status=409)
        t = Tenant(
            name=b.name.strip(),
            slug=slug,
            wazuh_groups=b.wazuh_groups,
            host_patterns=b.host_patterns,
            brand=brand,
            contacts=b.contacts,
            active=b.active,
        )
        db.add(t)
        db.flush()
        from ..tenancy import retag

        retag(db)   # back-fill history, not only future alerts
        db.commit()
        out = _t_out(t)
    audit(user.username, "tenant.created", out["slug"], groups=b.wazuh_groups, patterns=b.host_patterns)
    return out


@router.put("/api/tenants/{tid}")
def edit_tenant(tid: int, b: TenantBody, user=Depends(p_admin)):
    with SessionLocal() as db:
        t = db.get(Tenant, tid)
        if not t:
            raise SieveError(NOT_FOUND, "Tenant not found.", status=404)
        t.name, t.wazuh_groups, t.host_patterns, t.contacts, t.active = (
            b.name,
            b.wazuh_groups,
            b.host_patterns,
            b.contacts,
            b.active,
        )
        t.brand = {k: str(v)[:120] for k, v in (b.brand or {}).items() if k in ("color", "title", "footer")}
        db.flush()
        from ..tenancy import retag

        retag(db)   # back-fill history, not only future alerts
        db.commit()
        out = _t_out(t)
    audit(user.username, "tenant.updated", out["slug"])
    return out


@router.get("/api/tenants/cross-attackers")
def cross_attackers(days: int = 7, user=Depends(p_viewer)):
    from ..tenancy import cross_tenant_attackers

    with SessionLocal() as db:
        return cross_tenant_attackers(db, max(1, min(days, 90)))


@router.get("/api/tenants/{tid}/usage")
def tenant_usage(tid: int, days: int = 30, user=Depends(viewer)):
    if tenant_of(user) and tenant_of(user) != tid:
        raise SieveError(NOT_FOUND, "Tenant not found.", status=404)
    from ..tenancy import usage

    with SessionLocal() as db:
        if not db.get(Tenant, tid):
            raise SieveError(NOT_FOUND, "Tenant not found.", status=404)
        return usage(db, tid, max(1, min(days, 365)))


@router.post("/api/tenants/refresh-agents")
async def refresh_agents(user=Depends(p_admin)):
    from ..tenancy import refresh_agent_groups

    n = await refresh_agent_groups(runtime.current())
    audit(user.username, "tenant.agents_refreshed", str(n))
    return {"agents": n}


class UserTenantBody(BaseModel):
    tenant_id: int | None = None


@router.post("/api/users/{uid}/tenant")
def set_user_tenant(uid: int, b: UserTenantBody, user=Depends(p_admin)):
    with SessionLocal() as db:
        u = db.get(User, uid)
        if not u:
            raise SieveError(NOT_FOUND, "User not found.", status=404)
        if b.tenant_id and u.role == "admin":
            raise SieveError(BAD_REQUEST, "Admins are provider staff. Make the user an analyst or viewer first.", status=422)
        if b.tenant_id and not db.get(Tenant, b.tenant_id):
            raise SieveError(NOT_FOUND, "Tenant not found.", status=404)
        u.tenant_id = b.tenant_id
        db.commit()
    audit(user.username, "user.tenant", str(uid), tenant_id=b.tenant_id)
    return {"ok": True}


class InviteBody2(BaseModel):
    role: Literal["viewer", "analyst", "admin"] = "analyst"
    tenant_id: int | None = None


@router.post("/api/users/invite-tenant", status_code=201)
def invite_tenant(b: InviteBody2, user=Depends(p_admin)):
    from ..auth import create_invite

    tok = create_invite(b.role, user.username, b.tenant_id)
    audit(user.username, "user.invite_created", b.role, tenant_id=b.tenant_id)
    return {
        "url": f"{runtime.current().notify.public_url.rstrip('/')}/invite/{tok}",
        "role": b.role,
        "tenant_id": b.tenant_id,
        "expires_in_hours": 72,
    }


# ---------------- agents ----------------
@router.get("/api/agents")
def agents(user=Depends(viewer)):
    from ..assets import silent_agents

    s = runtime.current()
    silent = {a["agent_name"]: a for a in silent_agents(s)}
    with SessionLocal() as db:
        q = select(AgentState).order_by(AgentState.agent_name)
        if tenant_of(user):
            q = q.where(AgentState.tenant_id == tenant_of(user))
        names = {t.id: t.name for t in db.scalars(select(Tenant))}
        return [
            {
                "agent_name": a.agent_name,
                "agent_id": a.agent_id,
                "groups": a.groups,
                "tenant": names.get(a.tenant_id),
                "tenant_id": a.tenant_id,
                "last_alert_at": iso(a.last_alert_at),
                "alerts_7d": a.alerts_7d,
                "status": a.status,
                "silent": silent.get(a.agent_name),
                "vulns": {"critical": (a.vulns or {}).get("critical", 0), "high": (a.vulns or {}).get("high", 0)},
                "criticality": s.criticality_label(a.agent_name),
            }
            for a in db.scalars(q)
        ]


@router.get("/api/health/sources")
def source_health(user=Depends(p_viewer)):
    from ..assets import quiet_rules, silent_agents

    return {"silent_agents": silent_agents(runtime.current()), "quiet_rules": quiet_rules()}


# ---------------- compliance, report, evidence ----------------
class ComplianceBody(BaseModel):
    aware_at: str | None = None
    nis2_applies: bool | None = None
    dora_applies: bool | None = None
    dora_criteria: dict[str, bool] | None = None
    dora_malicious_loss: bool | None = None
    dora_classified_major_at: str | None = None
    personal_data: bool | None = None
    gdpr_aware_at: str | None = None
    mark_sent: str | None = Field(
        None, pattern=r"^(nis2_early|nis2_notification|nis2_final|dora_initial|dora_intermediate|dora_final|gdpr_dpa)_sent$"
    )


@router.get("/api/incidents/{inc_id}/compliance")
def get_compliance(inc_id: int, user=Depends(viewer)):
    from ..compliance import DORA_CRITERIA, clocks

    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        return {
            **clocks(i, runtime.current().compliance),
            "dora_criteria_labels": DORA_CRITERIA,
            "enabled": runtime.current().compliance.model_dump(),
        }


@router.put("/api/incidents/{inc_id}/compliance")
def put_compliance(inc_id: int, b: ComplianceBody, user=Depends(analyst)):
    from datetime import datetime

    from ..compliance import DORA_CRITERIA, clocks

    patch = b.model_dump(exclude_none=True)
    for k in ("aware_at", "dora_classified_major_at", "gdpr_aware_at"):
        if k in patch:
            try:
                datetime.fromisoformat(patch[k].replace("Z", "+00:00"))
            except ValueError as e:
                raise SieveError(BAD_REQUEST, f"{k} must be an ISO 8601 time.", status=422) from e
    if "dora_criteria" in patch:
        patch["dora_criteria"] = {k: bool(v) for k, v in patch["dora_criteria"].items() if k in DORA_CRITERIA}
    sent = patch.pop("mark_sent", None)
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        c = dict(i.compliance or {})
        c.update(patch)
        if sent:
            c[sent] = utcnow().isoformat()
        c.setdefault("history", [])
        c["history"] = [
            *c["history"][-50:],
            {"at": utcnow().isoformat(), "by": user.username, "set": sorted(patch) + ([sent] if sent else [])},
        ]
        i.compliance = c
        db.commit()
        out = clocks(i, runtime.current().compliance)
    audit(user.username, "compliance.updated", f"INC-{inc_id}", fields=sorted(patch), sent=sent)
    return out


def _trace(inc_id: int, user) -> dict:
    from .smart import decision_trace

    return decision_trace(inc_id, user)


@router.get("/api/incidents/{inc_id}/report.md", response_class=PlainTextResponse)
def report_md(inc_id: int, user=Depends(viewer)):
    from ..compliance import clocks, report_markdown

    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        md = report_markdown(i, _trace(inc_id, user), clocks(i, runtime.current().compliance))
    audit(user.username, "incident.report_exported", f"INC-{inc_id}")
    return PlainTextResponse(md, headers={"Content-Disposition": f'attachment; filename="sieve-INC-{inc_id:04d}-report.md"'})


@router.get("/api/incidents/{inc_id}/evidence-pack")
def evidence(inc_id: int, user=Depends(analyst)):
    from ..compliance import clocks, evidence_pack, report_markdown

    s = runtime.current()
    with SessionLocal() as db:
        i = get_incident(db, inc_id, user)
        tr = _trace(inc_id, user)
        md = report_markdown(i, tr, clocks(i, s.compliance))
        raws = [a.raw for a in db.scalars(select(Alert).where(Alert.incident_id == inc_id))]
        blob, manifest = evidence_pack(i, tr, md, raws, s.secret_key, user.username)
    audit(user.username, "incident.evidence_pack", f"INC-{inc_id}", sha256=manifest["sha256"], hmac=manifest["hmac_sha256"][:16])
    return Response(
        blob,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="sieve-INC-{inc_id:04d}-evidence.zip"'},
    )


@router.post("/api/evidence/verify")
async def verify_pack(request: Request, user=Depends(analyst)):
    import io
    import zipfile

    from ..compliance import verify_manifest

    body = await request.body()
    if len(body) > 50 * 1024 * 1024:
        raise SieveError(BAD_REQUEST, "File too large.", status=413)
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
        manifest = json.loads(z.read("MANIFEST.json"))
        files = {n: z.read(n) for n in manifest["sha256"]}
    except (zipfile.BadZipFile, KeyError, ValueError) as e:
        raise SieveError(BAD_REQUEST, "Not a Sieve evidence pack.", status=422) from e
    ok = verify_manifest(manifest, files, runtime.current().secret_key)
    return {
        "valid": ok,
        "incident": manifest.get("incident"),
        "exported_at": manifest.get("exported_at"),
        "exported_by": manifest.get("exported_by"),
    }


# ---------------- pilot ----------------
@router.post("/api/pilot/start")
def pilot_start(user=Depends(p_admin)):
    from ..pilot import start

    res = start(user.username)
    audit(user.username, "pilot.started", res["started_at"])
    return res


@router.get("/api/pilot/report")
def pilot_report(tenant: int | None = None, user=Depends(viewer)):
    from ..pilot import report

    return report(runtime.current(), tenant_id=tenant_of(user) or tenant)


@router.post("/api/pilot/selftest")
def pilot_selftest(sample: int = 120, user=Depends(p_admin)):
    from ..pilot import injection_selftest

    res = injection_selftest(runtime.current(), max(10, min(sample, 500)))
    audit(user.username, "pilot.selftest", f"{res['incidents_tested']} incidents", bands_changed=res["bands_changed"])
    return res


# ---------------- AI governance ----------------
@router.get("/api/ai/permissions")
def ai_permissions(user=Depends(p_admin)):
    from ..auth import SCOPES

    s = runtime.current()
    with SessionLocal() as db:
        calls = db.scalars(select(LlmCall).order_by(LlmCall.id.desc()).limit(50)).all()
        toks = db.scalars(select(ApiToken).order_by(ApiToken.id.desc())).all()
    sent = [
        "rule IDs and levels",
        "timestamps",
        "validated IPs, users and host names",
        "score breakdown",
        "ATT&CK IDs",
        "rule-based facts",
        "company profile",
        "untrusted log fields (fenced, escaped, capped at 1,000 characters each)",
    ]
    return {
        "providers": [
            {
                "name": p.name,
                "model": p.model,
                "cloud": p.is_cloud,
                "enabled": p.enabled,
                "receives": sent
                if not p.is_cloud or not s.llm.mask_for_cloud
                else [
                    x.replace("validated IPs, users and host names", "pseudonyms instead of IPs, users and host names")
                    for x in sent
                ],
            }
            for p in s.llm.providers
        ],
        "never_sent": [
            "passwords and API keys",
            "your notes and comments",
            "other incidents",
            "raw alert JSON outside the fence",
        ],
        "model_powers": "None. Models cannot call tools, change severity, run actions, or query data directly.",
        "masking_for_cloud": s.llm.mask_for_cloud,
        "budget_per_hour": s.llm.calls_per_hour,
        "scopes": {k: [f"{m} {p}*" for m, p in v] for k, v in SCOPES.items()},
        "tokens": [
            {
                "id": t.id,
                "name": t.name,
                "role": t.role,
                "scopes": t.scopes,
                "tenant_id": t.tenant_id,
                "uses": t.use_count,
                "last_used_at": iso(t.last_used_at),
                "revoked": t.revoked,
            }
            for t in toks
        ],
        "recent_calls": [
            {
                "at": iso(c.at),
                "provider": c.provider,
                "purpose": c.purpose,
                "ok": c.ok,
                "incident_id": c.incident_id,
                "latency_ms": c.latency_ms,
                "tokens": c.tokens,
            }
            for c in calls
        ],
    }


class ScopedToken(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    scopes: list[Literal["incidents:read", "incidents:write", "ask", "reports", "intel", "admin"]] | None = None
    tenant_id: int | None = None
    expires_in_days: int | None = Field(90, ge=1, le=730)


@router.post("/api/tokens/scoped", status_code=201)
def new_scoped_token(b: ScopedToken, user=Depends(p_admin)):
    if b.tenant_id and b.role == "admin":
        raise SieveError(BAD_REQUEST, "Customer tokens cannot be admin.", status=422)
    tok, row = create_api_token(b.name, b.role, user.username, b.expires_in_days, b.scopes, b.tenant_id)
    audit(user.username, "token.created", b.name, role=b.role, scopes=b.scopes, tenant_id=b.tenant_id, prefix=row.prefix)
    return {"token": tok, "id": row.id, "scopes": b.scopes, "note": "Shown once. For MCP use scopes incidents:read and ask."}


# ---------------- automation rules ----------------
class RuleBody(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    trigger: Literal["incident.created", "incident.band_raised", "incident.tripwire", "incident.overdue"]
    conditions: dict = Field(default_factory=dict)
    actions: list[dict] = Field(min_length=1, max_length=10)
    enabled: bool = True
    tenant_id: int | None = None


def _check_rule(b: RuleBody) -> None:
    from ..automation import ACTIONS

    allowed = {"min_band", "hosts", "rule_ids", "techniques", "tripwire", "tags_any"}
    if set(b.conditions) - allowed:
        raise SieveError(BAD_REQUEST, f"Unknown condition(s): {', '.join(sorted(set(b.conditions) - allowed))}.", status=422)
    for a in b.actions:
        if a.get("type") not in ACTIONS:
            raise SieveError(
                BAD_REQUEST, f"Action must be one of {', '.join(ACTIONS)}. Response on hosts is never automated.", status=422
            )
        if a["type"] == "webhook" and not str(a.get("url", "")).startswith("https://"):
            raise SieveError(BAD_REQUEST, "Webhook actions need an https:// URL.", status=422)


def _r_out(r: AutomationRule) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "trigger": r.trigger,
        "conditions": r.conditions,
        "actions": r.actions,
        "enabled": r.enabled,
        "tenant_id": r.tenant_id,
        "runs": r.runs,
        "last_run_at": iso(r.last_run_at),
        "created_by": r.created_by,
    }


@router.get("/api/automation-rules")
def list_rules(user=Depends(p_viewer)):
    with SessionLocal() as db:
        return [_r_out(r) for r in db.scalars(select(AutomationRule).order_by(AutomationRule.id))]


@router.post("/api/automation-rules", status_code=201)
def add_rule(b: RuleBody, user=Depends(p_admin)):
    _check_rule(b)
    with SessionLocal() as db:
        r = AutomationRule(
            name=b.name,
            trigger=b.trigger,
            conditions=b.conditions,
            actions=b.actions,
            enabled=b.enabled,
            tenant_id=b.tenant_id,
            created_by=user.username,
        )
        db.add(r)
        db.commit()
        out = _r_out(r)
    audit(user.username, "automation.created", b.name, rule=out)
    return out


@router.delete("/api/automation-rules/{rid}")
def del_rule(rid: int, user=Depends(p_admin)):
    with SessionLocal() as db:
        r = db.get(AutomationRule, rid)
        if not r:
            raise SieveError(NOT_FOUND, "Rule not found.", status=404)
        r.enabled = False
        db.commit()
    audit(user.username, "automation.disabled", f"rule#{rid}")
    return {"ok": True}


@router.post("/api/automation-rules/dry-run")
def dry_run(b: RuleBody, incident_id: int, user=Depends(p_analyst)):
    from ..automation import matches

    _check_rule(b)
    with SessionLocal() as db:
        i = get_incident(db, incident_id, user)
        r = AutomationRule(
            name=b.name, trigger=b.trigger, conditions=b.conditions, actions=b.actions, tenant_id=b.tenant_id, created_by="dry"
        )
        return {"would_match": matches(r, i), "actions": [a.get("type") for a in b.actions]}


# ---------------- detection drafts ----------------
@router.get("/api/coverage/draft/{technique}")
def draft(technique: str, user=Depends(p_analyst)):
    from ..backtest import backtest
    from ..detection import draft_for

    if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
        raise SieveError(BAD_REQUEST, "Give an ATT&CK technique ID such as T1110.", status=422)
    d = draft_for(technique)
    if not d:
        return {
            "technique": technique,
            "available": False,
            "message": "No reviewed draft for this technique yet. Search SigmaHQ (3,000+ community rules) "
            "and backtest it under Investigate.",
        }
    try:
        bt = backtest(d["sigma"], 30)
    except SieveError as e:
        bt = {"error": e.message}
    return {
        **d,
        "available": True,
        "backtest": bt,
        "note": "Draft only. Review it, backtest it, then add it to Wazuh yourself. Sieve never deploys rules.",
    }


# ---------------- chat-ops ----------------
@router.post("/api/chatops/link-code")
def link_code(user=Depends(viewer)):
    if user.id < 0:
        raise SieveError(BAD_REQUEST, "API tokens cannot be linked to chat.", status=422)
    from ..chatops import new_link_code

    code = new_link_code(user.id)
    audit(user.username, "chatops.link_code", user.username)
    return {
        "code": code,
        "telegram": f"Send /link {code} to your Sieve bot.",
        "slack": "Use the code in the Link account button in Slack.",
        "expires": "single use",
    }


@router.post("/api/integrations/telegram/webhook")
async def telegram_webhook(request: Request):
    from .. import http, secrets_store
    from ..chatops import handle_telegram

    s = runtime.current()
    res = handle_telegram(await request.json(), s, request.headers.get("x-telegram-bot-api-secret-token", ""))
    if res.get("status") == 401:
        raise SieveError("SIEVE-AUTH-403", "Bad Telegram secret.", status=401)
    tok = secrets_store.resolve(s.notify.telegram.token_env)
    if tok and res.get("reply"):
        async with http.client(timeout=10) as c:
            if res.get("callback_id"):
                await c.post(
                    f"https://api.telegram.org/bot{tok}/answerCallbackQuery",
                    json={"callback_query_id": res["callback_id"], "text": res["reply"][:190], "show_alert": False},
                )
            elif res.get("chat_id"):
                await c.post(
                    f"https://api.telegram.org/bot{tok}/sendMessage", json={"chat_id": res["chat_id"], "text": res["reply"]}
                )
    return {"ok": True}


@router.post("/api/integrations/slack/actions")
async def slack_actions(request: Request):
    from urllib.parse import parse_qs

    from ..chatops import handle_slack, verify_slack

    body = await request.body()
    if not verify_slack(
        runtime.current(),
        request.headers.get("x-slack-request-timestamp", ""),
        request.headers.get("x-slack-signature", ""),
        body,
    ):
        raise SieveError("SIEVE-AUTH-403", "Bad Slack signature.", status=401)
    payload = json.loads((parse_qs(body.decode()).get("payload") or ["{}"])[0])
    return {"response_type": "ephemeral", "replace_original": False, "text": handle_slack(payload)}


# ---------------- push and on-call ----------------
@router.get("/api/push/vapid")
def vapid(user=Depends(viewer)):
    from ..chatops import vapid_keys

    return {"public_key": vapid_keys()["public"]}


class SubBody(BaseModel):
    endpoint: str = Field(min_length=10, max_length=2000)
    keys: dict


@router.post("/api/push/subscribe", status_code=201)
def subscribe(b: SubBody, user=Depends(viewer)):
    if user.id < 0 or not b.endpoint.startswith("https://") or not {"p256dh", "auth"} <= set(b.keys):
        raise SieveError(BAD_REQUEST, "Invalid push subscription.", status=422)
    with SessionLocal() as db:
        row = db.scalar(select(PushSubscription).where(PushSubscription.endpoint == b.endpoint))
        if row:
            row.user_id, row.keys = user.id, b.keys
        else:
            db.add(
                PushSubscription(user_id=user.id, endpoint=b.endpoint, keys={"p256dh": b.keys["p256dh"], "auth": b.keys["auth"]})
            )
        db.commit()
    audit(user.username, "push.subscribed", user.username)
    return {"ok": True}


@router.post("/api/push/test")
async def push_test(user=Depends(viewer)):
    from ..chatops import push_users
    from ..models import Incident

    fake = Incident(id=0, title="Sieve test notification", agent_name="your phone", band="low")
    n = await push_users([user.username], fake, runtime.current(), "test")
    return {"sent": n}


class OnCallBody(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    members: list[str] = Field(min_length=1, max_length=50)
    starts_at: str | None = None
    shift_hours: int = Field(168, ge=1, le=24 * 31)
    tenant_id: int | None = None


@router.get("/api/oncall")
def oncall(user=Depends(viewer)):
    from ..chatops import on_call_now, schedule

    with SessionLocal() as db:
        rows = db.scalars(select(OnCall).where(OnCall.enabled.is_(True))).all()
        return {
            "now": on_call_now(db, tenant_of(user)),
            "rotations": [
                {
                    "id": r.id,
                    "name": r.name,
                    "members": r.members,
                    "shift_hours": r.shift_hours,
                    "tenant_id": r.tenant_id,
                    "next": schedule(r),
                }
                for r in rows
                if not tenant_of(user) or r.tenant_id in (None, tenant_of(user))
            ],
        }


@router.post("/api/oncall", status_code=201)
def add_oncall(b: OnCallBody, user=Depends(p_admin)):
    from datetime import datetime

    with SessionLocal() as db:
        known = {u for (u,) in db.execute(select(User.username))}
        missing = [m for m in b.members if m not in known]
        if missing:
            raise SieveError(BAD_REQUEST, f"Unknown users: {', '.join(missing)}.", status=422)
        st = aware(datetime.fromisoformat(b.starts_at.replace("Z", "+00:00"))) if b.starts_at else utcnow()
        r = OnCall(name=b.name, members=b.members, starts_at=st, shift_hours=b.shift_hours, tenant_id=b.tenant_id)
        db.add(r)
        db.commit()
        rid = r.id
    audit(user.username, "oncall.created", b.name, members=b.members)
    return {"ok": True, "id": rid}


@router.delete("/api/oncall/{rid}")
def del_oncall(rid: int, user=Depends(p_admin)):
    with SessionLocal() as db:
        r = db.get(OnCall, rid)
        if not r:
            raise SieveError(NOT_FOUND, "Rotation not found.", status=404)
        r.enabled = False
        db.commit()
    audit(user.username, "oncall.disabled", f"rotation#{rid}")
    return {"ok": True}


# ---------------- risk-based alerting ----------------
@router.get("/api/risk")
def risk(user=Depends(viewer)):
    from ..behaviour import top_risk

    with SessionLocal() as db:
        return top_risk(db, runtime.current(), tenant_of(user))


@router.delete("/api/risk/{entity}")
def reset_risk(entity: str, user=Depends(analyst)):
    from ..models import EntityRisk

    with SessionLocal() as db:
        r = db.get(EntityRisk, entity[:260])
        if not r or (tenant_of(user) and r.tenant_id != tenant_of(user)):
            raise SieveError(NOT_FOUND, "Entity not found.", status=404)
        r.points = 0
        db.commit()
    audit(user.username, "risk.reset", entity[:200])
    return {"ok": True}


# ---------------- dashboards ----------------
WIDGETS = [
    "kpis",
    "open_by_band",
    "sla_breaches",
    "top_hosts",
    "top_ips",
    "risk_top",
    "open_by_owner",
    "tripwires",
    "compliance_due",
    "silent_sources",
    "noise_trend",
]
DEFAULT_LAYOUT = ["kpis", "open_by_band", "sla_breaches", "risk_top", "top_hosts", "compliance_due"]


class LayoutBody(BaseModel):
    widgets: list[str] = Field(max_length=20)


@router.get("/api/dashboard")
def get_layout(user=Depends(viewer)):
    from ..models import KV

    with SessionLocal() as db:
        row = db.get(KV, f"dash:{user.id}")
    return {"widgets": (row.value.get("widgets") if row else None) or DEFAULT_LAYOUT, "available": WIDGETS}


@router.put("/api/dashboard")
def put_layout(b: LayoutBody, user=Depends(viewer)):
    from ..models import KV

    w = [x for x in b.widgets if x in WIDGETS]
    with SessionLocal() as db:
        row = db.get(KV, f"dash:{user.id}")
        if row:
            row.value = {"widgets": w}
        else:
            db.add(KV(key=f"dash:{user.id}", value={"widgets": w}))
        db.commit()
    return {"widgets": w}


@router.get("/api/dashboard/data")
def dash_data(tenant: int | None = None, user=Depends(viewer)):
    from collections import Counter
    from datetime import timedelta

    from sqlalchemy import func

    from ..behaviour import top_risk
    from ..compliance import clocks
    from ..models import Incident, Notification
    from .common import scoped

    s = runtime.current()
    now = utcnow()
    with SessionLocal() as db:
        open_ = db.scalars(
            scoped(select(Incident).where(Incident.status.in_(("new", "acknowledged"))), Incident.tenant_id, user, tenant)
        ).all()
        week = db.scalars(
            scoped(select(Incident).where(Incident.opened_at >= now - timedelta(days=7)), Incident.tenant_id, user, tenant)
        ).all()
        alerts_today = (
            db.scalar(
                scoped(
                    select(func.count(Alert.id)).where(Alert.received_at >= now - timedelta(hours=24)),
                    Alert.tenant_id,
                    user,
                    tenant,
                )
            )
            or 0
        )
        ids = [i.id for i in week] or [-1]
        notes_today = (
            db.scalar(
                select(func.count(Notification.id)).where(
                    Notification.at >= now - timedelta(hours=24), Notification.phase == "send", Notification.incident_id.in_(ids)
                )
            )
            or 0
        )
        due = []
        for i in open_:
            for reg, items in clocks(i, s.compliance)["regimes"].items():
                for it in items:
                    if it["state"] != "sent" and it.get("minutes_left") is not None and it["minutes_left"] < 24 * 60:
                        due.append(
                            {"id": i.id, "title": i.title, "regime": reg, "item": it["name"], "minutes_left": it["minutes_left"]}
                        )
        daily = Counter(aware(i.opened_at).strftime("%m-%d") for i in week)
        risk_rows = top_risk(db, s, tenant_of(user) or tenant, 8)
    from ..assets import silent_agents

    silent = [a for a in silent_agents(s) if not (tenant_of(user) or tenant) or a["tenant_id"] == (tenant_of(user) or tenant)]
    return {
        "kpis": {
            "open": len(open_),
            "alerts_24h": alerts_today,
            "notifications_24h": notes_today,
            "critical_open": sum(i.band == "critical" for i in open_),
        },
        "open_by_band": dict(Counter(i.band for i in open_)),
        "sla_breaches": [
            {"id": i.id, "title": i.title, "band": i.band}
            for i in open_
            if i.status == "new" and i.sla_due and aware(i.sla_due) < now
        ][:10],
        "top_hosts": Counter(i.agent_name for i in week if i.agent_name).most_common(6),
        "top_ips": Counter(i.srcip for i in week if i.srcip).most_common(6),
        "risk_top": risk_rows,
        "open_by_owner": Counter(i.assignee or "Unassigned" for i in open_).most_common(8),
        "tripwires": [{"id": i.id, "title": i.title} for i in week if i.tripwire][:8],
        "compliance_due": sorted(due, key=lambda x: x["minutes_left"])[:8],
        "silent_sources": silent[:8],
        "noise_trend": sorted(daily.items()),
    }

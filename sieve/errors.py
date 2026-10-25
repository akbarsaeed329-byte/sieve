"""Stable, documented error codes. Every user-facing error carries a code, a message and a fix.

See docs/ERROR_CODES.md. Never change the meaning of an existing code; add new ones instead.
The ``FIXES`` table is the single source for the human-readable fix shown in the UI and on the
troubleshooting page, so call sites never invent fix text for a known code.
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

    def __post_init__(self) -> None:
        if not self.fix:
            self.fix = FIXES.get(self.code, "")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "fix": self.fix}


# Catalogue (keep in sync with docs/ERROR_CODES.md)
CONFIG_INVALID = "SIEVE-CFG-001"
CONFIG_READONLY = "SIEVE-CFG-002"
INGEST_BAD_TOKEN = "SIEVE-ING-401"
INGEST_BAD_PAYLOAD = "SIEVE-ING-400"
INGEST_TOO_LARGE = "SIEVE-ING-413"
AUTH_BAD_LOGIN = "SIEVE-AUTH-401"
AUTH_REQUIRED = "SIEVE-AUTH-403"
AUTH_WEAK_PASSWORD = "SIEVE-AUTH-422"
AUTH_LOCKED = "SIEVE-AUTH-423"
AUTH_CSRF = "SIEVE-AUTH-419"
AUTH_INVITE_INVALID = "SIEVE-AUTH-410"
AUTH_USER_EXISTS = "SIEVE-AUTH-409"
AUTH_LAST_ADMIN = "SIEVE-AUTH-428"
SETUP_DONE = "SIEVE-SETUP-409"
LLM_TIMEOUT = "SIEVE-LLM-504"
LLM_RATE_LIMIT = "SIEVE-LLM-429"
LLM_AUTH = "SIEVE-LLM-401"
LLM_BAD_OUTPUT = "SIEVE-LLM-422"
LLM_ALL_FAILED = "SIEVE-LLM-503"
LLM_BUDGET = "SIEVE-LLM-509"
NOTIFY_FAILED = "SIEVE-NTF-502"
NOTIFY_NOT_CONFIGURED = "SIEVE-NTF-424"
NOT_FOUND = "SIEVE-API-404"
BAD_REQUEST = "SIEVE-API-400"
WAZUH_NOT_CONFIGURED = "SIEVE-WZ-424"
WAZUH_AUTH = "SIEVE-WZ-401"
WAZUH_UNREACHABLE = "SIEVE-WZ-504"
WAZUH_ERROR = "SIEVE-WZ-502"
AR_DISABLED = "SIEVE-AR-403"
AR_NOT_CONFIRMED = "SIEVE-AR-428"
AR_NOT_APPLICABLE = "SIEVE-AR-422"
INTEL_AUTH = "SIEVE-INTEL-401"
INTEL_QUOTA = "SIEVE-INTEL-429"
INTEL_UNREACHABLE = "SIEVE-INTEL-504"
PLUGIN_UNKNOWN = "SIEVE-PLG-404"
PLUGIN_BAD_SETTINGS = "SIEVE-PLG-422"
RULE_PARSE = "SIEVE-RULE-422"
AUTH_TOTP = "SIEVE-AUTH-449"
RATE_LIMITED = "SIEVE-RATE-429"
AUTH_2FA_REQUIRED = "SIEVE-AUTH-450"
CASE_EVIDENCE = "SIEVE-CASE-428"
SSO_ERROR = "SIEVE-SSO-502"
SSO_OFF = "SIEVE-SSO-404"

FIXES: dict[str, str] = {
    CONFIG_INVALID: "Compare your file with config/sieve.example.yaml, or run `sieve check-config`.",
    CONFIG_READONLY: "Sieve saves UI changes to data/settings.override.yaml; make the data directory writable.",
    INGEST_BAD_TOKEN: "Use the output of `sieve token` as the api_key in the Wazuh <integration> block.",
    INGEST_BAD_PAYLOAD: "Send Wazuh alerts.json objects; each one needs a 'rule' object.",
    INGEST_TOO_LARGE: "Send at most 1,000 alerts and 5 MB per request.",
    AUTH_BAD_LOGIN: "Check the username and password. Repeated failures lock the account for 30 minutes.",
    AUTH_REQUIRED: "Sign in again, or ask an admin for a role that allows this.",
    AUTH_WEAK_PASSWORD: "Use 12 or more characters; a passphrase of four words works well.",
    AUTH_LOCKED: "Wait for the lock to expire, or ask an admin to unlock the account.",
    AUTH_CSRF: "Reload the page so the browser gets a fresh security token, then try again.",
    AUTH_INVITE_INVALID: "Ask an admin for a new invite link; each link works once and expires after 72 hours.",
    AUTH_USER_EXISTS: "Choose a different username.",
    AUTH_LAST_ADMIN: "Promote another user to admin first; Sieve always keeps at least one admin.",
    SETUP_DONE: "Setup is already complete. Sign in instead.",
    LLM_TIMEOUT: "Check that the model server's base_url is reachable from Sieve, or pick a smaller model.",
    LLM_RATE_LIMIT: "Lower llm.calls_per_hour or add another provider to the fallback chain.",
    LLM_AUTH: "Check the API key for this provider in Settings > Models (or its environment variable).",
    LLM_BAD_OUTPUT: "Try another model; the explanation's validation report shows what was rejected.",
    LLM_ALL_FAILED: "Rule-based facts are still shown and notifications still go out. Check Health.",
    LLM_BUDGET: "The hourly AI budget is used up; raise llm.calls_per_hour or wait for the next hour.",
    NOTIFY_FAILED: "Check the bot token and chat or channel ID in Settings > Integrations, then press Test.",
    NOTIFY_NOT_CONFIGURED: "Enable and configure this channel in Settings > Integrations first.",
    NOT_FOUND: "Reload the page; the item may have been removed.",
    BAD_REQUEST: "Check the values you entered and try again.",
    WAZUH_NOT_CONFIGURED: "Add the Wazuh manager or indexer URL in Settings > Integrations.",
    WAZUH_AUTH: "Check the Wazuh API user and password; use a read-only user for queries.",
    WAZUH_UNREACHABLE: "Check the Wazuh URL and port, and that Sieve can reach it (firewall, Docker network).",
    WAZUH_ERROR: "Wazuh returned an error; check the Wazuh manager logs.",
    AR_DISABLED: "Active response is off. An admin can set allow_active_response: true in the config.",
    AR_NOT_CONFIRMED: "Send {\"confirm\": true} to approve this action.",
    AR_NOT_APPLICABLE: "This incident has no source IP or user to act on.",
    INTEL_AUTH: "Check the AbuseIPDB key in SIEVE_ABUSEIPDB_KEY or Settings > Plugins.",
    INTEL_QUOTA: "The free daily lookup limit is used up; lookups resume tomorrow. Cached results still apply.",
    INTEL_UNREACHABLE: "The threat-intel service did not answer; Sieve marks the incident 'partial context'.",
    PLUGIN_UNKNOWN: "Reload the plugins page; this plugin is not installed.",
    PLUGIN_BAD_SETTINGS: "Fix the highlighted field; the plugin's settings schema rejected the value.",
    AUTH_TOTP: "Enter the current 6-digit code from your authenticator app; check the phone's clock if it keeps failing.",
    RATE_LIMITED: "Wait a minute and try again.",
    CASE_EVIDENCE: "Open the incident's evidence first (press E on the incident page), then close it.",
    SSO_ERROR: "Check the OIDC issuer URL and that Sieve can reach it; see Settings > Security.",
    SSO_OFF: "An admin can configure single sign-on under Settings > Security.",
    AUTH_2FA_REQUIRED: "Open Settings > Security and turn on two-factor sign-in; this server requires it for admins.",
    RULE_PARSE: "Paste a Sigma rule (YAML with a detection section) or a single Wazuh <rule> element.",
}


def err(code: str, message: str, status: int = 400, **kw) -> SieveError:
    """Shorthand that always attaches the catalogue fix."""
    return SieveError(code, message, FIXES.get(code, ""), status=status, **kw)

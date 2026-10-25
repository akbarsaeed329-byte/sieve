# Error codes

Every user-facing error has a stable code, a message and a fix. Never reuse a code for a different meaning.

| Code | Meaning | Usual fix |
| --- | --- | --- |
| SIEVE-CFG-001 | Configuration invalid | Compare with `config/sieve.example.yaml`; run `sieve check-config` |
| SIEVE-ING-400 | Ingest body is not a Wazuh alert | Send `alerts.json` objects (need a `rule` object) |
| SIEVE-ING-401 | Ingest token wrong or missing | Use `sieve token` output as the integration `api_key` |
| SIEVE-AUTH-401 | Wrong username or password | Retry; 5 failures lock the account for 15 minutes |
| SIEVE-AUTH-403 | Not signed in, wrong role, or CSRF token missing | Sign in again; reload the page |
| SIEVE-AUTH-422 | Password too short | 12+ characters; use a passphrase |
| SIEVE-AUTH-423 | Account locked | Wait 15 minutes or ask an admin |
| SIEVE-SETUP-409 | Setup already done | Sign in instead |
| SIEVE-LLM-401 | Provider rejected the API key | Check the env var named in `api_key_env` |
| SIEVE-LLM-429 | Provider rate limit | Lower `llm.calls_per_hour`, add a fallback provider |
| SIEVE-LLM-503 | No provider answered | Rule-based facts are still shown; check Health |
| SIEVE-LLM-504 | Provider timeout or unreachable | Check `base_url` is reachable from the container |
| SIEVE-LLM-422 | Model output unusable after validation | Try another model; see the explanation's validation report |
| SIEVE-NTF-502 | Notification channel failed | Check bot token and chat ID |
| SIEVE-API-404 | Item not found | Reload |

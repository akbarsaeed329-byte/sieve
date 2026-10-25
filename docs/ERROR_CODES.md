# Error codes

Every user-facing error has a stable code, a message and a fix. Generated from `sieve/errors.py`
(`FIXES`); a test keeps this file in sync. Never reuse a code for a different meaning.

| Code | Usual fix |
| --- | --- |
| SIEVE-API-400 | Check the values you entered and try again. |
| SIEVE-API-404 | Reload the page; the item may have been removed. |
| SIEVE-AR-403 | Active response is off. An admin can set allow_active_response: true in the config. |
| SIEVE-AR-422 | This incident has no source IP or user to act on. |
| SIEVE-AR-428 | Send {"confirm": true} to approve this action. |
| SIEVE-AUTH-401 | Check the username and password. Repeated failures lock the account for 30 minutes. |
| SIEVE-AUTH-403 | Sign in again, or ask an admin for a role that allows this. |
| SIEVE-AUTH-409 | Choose a different username. |
| SIEVE-AUTH-410 | Ask an admin for a new invite link; each link works once and expires after 72 hours. |
| SIEVE-AUTH-419 | Reload the page so the browser gets a fresh security token, then try again. |
| SIEVE-AUTH-422 | Use 12 or more characters; a passphrase of four words works well. |
| SIEVE-AUTH-423 | Wait for the lock to expire, or ask an admin to unlock the account. |
| SIEVE-AUTH-428 | Promote another user to admin first; Sieve always keeps at least one admin. |
| SIEVE-CFG-001 | Compare your file with config/sieve.example.yaml, or run `sieve check-config`. |
| SIEVE-CFG-002 | Sieve saves UI changes to data/settings.override.yaml; make the data directory writable. |
| SIEVE-ING-400 | Send Wazuh alerts.json objects; each one needs a 'rule' object. |
| SIEVE-ING-401 | Use the output of `sieve token` as the api_key in the Wazuh <integration> block. |
| SIEVE-ING-413 | Send at most 1,000 alerts and 5 MB per request. |
| SIEVE-INTEL-401 | Check the AbuseIPDB key in SIEVE_ABUSEIPDB_KEY or Settings > Plugins. |
| SIEVE-INTEL-429 | The free daily lookup limit is used up; lookups resume tomorrow. Cached results still apply. |
| SIEVE-INTEL-504 | The threat-intel service did not answer; Sieve marks the incident 'partial context'. |
| SIEVE-LLM-401 | Check the API key for this provider in Settings > Models (or its environment variable). |
| SIEVE-LLM-422 | Try another model; the explanation's validation report shows what was rejected. |
| SIEVE-LLM-429 | Lower llm.calls_per_hour or add another provider to the fallback chain. |
| SIEVE-LLM-503 | Rule-based facts are still shown and notifications still go out. Check Health. |
| SIEVE-LLM-504 | Check that the model server's base_url is reachable from Sieve, or pick a smaller model. |
| SIEVE-LLM-509 | The hourly AI budget is used up; raise llm.calls_per_hour or wait for the next hour. |
| SIEVE-NTF-424 | Enable and configure this channel in Settings > Integrations first. |
| SIEVE-NTF-502 | Check the bot token and chat or channel ID in Settings > Integrations, then press Test. |
| SIEVE-PLG-404 | Reload the plugins page; this plugin is not installed. |
| SIEVE-PLG-422 | Fix the highlighted field; the plugin's settings schema rejected the value. |
| SIEVE-RULE-422 | Paste a Sigma rule (YAML with a detection section) or a single Wazuh <rule> element. |
| SIEVE-SETUP-409 | Setup is already complete. Sign in instead. |
| SIEVE-WZ-401 | Check the Wazuh API user and password; use a read-only user for queries. |
| SIEVE-WZ-424 | Add the Wazuh manager or indexer URL in Settings > Integrations. |
| SIEVE-WZ-502 | Wazuh returned an error; check the Wazuh manager logs. |
| SIEVE-WZ-504 | Check the Wazuh URL and port, and that Sieve can reach it (firewall, Docker network). |
| SIEVE-INV-422 | The model asked for an unknown or incomplete query template; it is refused and the loop stops. |
| SIEVE-PLG-428 | Approve the plugin's permissions to enable it. |
| SIEVE-PLG-500 | A plugin crashed; it was contained. Check the logs. |
| SIEVE-PLG-504 | A plugin timed out; the incident is marked partial context. |
| SIEVE-LLM-404 | The Ollama model is not pulled; run the command shown. |
| SIEVE-NET-000 | The browser cannot reach Sieve; check that it is running. |

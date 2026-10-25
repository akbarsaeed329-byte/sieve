# Writing a Sieve plugin

A plugin is a Python module under `sieve/plugins/<type>/<name>.py` that registers a `Manifest`:

```python
from sieve.plugins import Manifest, register
MANIFEST = register(Manifest(
    id="otx", name="AlienVault OTX", type="enricher", version="1.0.0",
    description="Looks up source IPs on OTX.",
    permissions={"network": ["otx.alienvault.com"], "read_alerts": False, "trigger_response": False},
    settings_schema={"type": "object", "properties": {
        "min_pulses": {"type": "integer", "minimum": 1, "default": 2, "title": "Pulses that count as a hit"},
        "api_key": {"type": "string", "format": "password", "x-secret-name": "SIEVE_OTX_KEY"}}},
    secret_fields=["api_key"]))

async def enrich(srcip: str, settings) -> dict: ...
```

Rules: use `sieve.http.client()` (timeouts, test transport), read secrets with `secrets_store.resolve()`, raise
`SieveError` with a code from `sieve/errors.py`, cache results, respect free-tier limits, and never send private
addresses anywhere. The worker calls you through `plugins.call_safely`, so a failure becomes "partial context".
Enrichers feed deterministic score terms only; they never decide a band. Add tests with `httpx.MockTransport`.
The Settings › Plugins page renders your form from `settings_schema` and asks the admin to approve
`permissions` before the plugin is enabled. See ADR-006 for the isolation roadmap.

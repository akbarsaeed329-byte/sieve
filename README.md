<p align="center">
  <img src="docs/sieve-logo.svg" alt="Sieve" width="80">
</p>

<h1 align="center">Sieve</h1>
<p align="center">
  Free, local-first, injection-hardened triage layer for Wazuh alerts.<br>
  <strong>Turns 5,000 daily alerts into 6 trustworthy incidents.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="CONTRIBUTING.md">Contribute</a>
</p>

---

## What Sieve does

Sieve sits between Wazuh and your team.  It:

1. **Filters and groups** thousands of raw alerts into a handful of incidents
2. **Scores severity** deterministically — the AI never decides the band
3. **Detects injection** — attacker-controlled log fields that try to steer the AI are flagged as their own alert
4. **Explains in plain English** — every sentence links to the exact log lines behind it
5. **Notifies instantly** — first message within ~1 second; AI summary added to the same message a few seconds later

## Why it is different

| Feature | Most open-source scripts | Commercial AI SOC agents | **Sieve** |
|---|---|---|---|
| Free and self-hosted | ✅ | ❌ | ✅ |
| AI decides severity | Often | Not disclosed | **Never** |
| Injection defence | ❌ | Not disclosed | **Tripwire + fencing** |
| Evidence links | ❌ | Varies | **Every sentence** |
| Suppression audit | ❌ | ❌ | ✅ |
| Published benchmark | ❌ | Vendor-only | **PoisonedLogs (open)** |

## Quick start

### Option A — Docker (recommended, no Wazuh required for the demo)

```bash
git clone https://github.com/yourhandle/sieve
cd sieve
cp config/sieve.example.yaml config/sieve.yaml   # edit if you want
docker compose up -d                              # starts Sieve + Ollama

# Pull a model (first time only — ~5 GB, grab a coffee)
docker exec ollama ollama pull llama3.1:8b

# Try the demo — injects realistic alerts including a poisoned one
docker compose --profile demo up sieve-demo
```

Open **http://localhost:8080** → create your admin account → see the incidents.

### Option B — pip (bring your own Ollama or use a free cloud API)

```bash
pip install sieve-triage          # or: pip install -e . from the repo
cp config/sieve.example.yaml config/sieve.yaml
sieve demo                        # inject demo alerts
sieve serve                       # start the web UI
```

## Connect Wazuh

1. Copy `integrations/wazuh/custom-sieve.py` to `/var/ossec/integrations/custom-sieve` on your Wazuh manager
2. Set permissions: `chmod 750 ... && chown root:wazuh ...`
3. Find your ingest token: `cat data/.ingest_token`
4. Add the integration block to `/var/ossec/etc/ossec.conf` (example in the file header)
5. Restart the Wazuh manager

## Telegram notifications

```yaml
# config/sieve.yaml
notify:
  telegram:
    enabled: true
    chat_id: "YOUR_CHAT_ID"     # get from @userinfobot
    token_env: SIEVE_TELEGRAM_TOKEN
```

```bash
export SIEVE_TELEGRAM_TOKEN=your_bot_token
sieve serve
```

## Project layout

```
sieve/
  pipeline/   normalise · tripwire · filter · group · score
  llm/        fence · validate · client (fallback chain)
  notify/     console · telegram · dispatch
  api/        ingest · incidents · auth · health · metrics
  playbooks/  PB-BRUTE.yaml · PB-NEWADMIN.yaml · …
integrations/
  wazuh/      custom-sieve.py (Wazuh integration script)
samples/      brute_force.json · poisoned_brute.json
tests/        test_tripwire · test_normalise · test_score · test_filter
docs/
  adr/        ADR-001 · ADR-002 · …
config/
  sieve.example.yaml
```

## Run the tests

```bash
pytest -v
```

## The injection tripwire

When an attacker puts instructions in a log field — username, user-agent, command line — the tripwire
detects it **before** the LLM sees the data.  The detection itself becomes a separate alert in the UI,
labelled with MITRE ATLAS AML.T0051.  Because the LLM never decides severity, a successful injection
can only affect the wording of a summary, not the band or the action.

See `sieve/pipeline/tripwire.py` for the rule set and `tests/test_tripwire.py` for the test cases.

## Benchmark

The PoisonedLogs dataset and benchmark scripts are in `benchmark/` (Phase 3).  Results will be
published at v0.1 release.

## Licence

Apache 2.0 — see `LICENSE`.

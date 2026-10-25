# Install and connect Sieve (step by step)

## 1. Get it
```bash
git clone https://github.com/<your-org>/sieve.git && cd sieve
make setup            # creates config/sieve.yaml and .env from the examples
```

## 2. Run it
* **Docker (recommended):** `make up` (Sieve only) or `make up-ai` (Sieve + Ollama with llama3.1:8b).
* **Python 3.12:** `pip install -e .` then `sieve serve`.
Sieve listens on `http://127.0.0.1:8080`. For remote access put a TLS reverse proxy (Caddy, nginx) in front and
set `notify.public_url`.

## 3. First visit: the setup wizard
1. **Admin account** (12+ character passphrase).
2. **Wazuh**: manager API URL (`https://<manager>:55000`), indexer URL (`https://<indexer>:9200`), a read-only
   user and password. Press *Save and test*.
3. **AI**: local Ollama (private), a cloud OpenAI-compatible model (masked), or none. Press *Save and test*.
4. **Telegram**: chat ID and bot token. Press *Save and send test*. Slack, Discord and email are in Settings.
5. **Test alert**: Sieve runs a synthetic alert through the whole pipeline and shows the time to notification.

## 4. Get alerts into Sieve (pick one)
* **Pull mode (nothing to install):** Settings › Integrations › Wazuh: set the indexer URL and credentials, then
  set `wazuh.pull_enabled: true` (or tick it in config). Sieve polls every 15 s.
* **Push mode (lowest latency):** on the Wazuh manager:
  ```bash
  cp integrations/wazuh/custom-sieve* /var/ossec/integrations/
  chmod 750 /var/ossec/integrations/custom-sieve*; chown root:wazuh /var/ossec/integrations/custom-sieve*
  ```
  Add `integrations/wazuh/ossec.conf.snippet.xml` to `/var/ossec/etc/ossec.conf` with your Sieve address and the
  token from `sieve token`, then `systemctl restart wazuh-manager`.

## 5. Recommended hardening
* Settings › Security: turn on two-factor sign-in; tick "Require two-factor sign-in for all admins".
* Keep `bind_host: 127.0.0.1` and use a reverse proxy with HTTPS.
* Create a dedicated read-only Wazuh API user.
* Back up nightly: `sieve backup /backups/sieve-$(date +%F).db` and keep `data/.secret_key` with it.
* Start new deployments in shadow mode for a week and compare Sieve's bands with yours under Metrics.

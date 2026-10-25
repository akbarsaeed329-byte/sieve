#!/usr/bin/env python3
"""Wazuh custom integration: forward every alert to Sieve.

Deploy
------
1. Copy this file to /var/ossec/integrations/custom-sieve
2. chmod 750 /var/ossec/integrations/custom-sieve
3. chown root:wazuh /var/ossec/integrations/custom-sieve
4. Add to /var/ossec/etc/ossec.conf:

   <integration>
     <name>custom-sieve</name>
     <hook_url>http://sieve:8080/api/ingest</hook_url>
     <api_key>YOUR_INGEST_TOKEN</api_key>
     <alert_format>json</alert_format>
   </integration>

5. Restart Wazuh manager: systemctl restart wazuh-manager
"""
import json
import os
import sys
import urllib.request
import urllib.error

TIMEOUT = 10


def main():
    if len(sys.argv) < 4:
        sys.exit(0)
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        alert = json.loads(open(alert_file).read())
    except (OSError, json.JSONDecodeError):
        sys.exit(1)
    payload = json.dumps(alert).encode()
    req = urllib.request.Request(
        hook_url,
        data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=TIMEOUT)
    except urllib.error.URLError:
        sys.exit(1)


if __name__ == "__main__":
    main()

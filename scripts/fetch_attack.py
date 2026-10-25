"""Download the official MITRE ATT&CK Enterprise dataset and write data/attack_ids.txt.

After this, Sieve rejects any technique ID the model invents that is not in the real catalogue.
Usage: python scripts/fetch_attack.py [--out data/attack_ids.txt]
"""
import argparse
import json
import urllib.request

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

p = argparse.ArgumentParser()
p.add_argument("--out", default="data/attack_ids.txt")
a = p.parse_args()
with urllib.request.urlopen(URL, timeout=120) as r:
    bundle = json.load(r)
ids = set()
for o in bundle["objects"]:
    if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                ids.add(ref["external_id"])
with open(a.out, "w") as f:
    f.write("\n".join(sorted(ids)) + "\n")
print(f"Wrote {len(ids)} technique IDs to {a.out}")

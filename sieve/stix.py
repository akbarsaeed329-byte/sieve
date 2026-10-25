"""STIX 2.1 export (master prompt 3.5): the incident as a sighting of indicator objects.

IDs are deterministic UUIDv5 values so re-exporting the same incident gives the same bundle.
"""
from __future__ import annotations

import ipaddress
import uuid

from .llm.attack import info
from .models import Incident, aware

NS = uuid.UUID("6f6b6b8e-5a43-4b2b-9b51-5c1e0e0b0a11")


def _id(kind: str, *parts: object) -> str:
    return f"{kind}--{uuid.uuid5(NS, '|'.join(str(p) for p in parts))}"


def _ts(d) -> str:
    return aware(d).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def bundle(inc: Incident) -> dict:
    created = _ts(inc.opened_at)
    identity = {"type": "identity", "spec_version": "2.1", "id": _id("identity", "sieve"), "created": created,
                "modified": created, "name": "Sieve", "identity_class": "system"}
    objs: list[dict] = [identity]
    indicators = []
    if inc.srcip:
        kind = "ipv6-addr" if ipaddress.ip_address(inc.srcip).version == 6 else "ipv4-addr"
        ind = {"type": "indicator", "spec_version": "2.1", "id": _id("indicator", "ip", inc.srcip),
               "created": created, "modified": created, "created_by_ref": identity["id"],
               "name": f"Source of {inc.title}"[:200], "indicator_types": ["malicious-activity"],
               "pattern": f"[{kind}:value = '{inc.srcip}']", "pattern_type": "stix", "valid_from": created,
               "labels": [f"sieve-band:{inc.band}"]}
        indicators.append(ind)
    for t in inc.techniques:
        meta = info(t) or {}
        ap = {"type": "attack-pattern", "spec_version": "2.1", "id": _id("attack-pattern", t), "created": created,
              "modified": created, "name": meta.get("name", t),
              "external_references": [{"source_name": "mitre-attack", "external_id": t,
                                       "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}]}
        objs.append(ap)
        for ind in indicators:
            objs.append({"type": "relationship", "spec_version": "2.1", "id": _id("relationship", ind["id"], ap["id"]),
                         "created": created, "modified": created, "relationship_type": "indicates",
                         "source_ref": ind["id"], "target_ref": ap["id"]})
    objs += indicators
    target = indicators[0]["id"] if indicators else (objs[1]["id"] if len(objs) > 1 else None)
    if target:
        objs.append({"type": "sighting", "spec_version": "2.1", "id": _id("sighting", inc.id), "created": created,
                     "modified": _ts(inc.last_seen), "created_by_ref": identity["id"], "sighting_of_ref": target,
                     "first_seen": _ts(inc.first_seen), "last_seen": _ts(inc.last_seen),
                     "count": max(1, inc.alert_count), "where_sighted_refs": [identity["id"]],
                     "description": f"INC-{inc.id:04d} {inc.title} on {inc.agent_name} ({inc.band})"[:500]})
    return {"type": "bundle", "id": _id("bundle", inc.id, inc.last_seen), "objects": objs}

from datetime import UTC, datetime, timedelta

T0 = datetime(2026, 10, 16, 9, 10, 0, tzinfo=UTC)


def alert(i, *, rule="5716", level=8, groups=("sshd", "authentication_failed"), ip="203.0.113.45",
          user="deploy", host="web-01", t=None, tactic="Credential Access", tech="T1110.001", **data):
    ts = (t or (T0 + timedelta(seconds=2 * i))).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    d = {"dstuser": user, **data}
    if ip:
        d["srcip"] = ip
    return {"id": f"a-{rule}-{i}", "timestamp": ts,
            "rule": {"id": rule, "level": level, "description": f"rule {rule}", "groups": list(groups),
                     "mitre": {"id": [tech] if tech else [], "tactic": [tactic] if tactic else []}},
            "agent": {"id": "001", "name": host}, "data": d, "full_log": f"log {i}"}


def success(i=99, ip="203.0.113.45", t=None):
    return alert(i, rule="5715", level=3, groups=("sshd", "authentication_success"), ip=ip, t=t,
                 tactic="Initial Access", tech="T1078")


async def feed(alerts, settings):
    from sieve.worker import drain, enqueue, run_once
    for a in alerts:
        enqueue(a)
    while await run_once(500):
        pass
    await drain()

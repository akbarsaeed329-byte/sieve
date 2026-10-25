"""Sieve CLI: serve | demo | ingest <file> | replay <jsonl> | token | check-config | digest | version"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="sieve", description="Free, local-first triage for Wazuh alerts.")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="start the web app and the triage worker")
    d = sub.add_parser("demo", help="load demo alerts (no Wazuh needed), then serve unless --no-serve")
    d.add_argument("--no-serve", action="store_true")
    i = sub.add_parser("ingest", help="queue one alert JSON file")
    i.add_argument("file")
    r = sub.add_parser("replay", help="queue every alert in a JSONL file and process it")
    r.add_argument("file")
    sub.add_parser("token", help="print the ingest token for the Wazuh integration")
    sub.add_parser("check-config", help="validate the configuration and exit")
    g = sub.add_parser("digest", help="print (or --send) the daily digest")
    g.add_argument("--version", choices=["manager", "technical"], default="manager")
    g.add_argument("--send", action="store_true")
    bk = sub.add_parser("backup", help="write a consistent copy of the database (safe while running)")
    bk.add_argument("path")
    sub.add_parser("purge", help="apply the data-retention policy now")
    mc = sub.add_parser("mcp", help="read-only MCP server for AI assistants (stdio)")
    mc.add_argument("--url", default="http://127.0.0.1:8080")
    mc.add_argument("--token", default=None, help="viewer API token (or SIEVE_MCP_TOKEN)")
    sub.add_parser("version")
    a = p.parse_args(argv if argv is not None else sys.argv[1:])
    cmd = a.cmd or "serve"

    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from . import __version__, runtime
    from .errors import SieveError
    try:
        s = runtime.current()
    except SieveError as e:
        print(f"{e.code}: {e.message}\nFix: {e.fix}", file=sys.stderr)
        sys.exit(2)

    if cmd == "mcp":
        import os

        from .mcp_server import serve
        tok = a.token or os.environ.get("SIEVE_MCP_TOKEN", "")
        if not tok.startswith("sv_"):
            print("Give a viewer API token with --token or SIEVE_MCP_TOKEN.", file=sys.stderr)
            sys.exit(2)
        serve(a.url, tok)
        return
    if cmd == "version":
        print(f"Sieve {__version__}")
    elif cmd == "check-config":
        print(f"Config OK. data_dir={s.data_dir} bind={s.bind_host}:{s.port} providers="
              f"{[x.name for x in s.llm.providers]} shadow_mode={s.shadow_mode}")
    elif cmd == "token":
        print(s.ingest_token)
    elif cmd == "serve":
        _serve(s)
    elif cmd == "demo":
        from .demo import run_demo
        asyncio.run(run_demo())
        if not a.no_serve:
            _serve(s)
    elif cmd in ("ingest", "replay"):
        from .db import init_db
        from .worker import drain, enqueue, run_once
        init_db(s.db_path)
        with open(a.file) as f:
            items = [json.loads(line) for line in f if line.strip()] if cmd == "replay" else [json.load(f)]
        for x in items:
            enqueue(x, "cli")

        async def go():
            while await run_once(200):
                pass
            await drain()
        asyncio.run(go())
        print(f"Queued and processed {len(items)} alert(s).")
    elif cmd == "backup":
        import sqlite3
        src = sqlite3.connect(s.db_path)
        dst = sqlite3.connect(a.path)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()
        print(f"Backed up {s.db_path} to {a.path}. Also keep data/.secret_key: it decrypts stored secrets.")
    elif cmd == "purge":
        from .db import init_db
        from .housekeeping import purge_old
        init_db(s.db_path)
        print(purge_old())
    elif cmd == "digest":
        from . import digest
        from .db import init_db
        init_db(s.db_path)
        if a.send:
            print(asyncio.run(digest.send_digest(s, a.version)))
        else:
            print(digest.build(a.version)["text"])


def _serve(s) -> None:
    import uvicorn

    from .app import create_app
    uvicorn.run(create_app(), host=s.bind_host, port=s.port, log_level="info", proxy_headers=False)

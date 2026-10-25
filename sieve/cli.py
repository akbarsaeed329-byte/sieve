"""Sieve CLI: sieve serve | demo | ingest | version"""
from __future__ import annotations
import asyncio
import json
import sys


def main(argv=None):
    args = (argv or sys.argv)[1:]
    cmd = args[0] if args else "serve"

    if cmd == "version":
        import sieve
        print(f"Sieve {sieve.__version__}")
        return

    if cmd == "serve":
        import uvicorn
        from .app import create_app, get_settings
        settings = get_settings()
        uvicorn.run(create_app(), host=settings.bind_host, port=settings.port,
                    log_level="info")

    elif cmd == "demo":
        from .demo import run_demo
        asyncio.run(run_demo())

    elif cmd == "ingest":
        if len(args) < 2:
            print("Usage: sieve ingest <alert.json>", file=sys.stderr)
            sys.exit(1)
        payload = json.loads(open(args[1]).read())
        from .api.ingest import enqueue
        from .db import init_db
        from .config import load_settings
        settings = load_settings()
        init_db(settings.db_path)
        enqueue(payload)
        print("Alert queued.")

    else:
        print(f"Unknown command: {cmd}\nUsage: sieve [serve|demo|ingest|version]")
        sys.exit(1)

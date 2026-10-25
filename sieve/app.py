"""FastAPI application factory.

Serves the API under /api, Prometheus metrics at /metrics, and the static SvelteKit build
(sieve/web/build) for every other path, with an SPA fallback to index.html. The Content-Security-
Policy allows only same-origin scripts plus the SHA-256 hashes of SvelteKit's inline bootstrap
scripts, computed from the build at startup (ADR-007).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__, runtime
from .config import Settings
from .db import init_db
from .errors import BAD_REQUEST, SieveError

log = logging.getLogger("sieve")
BUILD = Path(__file__).parent / "web" / "build"


def get_settings() -> Settings:   # kept for older imports
    return runtime.current()


def _script_hashes(html: str) -> list[str]:
    out = []
    for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S):
        out.append("'sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode() + "'")
    return out


def create_app(settings: Settings | None = None, start_worker: bool = True) -> FastAPI:
    if settings is not None:
        runtime.set_current(settings)
    s = runtime.current()
    init_db(s.db_path)
    stop = asyncio.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from .pipeline import playbooks
        playbooks.load()
        task = None
        if start_worker:
            from .worker import run_worker
            task = asyncio.create_task(run_worker(stop))
        log.info("Sieve %s on %s:%d (shadow mode: %s)", __version__, s.bind_host, s.port, s.shadow_mode)
        yield
        stop.set()
        if task:
            await task

    app = FastAPI(title="Sieve", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")

    index_html = (BUILD / "index.html").read_text() if (BUILD / "index.html").exists() else None
    hashes = " ".join(_script_hashes(index_html)) if index_html else ""
    csp = (f"default-src 'self'; script-src 'self' {hashes}; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
           "form-action 'self'; frame-ancestors 'none'")

    @app.exception_handler(SieveError)
    async def _sieve_err(_: Request, e: SieveError):
        return JSONResponse(e.to_dict(), status_code=e.status)

    @app.exception_handler(HTTPException)
    async def _http_err(_: Request, e: HTTPException):
        body = e.detail if isinstance(e.detail, dict) else {"code": f"SIEVE-HTTP-{e.status_code}",
                                                             "message": str(e.detail), "fix": ""}
        return JSONResponse(body, status_code=e.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError):
        first = e.errors()[0] if e.errors() else {"loc": [], "msg": "invalid"}
        where = ".".join(str(x) for x in first.get("loc", []) if x != "body")
        err = SieveError(BAD_REQUEST, f"{where or 'request'}: {first.get('msg')}", status=422)
        return JSONResponse(err.to_dict(), status_code=422)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Content-Security-Policy", csp)
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    from .api import admin, auth_routes, data, health, incidents, ingest, metrics, nis2
    for r in (ingest.router, auth_routes.router, incidents.router, nis2.router, admin.router, data.router,
              health.router, metrics.router):
        app.include_router(r)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
    def api_404(rest: str):
        raise SieveError("SIEVE-API-404", f"No API route /api/{rest[:80]}.", status=404)

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if index_html is None:
            return HTMLResponse("<h1>Sieve</h1><p>The web app is not built. Run <code>make web</code>.</p>"
                                "<p>The API is available at /api/docs.</p>", status_code=503)
        target = (BUILD / path).resolve()
        if path and target.is_file() and BUILD.resolve() in target.parents:
            headers = {"Cache-Control": "public, max-age=31536000, immutable"} if "/immutable/" in f"/{path}" else {}
            return FileResponse(target, headers=headers)
        return HTMLResponse(index_html, headers={"Cache-Control": "no-cache"})

    return app

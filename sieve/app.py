"""FastAPI application factory."""
from __future__ import annotations
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .config import Settings, load_settings
from .db import init_db

log = logging.getLogger("sieve")
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db(settings.db_path)
    from .worker import run_worker
    task = asyncio.create_task(run_worker(settings))
    log.info("Sieve %s starting on %s:%d", __import__('sieve').__version__,
             settings.bind_host, settings.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sieve",
        description="Free, local-first, injection-hardened triage layer for Wazuh alerts.",
        version=__import__('sieve').__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
        allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
    )
    from .api.ingest import router as ingest_router
    from .api.incidents import router as inc_router
    from .api.auth_routes import router as auth_router
    from .api.health import router as health_router
    from .api.metrics import router as metrics_router
    for r in (ingest_router, inc_router, auth_router, health_router, metrics_router):
        app.include_router(r)

    static = Path(__file__).parent / "web" / "static"
    if static.exists():
        app.mount("/", StaticFiles(directory=str(static), html=True), name="static")
    return app

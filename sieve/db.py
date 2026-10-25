"""SQLite storage (WAL mode). One engine per process.

Schema changes are additive in the 0.x series: ``init_db`` creates new tables and adds any new
nullable columns to existing tables (ADR-005). The audit table is protected by triggers that reject
UPDATE and DELETE, so the audit log stays append-only even against a buggy code path.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

log = logging.getLogger("sieve.db")


class Base(DeclarativeBase):
    pass


_engine = None
SessionLocal = sessionmaker(expire_on_commit=False)

_AUDIT_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
)


def engine():
    return _engine


def _add_missing_columns(eng) -> None:
    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                coltype = col.type.compile(dialect=eng.dialect)
                default = ""
                if col.default is not None and getattr(col.default, "is_scalar", False):
                    v = col.default.arg
                    default = f" DEFAULT {int(v) if isinstance(v, bool) else repr(v)}"
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}{default}'))
                log.info("migrated: added column %s.%s", table.name, col.name)


def init_db(db_path: Path | str) -> None:
    global _engine
    memory = str(db_path) == ":memory:"
    url = "sqlite://" if memory else f"sqlite:///{db_path}"
    if not memory:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict = {"connect_args": {"check_same_thread": False}}
    if memory:
        from sqlalchemy.pool import StaticPool
        kwargs["poolclass"] = StaticPool
    _engine = create_engine(url, **kwargs)

    @event.listens_for(_engine, "connect")
    def _pragma(dbapi_conn, _):  # pragma: no cover - driver hook
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(_engine)
    _add_missing_columns(_engine)
    with _engine.begin() as conn:
        for ddl in _AUDIT_TRIGGERS:
            conn.execute(text(ddl))
    SessionLocal.configure(bind=_engine)

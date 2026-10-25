"""SQLite storage (WAL mode). One engine per process."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


_engine = None
SessionLocal = sessionmaker(expire_on_commit=False)


def init_db(db_path: Path | str) -> None:
    global _engine
    url = "sqlite://" if str(db_path) == ":memory:" else f"sqlite:///{db_path}"
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(_engine, "connect")
    def _pragma(dbapi_conn, _):  # pragma: no cover - driver hook
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(_engine)
    SessionLocal.configure(bind=_engine)

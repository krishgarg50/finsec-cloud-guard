"""SQLite persistence for P3.

Deliberately plain ``sqlite3`` rather than an ORM: the schema is one table plus
a scan index, the queries are hand-written anyway (the filters are dynamic), and
a demo that needs no migrations and no database server is worth more here than
an abstraction layer.

Storage model
-------------
The full enriched finding is stored as a JSON document (the source of truth,
exactly as P2 produced it) *plus* denormalised columns for everything the UI
filters, sorts or aggregates on. That gives one writer, no marshalling bugs, and
a schema that automatically tolerates P2 adding fields -- while keeping the list
view off a full-table JSON scan.

The denormalised columns are derived, never authored. If they ever disagree with
the document, the document wins; ``repository.py`` reads the document back out
verbatim rather than reassembling it from columns.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "findings.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    resource_type    TEXT NOT NULL,
    resource_id      TEXT NOT NULL,
    resource_name    TEXT NOT NULL,
    resource_region  TEXT NOT NULL,
    detection_source TEXT NOT NULL,
    severity_raw     TEXT NOT NULL,
    risk_score       INTEGER NOT NULL,
    risk_band        TEXT NOT NULL,
    status           TEXT NOT NULL,
    -- canonical-order comma list, e.g. 'PCI-DSS,SOC2'. Lets the compliance
    -- view filter without parsing JSON for every row.
    frameworks       TEXT NOT NULL DEFAULT '',
    detected_at      TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    -- when P3 first stored this finding; the x-axis of the trend view
    first_seen_at    TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    reopen_count     INTEGER NOT NULL DEFAULT 0,
    document         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_score        ON findings (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_band         ON findings (risk_band);
CREATE INDEX IF NOT EXISTS idx_findings_status       ON findings (status);
CREATE INDEX IF NOT EXISTS idx_findings_scan         ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_resource     ON findings (resource_type);
CREATE INDEX IF NOT EXISTS idx_findings_first_seen   ON findings (first_seen_at);

CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    ingested_at    TEXT NOT NULL,
    finding_count  INTEGER NOT NULL,
    new_count      INTEGER NOT NULL,
    updated_count  INTEGER NOT NULL,
    reopened_count INTEGER NOT NULL DEFAULT 0,
    skipped_count  INTEGER NOT NULL DEFAULT 0,
    avg_score      REAL NOT NULL DEFAULT 0
);
"""


def connect(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection with the settings this app relies on."""
    path = Path(db_path)
    if path.parent and str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(path), check_same_thread=False)
    connection.row_factory = sqlite3.Row
    # WAL keeps the dashboard readable while a scan is being ingested.
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


@contextmanager
def session(db_path: Path | str = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    """Per-request connection helper.

    One connection per request rather than a shared global: sqlite3 connections
    are not thread-safe, and FastAPI runs sync endpoints in a threadpool.
    """
    connection = connect(db_path)
    try:
        init_db(connection)
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

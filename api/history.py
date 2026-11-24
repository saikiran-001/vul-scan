"""
history.py -- the SQLite database (Week 4 deliverable: scan history).

WHY SQLITE?
-----------
The project needs users, login sessions and a list of past scans. That is a
textbook relational problem, and SQLite is a real SQL database that lives in
one file -- no server to install. For a portfolio project it is the perfect
default; swapping in PostgreSQL later only means changing connect().

Every function opens a short-lived connection. That is slightly slower than a
connection pool but it is completely thread-safe, which matters because our
worker runs in a background thread.
"""

import json                          # the full result is stored as JSON text
import sqlite3                       # the database driver (standard library)
from contextlib import contextmanager   # lets us write our own "with db()" helper
from datetime import datetime, timezone

from .settings import DB_PATH

# The schema. "IF NOT EXISTS" makes init_db() safe to call on every startup.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url         TEXT    NOT NULL,
    final_url   TEXT,
    score       INTEGER NOT NULL,
    grade       TEXT    NOT NULL,
    result_json TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);
"""


def connect() -> sqlite3.Connection:
    """Open a connection configured the way we want it."""

    conn = sqlite3.connect(DB_PATH, timeout=15)      # wait up to 15s if another thread is writing
    conn.row_factory = sqlite3.Row                   # rows behave like dicts: row["email"]
    conn.execute("PRAGMA foreign_keys = ON")         # enforce the REFERENCES above
    return conn


@contextmanager
def db():
    """Context manager that ALWAYS closes the connection.

    `with sqlite3.connect(...)` only commits; it does not close the file.
    On Windows an unclosed connection keeps a lock on the .db file, so we
    wrap commit + close ourselves.
    """

    conn = connect()          # open
    try:
        yield conn            # hand it to the caller
        conn.commit()         # save the transaction
    finally:
        conn.close()          # release the file handle, even if an exception happened


def init_db() -> None:
    """Create the tables if this is the first run."""

    with db() as conn:                               # commit + close are handled for us
        conn.executescript(SCHEMA)                   # run every statement in SCHEMA


def save_scan(user_id: int, payload: dict) -> None:
    """Store one finished scan for a logged-in user."""

    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (id, user_id, url, final_url, score, grade, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["id"],
                user_id,
                payload["url"],
                payload.get("final_url", ""),
                int(payload["score"]),
                payload["grade"],
                json.dumps(payload),                                   # the whole report
                payload.get("started_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )


def list_scans(user_id: int, limit: int = 50) -> list:
    """Return the user's recent scans, newest first, without the heavy JSON."""

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, url, final_url, score, grade, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]               # sqlite3.Row -> plain dict for JSON


def get_scan(scan_id: str, user_id: int):
    """Load one full scan, but only if it belongs to this user."""

    with db() as conn:
        row = conn.execute(
            "SELECT result_json FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, user_id),
        ).fetchone()
    return json.loads(row["result_json"]) if row else None   # None = not found / not yours

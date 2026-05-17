"""SQLite persistence layer for the honeypot.

The database stores everything the honeypot observes: sessions, authentication
attempts, fake-shell commands and HTTP requests. WAL journalling is enabled so
the live engine can write while the read-only API serves the dashboard.

Nothing in this module ever interprets attacker input — values are bound as
SQL parameters only, never interpolated into statements.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# --- Schema -----------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol      TEXT    NOT NULL,
    src_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL,
    started_at    TEXT    NOT NULL,
    ended_at      TEXT,
    client_banner TEXT,
    country       TEXT,
    country_code  TEXT,
    latitude      REAL,
    longitude     REAL
);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts         TEXT    NOT NULL,
    username   TEXT    NOT NULL,
    password   TEXT    NOT NULL,
    success    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts         TEXT    NOT NULL,
    command    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS http_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id),
    ts              TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    user_agent      TEXT,
    headers_json    TEXT,
    body            TEXT,
    posted_username TEXT,
    posted_password TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_src_ip     ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_auth_username       ON auth_attempts(username);
CREATE INDEX IF NOT EXISTS idx_auth_password       ON auth_attempts(password);
CREATE INDEX IF NOT EXISTS idx_commands_command    ON commands(command);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a read/write connection with WAL journalling enabled.

    The parent directory is created if needed. ``check_same_thread=False`` is
    set because the SSH honeypot legitimately touches one connection from both
    the paramiko transport thread (auth callbacks) and the connection-handler
    thread (the fake shell); :mod:`honeypot.events` serialises every write
    behind a lock so this remains safe. WAL journalling additionally lets the
    read-only API query the database while the engine writes.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def connect_ro(db_path: str | Path) -> sqlite3.Connection:
    """Open a strictly read-only connection.

    Used by the API so a misbehaving or compromised dashboard process can never
    write to the capture database. Opening fails if the file does not exist.
    """
    uri = f"file:{Path(db_path).resolve()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path) -> None:
    """Create the schema (tables + indexes) if it does not already exist."""
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()

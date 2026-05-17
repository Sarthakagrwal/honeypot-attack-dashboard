"""Tests for the SQLite persistence layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from honeypot import events
from honeypot.db import connect, connect_ro, init_db


def test_init_db_creates_all_tables(temp_db: Path) -> None:
    """init_db must create every expected table."""
    conn = connect(temp_db)
    try:
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()
    assert {"sessions", "auth_attempts", "commands", "http_requests"} <= names


def test_init_db_creates_indexes(temp_db: Path) -> None:
    """The required indexes must exist after init."""
    conn = connect(temp_db)
    try:
        indexes = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
    finally:
        conn.close()
    for expected in (
        "idx_sessions_src_ip",
        "idx_sessions_started_at",
        "idx_auth_username",
        "idx_auth_password",
        "idx_commands_command",
    ):
        assert expected in indexes


def test_wal_journal_mode_enabled(temp_db: Path) -> None:
    """connect() must put the database into WAL journalling mode."""
    conn = connect(temp_db)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"


def test_init_db_is_idempotent(temp_db: Path) -> None:
    """Calling init_db twice must not raise or duplicate schema."""
    init_db(temp_db)  # second call (fixture already ran one)
    conn = connect(temp_db)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sessions'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_session_round_trip(temp_db: Path) -> None:
    """A session written via events can be read back with all fields intact."""
    conn = connect(temp_db)
    try:
        geo = {
            "country": "Germany",
            "country_code": "DE",
            "latitude": 51.17,
            "longitude": 10.45,
        }
        sid = events.start_session(
            conn, protocol="ssh", src_ip="88.198.1.2", src_port=51000, geo=geo
        )
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
        assert row["protocol"] == "ssh"
        assert row["src_ip"] == "88.198.1.2"
        assert row["country"] == "Germany"
        assert row["country_code"] == "DE"
        assert row["latitude"] == pytest.approx(51.17)
        assert row["ended_at"] is None

        events.end_session(conn, session_id=sid)
        row = conn.execute("SELECT ended_at FROM sessions WHERE id = ?", (sid,)).fetchone()
        assert row["ended_at"] is not None
    finally:
        conn.close()


def test_auth_attempt_round_trip(temp_db: Path) -> None:
    """Auth attempts persist and always store success=0."""
    conn = connect(temp_db)
    try:
        sid = events.start_session(
            conn, protocol="ssh", src_ip="1.2.3.4", src_port=2222
        )
        events.log_auth_attempt(
            conn, session_id=sid, username="root", password="123456", success=True
        )
        row = conn.execute(
            "SELECT username, password, success FROM auth_attempts WHERE session_id = ?",
            (sid,),
        ).fetchone()
        assert row["username"] == "root"
        assert row["password"] == "123456"
        # A honeypot never grants real auth: success is forced to 0.
        assert row["success"] == 0
    finally:
        conn.close()


def test_http_request_round_trip(temp_db: Path) -> None:
    """HTTP requests persist headers as JSON and posted credentials."""
    conn = connect(temp_db)
    try:
        sid = events.start_session(
            conn, protocol="http", src_ip="9.9.9.9", src_port=44000
        )
        events.log_http_request(
            conn,
            session_id=sid,
            method="POST",
            path="/wp-login.php",
            user_agent="curl/8.0",
            headers={"Host": "x", "User-Agent": "curl/8.0"},
            body="username=admin&password=admin",
            posted_username="admin",
            posted_password="admin",
        )
        row = conn.execute(
            "SELECT * FROM http_requests WHERE session_id = ?", (sid,)
        ).fetchone()
        assert row["method"] == "POST"
        assert row["path"] == "/wp-login.php"
        assert row["posted_username"] == "admin"
        assert '"Host": "x"' in row["headers_json"]
    finally:
        conn.close()


def test_connect_ro_is_read_only(temp_db: Path) -> None:
    """A read-only connection must reject writes."""
    ro = connect_ro(temp_db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            ro.execute(
                "INSERT INTO sessions (protocol, src_ip, src_port, started_at) "
                "VALUES ('ssh', '1.1.1.1', 22, '2024-01-01T00:00:00Z')"
            )
    finally:
        ro.close()


def test_connect_ro_missing_file_raises(tmp_path: Path) -> None:
    """Opening a non-existent DB read-only must raise (not create the file)."""
    missing = tmp_path / "does-not-exist.db"
    with pytest.raises(sqlite3.OperationalError):
        connect_ro(missing)
    assert not missing.exists()

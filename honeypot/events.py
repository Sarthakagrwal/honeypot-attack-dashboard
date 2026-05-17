"""The single event funnel every protocol writes through.

SSH, HTTP and the seed generator all record observations via these functions,
so live capture and synthetic history share one code path and one schema. No
function here ever executes or evaluates input — values are persisted verbatim
as bound SQL parameters.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime

# The SSH honeypot writes to one connection from two threads (the paramiko
# transport thread runs the auth callbacks; the handler thread runs the fake
# shell). Every write here is serialised behind this process-wide lock so that
# shared use is safe even though the connection is opened with
# ``check_same_thread=False``. Writes are tiny and infrequent, so a single
# global lock has no meaningful performance cost.
_WRITE_LOCK = threading.Lock()


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def start_session(
    conn: sqlite3.Connection,
    *,
    protocol: str,
    src_ip: str,
    src_port: int,
    client_banner: str | None = None,
    geo: dict | None = None,
    started_at: str | None = None,
) -> int:
    """Record the start of an attacker session and return its row id.

    ``geo`` is the optional dict returned by :func:`honeypot.geoip.lookup`;
    missing geolocation simply leaves those columns ``NULL``.
    """
    geo = geo or {}
    with _WRITE_LOCK:
        cur = conn.execute(
            """
            INSERT INTO sessions
                (protocol, src_ip, src_port, started_at, client_banner,
                 country, country_code, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                protocol,
                src_ip,
                src_port,
                started_at or _utc_now(),
                client_banner,
                geo.get("country"),
                geo.get("country_code"),
                geo.get("latitude"),
                geo.get("longitude"),
            ),
        )
        session_id = cur.lastrowid
        conn.commit()
    assert session_id is not None  # AUTOINCREMENT always yields an id
    return session_id


def log_auth_attempt(
    conn: sqlite3.Connection,
    *,
    session_id: int,
    username: str,
    password: str,
    success: bool = False,
    ts: str | None = None,
) -> None:
    """Record one username/password login attempt.

    ``success`` is accepted for interface symmetry with a generic auth funnel,
    but a honeypot never grants *real* authentication — the column is therefore
    always persisted as ``0`` regardless of the argument. (The SSH honeypot
    "accepts" a login only to unlock the *simulated* shell; that is not a real
    authentication success and is not recorded as one here.)
    """
    _ = success  # Intentionally ignored — see docstring.
    with _WRITE_LOCK:
        conn.execute(
            """
            INSERT INTO auth_attempts (session_id, ts, username, password, success)
            VALUES (?, ?, ?, ?, 0)
            """,
            (session_id, ts or _utc_now(), username, password),
        )
        conn.commit()


def log_command(
    conn: sqlite3.Connection,
    *,
    session_id: int,
    command: str,
    ts: str | None = None,
) -> None:
    """Record a command typed into the fake shell (the string is never run)."""
    with _WRITE_LOCK:
        conn.execute(
            "INSERT INTO commands (session_id, ts, command) VALUES (?, ?, ?)",
            (session_id, ts or _utc_now(), command),
        )
        conn.commit()


def log_http_request(
    conn: sqlite3.Connection,
    *,
    session_id: int,
    method: str,
    path: str,
    user_agent: str | None = None,
    headers: dict | None = None,
    body: str | None = None,
    posted_username: str | None = None,
    posted_password: str | None = None,
    ts: str | None = None,
) -> None:
    """Record one HTTP request observed by the fake web server."""
    with _WRITE_LOCK:
        conn.execute(
            """
            INSERT INTO http_requests
                (session_id, ts, method, path, user_agent, headers_json, body,
                 posted_username, posted_password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                ts or _utc_now(),
                method,
                path,
                user_agent,
                json.dumps(headers or {}),
                body,
                posted_username,
                posted_password,
            ),
        )
        conn.commit()


def set_client_banner(
    conn: sqlite3.Connection,
    *,
    session_id: int,
    client_banner: str,
) -> None:
    """Record the client's protocol banner once a handshake has completed."""
    with _WRITE_LOCK:
        conn.execute(
            "UPDATE sessions SET client_banner = ? WHERE id = ?",
            (client_banner, session_id),
        )
        conn.commit()


def end_session(
    conn: sqlite3.Connection,
    *,
    session_id: int,
    ended_at: str | None = None,
) -> None:
    """Mark a session as finished by stamping ``ended_at``."""
    with _WRITE_LOCK:
        conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ?",
            (ended_at or _utc_now(), session_id),
        )
        conn.commit()

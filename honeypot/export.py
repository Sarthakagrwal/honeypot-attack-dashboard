"""The dashboard data builder — the single source of the export shape.

Both the read-only API (``/api/export``) and the seed script
(``scripts/generate_seed.py``, which writes ``web/public/demo-data.json``)
call :func:`build_export`, so the live API and the bundled demo can never
diverge in structure.

Every function here issues read-only ``SELECT`` queries; nothing is executed
or interpolated — attacker-controlled strings are returned only as JSON data.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .db import connect_ro

# How many rows each "top N" / "recent" list returns.
_TOP_N = 12
_RECENT_N = 25


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Run a SELECT and return all rows."""
    return list(conn.execute(sql, params).fetchall())


def _stats(conn: sqlite3.Connection) -> dict[str, int]:
    """Compute the headline counters shown on the dashboard stat cards."""
    total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM sessions").fetchone()[0]
    auth_attempts = conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0]
    commands = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    http_requests = conn.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]
    ssh_sessions = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE protocol = 'ssh'"
    ).fetchone()[0]
    http_sessions = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE protocol = 'http'"
    ).fetchone()[0]
    return {
        "total_sessions": total_sessions,
        "unique_ips": unique_ips,
        "auth_attempts": auth_attempts,
        "commands": commands,
        "http_requests": http_requests,
        "ssh_sessions": ssh_sessions,
        "http_sessions": http_sessions,
    }


def _timeline(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Daily SSH vs HTTP session counts, ascending by date."""
    rows = _rows(
        conn,
        """
        SELECT substr(started_at, 1, 10) AS date,
               SUM(CASE WHEN protocol = 'ssh'  THEN 1 ELSE 0 END) AS ssh,
               SUM(CASE WHEN protocol = 'http' THEN 1 ELSE 0 END) AS http
        FROM sessions
        GROUP BY date
        ORDER BY date
        """,
    )
    return [{"date": r["date"], "ssh": r["ssh"], "http": r["http"]} for r in rows]


def _top_ips(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """The busiest source IPs with their country and activity counts."""
    rows = _rows(
        conn,
        """
        SELECT s.src_ip                              AS ip,
               MAX(s.country)                        AS country,
               MAX(s.country_code)                   AS country_code,
               COUNT(DISTINCT s.id)                  AS sessions,
               COUNT(a.id)                           AS attempts
        FROM sessions s
        LEFT JOIN auth_attempts a ON a.session_id = s.id
        GROUP BY s.src_ip
        ORDER BY sessions DESC, attempts DESC
        LIMIT ?
        """,
        (_TOP_N,),
    )
    return [
        {
            "ip": r["ip"],
            "country": r["country"],
            "country_code": r["country_code"],
            "attempts": r["attempts"],
            "sessions": r["sessions"],
        }
        for r in rows
    ]


def _value_counts(conn: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    """Run a ``(value, count)`` query and shape it for the bar charts."""
    return [{"value": r["value"], "count": r["count"]} for r in _rows(conn, sql)]


def _map_points(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Aggregate sessions by lat/lon for the Leaflet attack-origin map."""
    rows = _rows(
        conn,
        """
        SELECT latitude  AS lat,
               longitude AS lon,
               MAX(country) AS country,
               COUNT(*)  AS count
        FROM sessions
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        GROUP BY latitude, longitude
        ORDER BY count DESC
        """,
    )
    return [
        {"lat": r["lat"], "lon": r["lon"], "country": r["country"], "count": r["count"]}
        for r in rows
    ]


def _recent_sessions(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """The most recent sessions, each with its auth count and command list."""
    rows = _rows(
        conn,
        """
        SELECT s.id, s.protocol, s.src_ip, s.country, s.started_at,
               (SELECT COUNT(*) FROM auth_attempts a WHERE a.session_id = s.id)
                   AS auth_attempts
        FROM sessions s
        ORDER BY s.started_at DESC
        LIMIT ?
        """,
        (_RECENT_N,),
    )
    sessions: list[dict[str, Any]] = []
    for r in rows:
        cmd_rows = _rows(
            conn,
            "SELECT command FROM commands WHERE session_id = ? ORDER BY ts",
            (r["id"],),
        )
        sessions.append(
            {
                "id": r["id"],
                "protocol": r["protocol"],
                "src_ip": r["src_ip"],
                "country": r["country"],
                "started_at": r["started_at"],
                "auth_attempts": r["auth_attempts"],
                "commands": [c["command"] for c in cmd_rows],
            }
        )
    return sessions


def build_export(conn: sqlite3.Connection) -> dict[str, Any]:
    """Assemble the complete dashboard dataset from an open DB connection.

    The returned dict matches the exact contract documented in the project
    brief and consumed by ``web/src/api.ts``. The connection may be read-only.
    """
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "stats": _stats(conn),
        "timeline": _timeline(conn),
        "top_ips": _top_ips(conn),
        "top_usernames": _value_counts(
            conn,
            f"""
            SELECT username AS value, COUNT(*) AS count
            FROM auth_attempts GROUP BY username
            ORDER BY count DESC LIMIT {_TOP_N}
            """,
        ),
        "top_passwords": _value_counts(
            conn,
            f"""
            SELECT password AS value, COUNT(*) AS count
            FROM auth_attempts GROUP BY password
            ORDER BY count DESC LIMIT {_TOP_N}
            """,
        ),
        "top_commands": _value_counts(
            conn,
            f"""
            SELECT command AS value, COUNT(*) AS count
            FROM commands GROUP BY command
            ORDER BY count DESC LIMIT {_TOP_N}
            """,
        ),
        "http_paths": _value_counts(
            conn,
            f"""
            SELECT path AS value, COUNT(*) AS count
            FROM http_requests GROUP BY path
            ORDER BY count DESC LIMIT {_TOP_N}
            """,
        ),
        "map_points": _map_points(conn),
        "recent_sessions": _recent_sessions(conn),
    }


def build_export_from_path(db_path: str | Path) -> dict[str, Any]:
    """Open the DB at ``db_path`` read-only and build the export dict."""
    conn = connect_ro(db_path)
    try:
        return build_export(conn)
    finally:
        conn.close()

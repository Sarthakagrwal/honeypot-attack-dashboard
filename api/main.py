"""Read-only dashboard API for the honeypot.

A FastAPI app that exposes captured attack data over **GET-only** routes — it
opens the SQLite capture database strictly read-only, so the API can never
modify what the honeypot has recorded. There are deliberately no POST/PUT/
DELETE/PATCH routes; ``tests/test_api.py`` asserts this.

The database path is taken from the ``HONEYPOT_DB`` environment variable, or
falls back to the default location in :data:`honeypot.config.DEFAULT`.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from honeypot.config import DEFAULT
from honeypot.db import connect_ro
from honeypot.export import build_export

app = FastAPI(
    title="Honeypot Attack Dashboard API",
    description="Read-only access to captured honeypot attack data.",
    version="0.1.0",
)

# The dashboard is a static site served from a different origin (GitHub
# Pages), so permissive CORS is required. Only GET is ever used.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _db_path() -> Path:
    """Resolve the capture DB path from the environment or the default."""
    return Path(os.environ.get("HONEYPOT_DB", str(DEFAULT.db_path)))


def _open() -> sqlite3.Connection:
    """Open the capture DB read-only, returning HTTP 503 if it is missing."""
    path = _db_path()
    if not path.is_file():
        raise HTTPException(
            status_code=503,
            detail="Capture database not found. Run 'honeypot seed' first.",
        )
    return connect_ro(path)


def _export() -> dict[str, Any]:
    """Build the full export dict from the read-only DB."""
    conn = _open()
    try:
        return build_export(conn)
    finally:
        conn.close()


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness probe: reports whether the capture database is reachable."""
    path = _db_path()
    return {"status": "ok", "database": path.name, "database_present": path.is_file()}


@app.get("/api/stats")
def stats() -> dict[str, int]:
    """Headline counters for the dashboard stat cards."""
    return _export()["stats"]


@app.get("/api/timeline")
def timeline() -> list[dict[str, Any]]:
    """Daily SSH vs HTTP session counts for the timeline chart."""
    return _export()["timeline"]


@app.get("/api/top-ips")
def top_ips() -> list[dict[str, Any]]:
    """The busiest attacking source IPs."""
    return _export()["top_ips"]


@app.get("/api/credentials")
def credentials() -> dict[str, list[dict[str, Any]]]:
    """The most-tried usernames and passwords."""
    data = _export()
    return {
        "top_usernames": data["top_usernames"],
        "top_passwords": data["top_passwords"],
    }


@app.get("/api/commands")
def commands() -> list[dict[str, Any]]:
    """The most-run post-compromise commands."""
    return _export()["top_commands"]


@app.get("/api/map")
def attack_map() -> list[dict[str, Any]]:
    """Geolocated attack-origin points for the world map."""
    return _export()["map_points"]


@app.get("/api/sessions")
def sessions() -> list[dict[str, Any]]:
    """The most recent attacker sessions with their commands."""
    return _export()["recent_sessions"]


@app.get("/api/export")
def export() -> dict[str, Any]:
    """The entire dashboard dataset as one JSON object.

    This is the canonical payload consumed by ``web/src/api.ts`` and mirrored
    into the committed ``demo-data.json`` snapshot.
    """
    return _export()

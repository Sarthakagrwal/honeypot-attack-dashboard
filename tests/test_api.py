"""Tests for the read-only dashboard API.

Runs the FastAPI app against a seeded temporary database via ``TestClient`` and
asserts both the response shape of every route and the security invariant that
NO non-GET routes exist.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from honeypot.seed import seed_database


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    """Yield a TestClient bound to a freshly seeded temporary database."""
    db = tmp_path / "honeypot.db"
    seed_database(db)
    os.environ["HONEYPOT_DB"] = str(db)

    # Import (or reload) the app so it picks up the env var.
    import api.main as api_main

    importlib.reload(api_main)
    with TestClient(api_main.app) as test_client:
        yield test_client
    os.environ.pop("HONEYPOT_DB", None)


def test_healthz(client: TestClient) -> None:
    """The liveness probe reports the database is present."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database_present"] is True


def test_stats_route(client: TestClient) -> None:
    """/api/stats returns all the documented integer counters."""
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert set(stats) == {
        "total_sessions",
        "unique_ips",
        "auth_attempts",
        "commands",
        "http_requests",
        "ssh_sessions",
        "http_sessions",
    }
    assert stats["total_sessions"] > 0
    assert stats["unique_ips"] > 0


def test_timeline_route(client: TestClient) -> None:
    """/api/timeline returns dated SSH/HTTP counts."""
    resp = client.get("/api/timeline")
    assert resp.status_code == 200
    timeline = resp.json()
    assert isinstance(timeline, list) and timeline
    for item in timeline:
        assert set(item) == {"date", "ssh", "http"}


def test_top_ips_route(client: TestClient) -> None:
    """/api/top-ips returns shaped attacker IP rows."""
    resp = client.get("/api/top-ips")
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    for item in rows:
        assert set(item) == {"ip", "country", "country_code", "attempts", "sessions"}


def test_credentials_route(client: TestClient) -> None:
    """/api/credentials returns the top usernames and passwords."""
    resp = client.get("/api/credentials")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"top_usernames", "top_passwords"}
    for item in body["top_usernames"]:
        assert set(item) == {"value", "count"}


def test_commands_route(client: TestClient) -> None:
    """/api/commands returns the top post-compromise commands."""
    resp = client.get("/api/commands")
    assert resp.status_code == 200
    for item in resp.json():
        assert set(item) == {"value", "count"}


def test_map_route(client: TestClient) -> None:
    """/api/map returns geolocated attack points."""
    resp = client.get("/api/map")
    assert resp.status_code == 200
    for item in resp.json():
        assert set(item) == {"lat", "lon", "country", "count"}


def test_sessions_route(client: TestClient) -> None:
    """/api/sessions returns recent sessions with command lists."""
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    for item in rows:
        assert set(item) == {
            "id",
            "protocol",
            "src_ip",
            "country",
            "started_at",
            "auth_attempts",
            "commands",
        }


def test_export_route_full_shape(client: TestClient) -> None:
    """/api/export returns the entire dataset in the documented shape."""
    resp = client.get("/api/export")
    assert resp.status_code == 200
    data = resp.json()
    assert set(data) == {
        "generated_at",
        "stats",
        "timeline",
        "top_ips",
        "top_usernames",
        "top_passwords",
        "top_commands",
        "http_paths",
        "map_points",
        "recent_sessions",
    }


def test_no_non_get_routes_exist(client: TestClient) -> None:
    """SECURITY INVARIANT: the API exposes GET (and HEAD) routes only.

    A read-only dashboard API must never accept a mutating verb. This walks
    every registered route and fails if any POST/PUT/DELETE/PATCH is found.
    """
    import api.main as api_main

    mutating = {"POST", "PUT", "DELETE", "PATCH"}
    for route in api_main.app.routes:
        methods = getattr(route, "methods", set()) or set()
        offending = methods & mutating
        assert not offending, f"route {route.path} exposes {offending}"


def test_post_to_route_is_rejected(client: TestClient) -> None:
    """A POST to a GET route is rejected with 405 Method Not Allowed."""
    resp = client.post("/api/stats")
    assert resp.status_code == 405


def test_missing_database_returns_503(tmp_path: Path) -> None:
    """When the capture DB is absent the API degrades to HTTP 503."""
    os.environ["HONEYPOT_DB"] = str(tmp_path / "nonexistent.db")
    import api.main as api_main

    importlib.reload(api_main)
    try:
        with TestClient(api_main.app) as test_client:
            resp = test_client.get("/api/stats")
            assert resp.status_code == 503
    finally:
        os.environ.pop("HONEYPOT_DB", None)

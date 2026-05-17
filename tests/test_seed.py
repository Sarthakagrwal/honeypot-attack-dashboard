"""Tests for the deterministic seed generator and the export shape."""

from __future__ import annotations

from pathlib import Path

from honeypot.db import connect
from honeypot.export import build_export, build_export_from_path
from honeypot.seed import TOTAL_SESSIONS, seed_database

# The exact keys the dashboard contract requires at the top level.
_EXPORT_KEYS = {
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

_STATS_KEYS = {
    "total_sessions",
    "unique_ips",
    "auth_attempts",
    "commands",
    "http_requests",
    "ssh_sessions",
    "http_sessions",
}


def test_seed_writes_expected_session_count(tmp_path: Path) -> None:
    """The seeder writes exactly TOTAL_SESSIONS sessions."""
    db = tmp_path / "seed.db"
    count = seed_database(db)
    assert count == TOTAL_SESSIONS
    conn = connect(db)
    try:
        rows = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    finally:
        conn.close()
    assert rows == TOTAL_SESSIONS


def test_seed_is_deterministic(tmp_path: Path) -> None:
    """Two seed runs produce byte-identical exports (fixed RNG seed)."""
    db1 = tmp_path / "a.db"
    db2 = tmp_path / "b.db"
    seed_database(db1)
    seed_database(db2)

    exp1 = build_export_from_path(db1)
    exp2 = build_export_from_path(db2)

    # generated_at is a wall-clock timestamp; everything else must match.
    exp1.pop("generated_at")
    exp2.pop("generated_at")
    assert exp1 == exp2


def test_seed_is_idempotent(tmp_path: Path) -> None:
    """Re-seeding the same path replaces, not appends."""
    db = tmp_path / "seed.db"
    seed_database(db)
    seed_database(db)
    conn = connect(db)
    try:
        rows = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    finally:
        conn.close()
    assert rows == TOTAL_SESSIONS


def test_seed_has_both_protocols(tmp_path: Path) -> None:
    """The seeded data contains both SSH and HTTP sessions."""
    db = tmp_path / "seed.db"
    seed_database(db)
    conn = connect(db)
    try:
        protocols = {
            r[0] for r in conn.execute("SELECT DISTINCT protocol FROM sessions")
        }
    finally:
        conn.close()
    assert protocols == {"ssh", "http"}


def test_seed_spans_roughly_30_days(tmp_path: Path) -> None:
    """The timeline covers a multi-week window of activity."""
    db = tmp_path / "seed.db"
    seed_database(db)
    export = build_export_from_path(db)
    # At least ~20 distinct days should appear given 220 sessions over 30 days.
    assert len(export["timeline"]) >= 20


def test_export_top_level_shape(tmp_path: Path) -> None:
    """build_export produces exactly the documented top-level keys."""
    db = tmp_path / "seed.db"
    seed_database(db)
    conn = connect(db)
    try:
        export = build_export(conn)
    finally:
        conn.close()
    assert set(export) == _EXPORT_KEYS


def test_export_stats_shape(tmp_path: Path) -> None:
    """The stats block has exactly the documented keys, all integers."""
    db = tmp_path / "seed.db"
    seed_database(db)
    export = build_export_from_path(db)
    assert set(export["stats"]) == _STATS_KEYS
    assert all(isinstance(v, int) for v in export["stats"].values())
    assert export["stats"]["total_sessions"] == TOTAL_SESSIONS


def test_export_list_item_shapes(tmp_path: Path) -> None:
    """Each list in the export has correctly-shaped items."""
    db = tmp_path / "seed.db"
    seed_database(db)
    export = build_export_from_path(db)

    assert export["timeline"], "timeline should not be empty"
    for item in export["timeline"]:
        assert set(item) == {"date", "ssh", "http"}

    for item in export["top_ips"]:
        assert set(item) == {"ip", "country", "country_code", "attempts", "sessions"}

    for key in ("top_usernames", "top_passwords", "top_commands", "http_paths"):
        for item in export[key]:
            assert set(item) == {"value", "count"}

    for item in export["map_points"]:
        assert set(item) == {"lat", "lon", "country", "count"}

    assert export["recent_sessions"], "recent_sessions should not be empty"
    for item in export["recent_sessions"]:
        assert set(item) == {
            "id",
            "protocol",
            "src_ip",
            "country",
            "started_at",
            "auth_attempts",
            "commands",
        }
        assert isinstance(item["commands"], list)


def test_export_credentials_from_known_lists(tmp_path: Path) -> None:
    """Top usernames/passwords are drawn from the real honeypot top-lists."""
    db = tmp_path / "seed.db"
    seed_database(db)
    export = build_export_from_path(db)
    usernames = {row["value"] for row in export["top_usernames"]}
    # 'root' and 'admin' dominate real brute-force traffic and the seed lists.
    assert usernames & {"root", "admin", "user", "test"}

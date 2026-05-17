"""Shared pytest fixtures for the honeypot test suite."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from honeypot.config import DEFAULT, Config
from honeypot.db import init_db


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Return the path to a freshly initialised, empty capture DB."""
    db = tmp_path / "honeypot.db"
    init_db(db)
    return db


@pytest.fixture
def temp_config(tmp_path: Path) -> Config:
    """A Config pointing all filesystem paths inside a temp directory."""
    return DEFAULT.with_overrides(
        db_path=tmp_path / "honeypot.db",
        host_key_path=tmp_path / "host_keys" / "ssh_host_rsa_key",
        geoip_db_path=tmp_path / "missing.mmdb",
        host="127.0.0.1",
        conn_timeout=5.0,
    )


def free_port() -> int:
    """Return an OS-assigned free TCP port (the socket is closed before use)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

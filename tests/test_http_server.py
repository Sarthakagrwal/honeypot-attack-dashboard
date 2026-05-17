"""Tests for the HTTP honeypot.

Starts the server on an ephemeral port, drives it with real ``requests`` calls,
and asserts every request is logged and POSTed credentials are parsed.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
import requests

from honeypot.config import Config
from honeypot.db import connect, init_db
from honeypot.http_server import HoneypotHTTPServer, _extract_credentials

from .conftest import free_port


@pytest.fixture
def running_http(temp_config: Config) -> tuple[str, Path]:
    """Start the HTTP honeypot on a free port; yield (base_url, db_path)."""
    port = free_port()
    config = temp_config.with_overrides(http_port=port)
    init_db(config.db_path)
    server = HoneypotHTTPServer(("127.0.0.1", port), config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}", config.db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_index_page_served(running_http: tuple[str, Path]) -> None:
    """GET / returns the spoofed Apache default page."""
    base, _ = running_http
    resp = requests.get(f"{base}/", timeout=5)
    assert resp.status_code == 200
    assert "Apache2 Ubuntu Default Page" in resp.text
    # The Server header impersonates Apache, not Python's http.server.
    assert resp.headers.get("Server", "").startswith("Apache/2.4.52")


def test_env_bait_page_served(running_http: tuple[str, Path]) -> None:
    """GET /.env serves a believable decoy environment file."""
    base, _ = running_http
    resp = requests.get(f"{base}/.env", timeout=5)
    assert resp.status_code == 200
    assert "DB_PASSWORD" in resp.text


def test_unknown_path_returns_404(running_http: tuple[str, Path]) -> None:
    """An unmapped path returns an Apache-style 404."""
    base, _ = running_http
    resp = requests.get(f"{base}/nothing-here", timeout=5)
    assert resp.status_code == 404
    assert "Not Found" in resp.text


def test_get_request_is_logged(running_http: tuple[str, Path]) -> None:
    """Every GET is recorded as an http_request row with its headers."""
    base, db = running_http
    requests.get(f"{base}/admin", timeout=5, headers={"User-Agent": "pytest-scanner"})
    time.sleep(0.2)
    conn = connect(db)
    try:
        row = conn.execute(
            "SELECT method, path, user_agent, headers_json FROM http_requests "
            "WHERE path = '/admin'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["method"] == "GET"
    assert row["user_agent"] == "pytest-scanner"
    assert "pytest-scanner" in row["headers_json"]


def test_post_credentials_are_parsed_and_stored(running_http: tuple[str, Path]) -> None:
    """A form-encoded POST login has its credentials parsed and persisted."""
    base, db = running_http
    resp = requests.post(
        f"{base}/wp-login.php",
        data={"username": "administrator", "password": "hunter2"},
        timeout=5,
    )
    # The honeypot always rejects — never an auth success.
    assert resp.status_code == 200
    assert "Invalid username or password" in resp.text

    time.sleep(0.2)
    conn = connect(db)
    try:
        row = conn.execute(
            "SELECT method, posted_username, posted_password FROM http_requests "
            "WHERE path = '/wp-login.php' AND method = 'POST'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["posted_username"] == "administrator"
    assert row["posted_password"] == "hunter2"


def test_post_json_credentials_are_parsed(running_http: tuple[str, Path]) -> None:
    """A JSON POST body is also parsed for credential-like fields."""
    base, db = running_http
    requests.post(
        f"{base}/login",
        json={"user": "root", "pass": "toor"},
        timeout=5,
    )
    time.sleep(0.2)
    conn = connect(db)
    try:
        row = conn.execute(
            "SELECT posted_username, posted_password FROM http_requests "
            "WHERE path = '/login' AND method = 'POST'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["posted_username"] == "root"
    assert row["posted_password"] == "toor"


def test_extract_credentials_form_and_json() -> None:
    """The credential parser handles both encodings and missing fields."""
    u, p = _extract_credentials(
        "application/x-www-form-urlencoded", b"username=alice&password=secret"
    )
    assert (u, p) == ("alice", "secret")

    u, p = _extract_credentials("application/json", b'{"email":"e@x.com","pwd":"123"}')
    assert (u, p) == ("e@x.com", "123")

    # No credential fields present -> both None, no exception.
    u, p = _extract_credentials("application/x-www-form-urlencoded", b"q=search")
    assert (u, p) == (None, None)

    # Malformed JSON degrades to no credentials rather than raising.
    u, p = _extract_credentials("application/json", b"{not json")
    assert (u, p) == (None, None)

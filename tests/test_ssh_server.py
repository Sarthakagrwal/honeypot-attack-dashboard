"""Tests for the SSH honeypot.

Covers both the :class:`HoneypotServer` ``ServerInterface`` in isolation and a
full end-to-end connection through a real paramiko transport on an ephemeral
port.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest

from honeypot import events
from honeypot.config import Config
from honeypot.db import connect, init_db
from honeypot.ssh_server import HoneypotServer, ensure_host_key, serve

from .conftest import free_port


def _new_session(db: Path, src_ip: str = "5.5.5.5") -> tuple[object, int]:
    """Init the DB and start one session row; return (connection, session_id)."""
    init_db(db)
    conn = connect(db)
    sid = events.start_session(conn, protocol="ssh", src_ip=src_ip, src_port=22)
    return conn, sid


def test_get_allowed_auths_is_password_only(temp_db: Path) -> None:
    """The server advertises only password authentication."""
    conn, sid = _new_session(temp_db)
    try:
        server = HoneypotServer(conn, sid, Config())
        assert server.get_allowed_auths("anyone") == "password"
    finally:
        conn.close()


def test_publickey_auth_is_always_refused(temp_db: Path) -> None:
    """Public-key auth is rejected so attackers fall back to passwords."""
    conn, sid = _new_session(temp_db)
    try:
        server = HoneypotServer(conn, sid, Config())
        key = paramiko.RSAKey.generate(2048)
        assert server.check_auth_publickey("root", key) == paramiko.AUTH_FAILED
    finally:
        conn.close()


def test_auth_fails_until_threshold_then_succeeds(temp_db: Path) -> None:
    """Password auth returns AUTH_FAILED until grant_session_after attempts."""
    conn, sid = _new_session(temp_db)
    config = Config(grant_session_after=3)
    try:
        server = HoneypotServer(conn, sid, config)
        assert server.check_auth_password("root", "123456") == paramiko.AUTH_FAILED
        assert server.check_auth_password("root", "password") == paramiko.AUTH_FAILED
        # Third attempt crosses the threshold.
        assert server.check_auth_password("root", "admin") == paramiko.AUTH_SUCCESSFUL
    finally:
        conn.close()


def test_every_auth_attempt_is_logged(temp_db: Path) -> None:
    """Each password attempt is recorded with success forced to 0."""
    conn, sid = _new_session(temp_db)
    try:
        server = HoneypotServer(conn, sid, Config(grant_session_after=10))
        for user, pw in [("root", "a"), ("admin", "b"), ("oracle", "c")]:
            server.check_auth_password(user, pw)
        rows = conn.execute(
            "SELECT username, password, success FROM auth_attempts WHERE session_id = ?",
            (sid,),
        ).fetchall()
        assert len(rows) == 3
        assert {r[0] for r in rows} == {"root", "admin", "oracle"}
        assert all(r[2] == 0 for r in rows)
    finally:
        conn.close()


def test_channel_request_allows_session_only(temp_db: Path) -> None:
    """Only 'session' channels are permitted."""
    conn, sid = _new_session(temp_db)
    try:
        server = HoneypotServer(conn, sid, Config())
        assert server.check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED
        assert (
            server.check_channel_request("direct-tcpip", 0)
            == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )
    finally:
        conn.close()


def test_ensure_host_key_generates_and_persists(tmp_path: Path) -> None:
    """The RSA host key is generated once and reused on subsequent calls."""
    key_path = tmp_path / "keys" / "ssh_host_rsa_key"
    assert not key_path.exists()
    key1 = ensure_host_key(key_path)
    assert key_path.is_file()
    assert key1.get_bits() == 2048
    # A second call must load the same key, not regenerate it.
    key2 = ensure_host_key(key_path)
    assert key1.get_base64() == key2.get_base64()


def test_end_to_end_ssh_connection(temp_config: Config) -> None:
    """A real paramiko client brute-forces the honeypot and reaches the shell."""
    port = free_port()
    config = temp_config.with_overrides(ssh_port=port, grant_session_after=3)
    init_db(config.db_path)

    ready = threading.Event()
    server_thread = threading.Thread(
        target=serve, args=(config,), kwargs={"ready": ready}, daemon=True
    )
    server_thread.start()
    assert ready.wait(timeout=5), "SSH honeypot did not start"

    transport = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)

        # The banner must look like a real OpenSSH server.
        assert "OpenSSH" in transport.remote_version

        # First two password attempts fail...
        for pw in ("123456", "password"):
            with pytest.raises(paramiko.AuthenticationException):
                transport.auth_password("root", pw)
        # ...the third is "accepted" (unlocks the simulated shell only).
        transport.auth_password("root", "admin")
        assert transport.is_authenticated()

        channel = transport.open_session(timeout=5)
        channel.get_pty()
        channel.invoke_shell()
        time.sleep(0.4)  # let the MOTD/prompt arrive

        channel.sendall(b"whoami\n")
        time.sleep(0.4)
        channel.sendall(b"exit\n")
        time.sleep(0.4)

        output = b""
        deadline = time.time() + 3
        while time.time() < deadline:
            if channel.recv_ready():
                output += channel.recv(4096)
            else:
                time.sleep(0.1)
            if channel.exit_status_ready():
                break
        assert b"Ubuntu" in output  # MOTD rendered
        channel.close()
    finally:
        if transport is not None:
            transport.close()

    # Give the server thread a moment to flush its final DB writes.
    time.sleep(0.5)
    conn = connect(config.db_path)
    try:
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        attempts = conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0]
        commands = conn.execute(
            "SELECT command FROM commands"
        ).fetchall()
    finally:
        conn.close()
    assert sessions >= 1
    assert attempts >= 3  # three password attempts were logged
    assert any("whoami" in c[0] for c in commands)

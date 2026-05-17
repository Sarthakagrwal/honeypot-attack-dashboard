"""The SSH honeypot.

Presents a convincing OpenSSH service on a non-privileged port. Every password
attempt is logged; authentication is refused until ``grant_session_after``
tries, after which a *simulated* shell (see :mod:`honeypot.fake_shell`) is
granted so the attacker's post-login behaviour can be recorded.

The honeypot relies on paramiko purely for the SSH *transport* (framing,
key exchange, encryption). paramiko never runs commands — the shell channel is
handed to :func:`honeypot.fake_shell.run_shell`, which only does dictionary
lookups. No execution primitive is imported anywhere in this package.
"""

from __future__ import annotations

import logging
import socket
import threading
from pathlib import Path

import paramiko

from . import events, geoip
from .config import Config
from .db import connect
from .fake_shell import resolve_command, run_shell

log = logging.getLogger("honeypot.ssh")

# A realistic banner — many scanners fingerprint and branch on this string.
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


def ensure_host_key(host_key_path: str | Path) -> paramiko.RSAKey:
    """Load the RSA host key, generating a fresh 2048-bit key on first use.

    The key is written once to ``host_key_path`` (parent dirs created) so the
    honeypot presents a stable identity across restarts.
    """
    path = Path(host_key_path)
    if path.is_file():
        return paramiko.RSAKey(filename=str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    return key


class HoneypotServer(paramiko.ServerInterface):
    """paramiko :class:`~paramiko.ServerInterface` that logs and lures.

    One instance is created per connection. It records each password attempt
    through the shared event funnel and only "accepts" a login once the
    attacker has tried :pyattr:`Config.grant_session_after` times — mimicking a
    weak server that finally yields, which keeps brute-force tools engaged.
    """

    def __init__(self, conn: object, session_id: int, config: Config) -> None:
        self._conn = conn
        self._session_id = session_id
        self._config = config
        self.auth_attempts = 0
        # Signalled once the client requests a shell, so the handler can start
        # the fake shell on the right thread.
        self.shell_event = threading.Event()

    # --- Authentication ----------------------------------------------------

    def get_allowed_auths(self, username: str) -> str:
        """Advertise password authentication only."""
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        """Log every password attempt; grant a session after the threshold.

        Always records ``success=0`` — the honeypot never performs genuine
        authentication. Returning ``AUTH_SUCCESSFUL`` here only unlocks the
        *simulated* shell.
        """
        self.auth_attempts += 1
        events.log_auth_attempt(
            self._conn,  # type: ignore[arg-type]
            session_id=self._session_id,
            username=username,
            password=password,
            success=False,
        )
        log.info(
            "ssh auth attempt #%d user=%r pass=%r", self.auth_attempts, username, password
        )
        if self.auth_attempts >= self._config.grant_session_after:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Always refuse public-key auth so attackers fall back to passwords."""
        return paramiko.AUTH_FAILED

    # --- Channels ----------------------------------------------------------

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Permit only interactive ``session`` channels."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        """Accept a shell request and signal the handler to start the shell."""
        self.shell_event.set()
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        """Accept PTY requests so the client believes it has a real terminal."""
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        """Handle non-interactive ``ssh host <cmd>`` invocations.

        The command is *logged* and a canned reply is written, then the channel
        closes. The bytes are never executed — :func:`resolve_command` only
        indexes a dictionary.
        """
        cmd = command.decode("utf-8", errors="replace")[: self._config.max_command_length]
        events.log_command(
            self._conn,  # type: ignore[arg-type]
            session_id=self._session_id,
            command=cmd,
        )
        try:
            channel.sendall(resolve_command(cmd))
            channel.send_exit_status(0)
        except OSError:
            pass
        finally:
            channel.close()
        return True


def _handle_connection(
    client: socket.socket,
    addr: tuple[str, int],
    host_key: paramiko.RSAKey,
    config: Config,
    semaphore: threading.Semaphore,
) -> None:
    """Serve one attacker connection end-to-end, then release the slot."""
    src_ip, src_port = addr[0], addr[1]
    conn = connect(config.db_path)
    transport: paramiko.Transport | None = None
    session_id: int | None = None
    try:
        client.settimeout(config.conn_timeout)
        geo = geoip.lookup(src_ip, config.geoip_db_path)
        session_id = events.start_session(
            conn,
            protocol="ssh",
            src_ip=src_ip,
            src_port=src_port,
            geo=geo,
        )
        log.info("ssh connection from %s:%s (session %s)", src_ip, src_port, session_id)

        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(conn, session_id, config)
        transport.start_server(server=server)

        channel = transport.accept(timeout=config.conn_timeout)
        if channel is None:
            return

        # Record the client's SSH banner now that the handshake has completed.
        events.set_client_banner(
            conn, session_id=session_id, client_banner=transport.remote_version
        )

        # Wait briefly for the shell request, then run the simulated shell.
        if server.shell_event.wait(timeout=config.conn_timeout):
            channel.settimeout(config.conn_timeout)
            run_shell(channel, session_id, conn, config)
        channel.close()
    except (paramiko.SSHException, EOFError, OSError) as exc:
        log.debug("ssh connection from %s ended: %s", src_ip, exc)
    except Exception:  # noqa: BLE001 - never let one connection crash the server.
        log.exception("unexpected error handling ssh connection from %s", src_ip)
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            client.close()
        except OSError:
            pass
        if session_id is not None:
            try:
                events.end_session(conn, session_id=session_id)
            except Exception:  # noqa: BLE001
                pass
        conn.close()
        semaphore.release()


def serve(config: Config, *, ready: threading.Event | None = None) -> None:
    """Run the SSH honeypot, accepting connections until the process is killed.

    Concurrency is bounded by a counting semaphore of size
    :pyattr:`Config.max_connections`; excess clients are accepted then closed
    immediately so a flood cannot exhaust threads. ``ready`` is set once the
    listening socket is bound (used by tests).
    """
    host_key = ensure_host_key(config.host_key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config.host, config.ssh_port))
    sock.listen(100)
    bound_port = sock.getsockname()[1]
    log.info("SSH honeypot listening on %s:%s", config.host, bound_port)
    if ready is not None:
        ready.set()

    semaphore = threading.Semaphore(config.max_connections)
    try:
        while True:
            client, addr = sock.accept()
            if not semaphore.acquire(blocking=False):
                # At capacity: drop the connection rather than queue threads.
                log.warning("max connections reached, dropping %s", addr[0])
                client.close()
                continue
            thread = threading.Thread(
                target=_handle_connection,
                args=(client, addr, host_key, config, semaphore),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown.
        log.info("SSH honeypot shutting down")
    finally:
        sock.close()

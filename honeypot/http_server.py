"""The HTTP honeypot.

Serves a small set of convincing decoy pages (admin panels, CMS logins,
exposed ``.env``/``.git`` files) and logs *every* request — method, path, all
headers, body and any posted credentials — through the shared event funnel.

Safety: this server never executes anything. POST bodies are *parsed* for
username/password-like fields using :mod:`urllib.parse` / :mod:`json`; the
parsed values are stored and a generic "invalid credentials" page is returned.
Authentication never succeeds and no attacker input reaches an interpreter.
"""

from __future__ import annotations

import json
import logging
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

from . import events, geoip
from .config import Config
from .db import connect
from .http_pages import LOGIN_PATHS, NOT_FOUND_BODY, STATIC_PAGES, login_page

log = logging.getLogger("honeypot.http")

# Spoofed identity — the honeypot impersonates a stock Apache install.
SERVER_BANNER = "Apache/2.4.52 (Ubuntu)"

# Field names commonly used for credentials across the bait login forms.
_USER_FIELDS = ("username", "user", "login", "email", "uname", "log", "userid")
_PASS_FIELDS = ("password", "pass", "passwd", "pwd", "pw")

# Cap on the request body we will read, so a huge upload cannot exhaust memory.
_MAX_BODY = 64 * 1024


def _extract_credentials(content_type: str, body: bytes) -> tuple[str | None, str | None]:
    """Pull username/password-like values from a form-encoded or JSON body.

    Returns ``(username, password)`` with ``None`` for anything not found. This
    only *reads* the body; it is never evaluated.
    """
    text = body.decode("utf-8", errors="replace")
    fields: dict[str, str] = {}

    ctype = content_type.lower()
    if "application/json" in ctype:
        try:
            parsed = json.loads(text or "{}")
            if isinstance(parsed, dict):
                fields = {str(k).lower(): str(v) for k, v in parsed.items()}
        except (ValueError, TypeError):
            fields = {}
    else:
        # Default: treat as application/x-www-form-urlencoded.
        for key, values in parse_qs(text).items():
            if values:
                fields[key.lower()] = values[0]

    username = next((fields[f] for f in _USER_FIELDS if f in fields), None)
    password = next((fields[f] for f in _PASS_FIELDS if f in fields), None)
    return username, password


class HoneypotHTTPRequestHandler(BaseHTTPRequestHandler):
    """Request handler that logs every hit and serves decoy content.

    The honeypot :class:`Config` and a DB connection are attached to the server
    instance (see :class:`HoneypotHTTPServer`) and read from there.
    """

    server_version = SERVER_BANNER
    sys_version = ""  # Suppress the Python version in the Server header.
    protocol_version = "HTTP/1.1"

    # --- Logging -----------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:
        """Route the stdlib access log through our logger instead of stderr."""
        log.debug("http %s - %s", self.address_string(), fmt % args)

    def _config(self) -> Config:
        return self.server.config  # type: ignore[attr-defined]

    def _record(
        self,
        method: str,
        body: bytes,
        posted_username: str | None,
        posted_password: str | None,
    ) -> None:
        """Persist one HTTP request via the shared event funnel."""
        config = self._config()
        src_ip, src_port = self.client_address[0], self.client_address[1]
        conn = connect(config.db_path)
        try:
            geo = geoip.lookup(src_ip, config.geoip_db_path)
            session_id = events.start_session(
                conn,
                protocol="http",
                src_ip=src_ip,
                src_port=src_port,
                client_banner=self.headers.get("User-Agent"),
                geo=geo,
            )
            events.log_http_request(
                conn,
                session_id=session_id,
                method=method,
                path=self.path,
                user_agent=self.headers.get("User-Agent"),
                headers={k: v for k, v in self.headers.items()},
                body=body.decode("utf-8", errors="replace") if body else None,
                posted_username=posted_username,
                posted_password=posted_password,
            )
            events.end_session(conn, session_id=session_id)
            log.info("http %s %s from %s", method, self.path, src_ip)
        finally:
            conn.close()

    # --- Response helpers --------------------------------------------------

    def _send(self, status: int, content_type: str, body: str) -> None:
        """Write a complete HTTP response with the spoofed Server header."""
        payload = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _path_only(self) -> str:
        """Return the request path without any query string."""
        return self.path.split("?", 1)[0]

    def _read_body(self) -> bytes:
        """Read the request body, bounded by ``_MAX_BODY``."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return b""
        length = max(0, min(length, _MAX_BODY))
        if length == 0:
            return b""
        try:
            return self.rfile.read(length)
        except (OSError, ValueError):
            return b""

    # --- HTTP verbs --------------------------------------------------------

    def do_GET(self) -> None:
        """Serve a decoy page (or login form) and log the request."""
        self._record("GET", b"", None, None)
        path = self._path_only()

        if path in STATIC_PAGES:
            ctype, body = STATIC_PAGES[path]
            self._send(200, ctype, body)
        elif path in LOGIN_PATHS:
            self._send(200, "text/html; charset=utf-8", login_page(LOGIN_PATHS[path], path))
        else:
            self._send(404, "text/html; charset=utf-8", NOT_FOUND_BODY)

    def do_POST(self) -> None:
        """Parse a posted login (never authenticating) and log everything."""
        body = self._read_body()
        path = self._path_only()
        content_type = self.headers.get("Content-Type", "")

        username, password = _extract_credentials(content_type, body)
        self._record("POST", body, username, password)

        if path in LOGIN_PATHS:
            # Always reject — a honeypot never grants access.
            self._send(
                200,
                "text/html; charset=utf-8",
                login_page(LOGIN_PATHS[path], path, invalid=True),
            )
        elif path in STATIC_PAGES:
            ctype, page = STATIC_PAGES[path]
            self._send(200, ctype, page)
        else:
            self._send(404, "text/html; charset=utf-8", NOT_FOUND_BODY)

    def do_HEAD(self) -> None:
        """Answer HEAD probes with headers only; still logged."""
        self._record("HEAD", b"", None, None)
        path = self._path_only()
        status = 200 if (path in STATIC_PAGES or path in LOGIN_PATHS) else 404
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass


class HoneypotHTTPServer(socketserver.ThreadingTCPServer):
    """Threaded TCP server carrying the honeypot config to each handler."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        self.config = config
        super().__init__(address, HoneypotHTTPRequestHandler)


def serve(config: Config, *, ready: threading.Event | None = None) -> HoneypotHTTPServer:
    """Start the HTTP honeypot and block in :meth:`serve_forever`.

    Returns the server object (after it stops) so tests that run it on a
    background thread can call :meth:`shutdown`. ``ready`` is set once bound.
    """
    server = HoneypotHTTPServer((config.host, config.http_port), config)
    bound_port = server.server_address[1]
    log.info("HTTP honeypot listening on %s:%s", config.host, bound_port)
    if ready is not None:
        ready.set()
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown.
        log.info("HTTP honeypot shutting down")
    finally:
        server.server_close()
    return server

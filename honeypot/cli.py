"""Command-line entry point for the honeypot.

Subcommands:

* ``honeypot ssh   [--port]``  — run the SSH honeypot.
* ``honeypot http  [--port]``  — run the HTTP honeypot.
* ``honeypot api   [--port]``  — run the read-only dashboard API.
* ``honeypot seed  [--out]``   — generate the synthetic capture database.
* ``honeypot all``             — run SSH + HTTP + API together.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from pathlib import Path

from .config import DEFAULT, Config
from .db import init_db


def base_config() -> Config:
    """Build the base :class:`Config`, applying environment-variable overrides.

    Recognised environment variables (used mainly by the Docker deployment):

    * ``HONEYPOT_HOST``      — bind address (containers need ``0.0.0.0``);
    * ``HONEYPOT_DB``        — capture database path;
    * ``HONEYPOT_GEOIP_DB``  — path to the GeoIP ``.mmdb``;
    * ``HONEYPOT_HOST_KEY``  — path to the SSH host key.

    Anything unset keeps the default from :data:`honeypot.config.DEFAULT`.
    """
    overrides: dict[str, object] = {}
    if host := os.environ.get("HONEYPOT_HOST"):
        overrides["host"] = host
    if db := os.environ.get("HONEYPOT_DB"):
        overrides["db_path"] = Path(db)
    if geoip := os.environ.get("HONEYPOT_GEOIP_DB"):
        overrides["geoip_db_path"] = Path(geoip)
    if host_key := os.environ.get("HONEYPOT_HOST_KEY"):
        overrides["host_key_path"] = Path(host_key)
    return DEFAULT.with_overrides(**overrides) if overrides else DEFAULT


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="honeypot",
        description="A low-interaction SSH/HTTP honeypot with an attack dashboard.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ssh = sub.add_parser("ssh", help="run the SSH honeypot")
    p_ssh.add_argument("--port", type=int, default=DEFAULT.ssh_port,
                       help=f"listen port (default {DEFAULT.ssh_port})")

    p_http = sub.add_parser("http", help="run the HTTP honeypot")
    p_http.add_argument("--port", type=int, default=DEFAULT.http_port,
                        help=f"listen port (default {DEFAULT.http_port})")

    p_api = sub.add_parser("api", help="run the read-only dashboard API")
    p_api.add_argument("--port", type=int, default=DEFAULT.api_port,
                       help=f"listen port (default {DEFAULT.api_port})")

    p_seed = sub.add_parser("seed", help="generate the synthetic capture database")
    p_seed.add_argument("--out", default=str(DEFAULT.db_path),
                        help=f"output DB path (default {DEFAULT.db_path})")

    sub.add_parser("all", help="run SSH + HTTP + API together")
    return parser


def _configure_logging(verbose: bool) -> None:
    """Set up console logging at INFO (or DEBUG when ``--verbose``)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def _run_ssh(config: Config) -> None:
    """Initialise the DB and start the SSH honeypot (blocking)."""
    from .ssh_server import serve

    init_db(config.db_path)
    serve(config)


def _run_http(config: Config) -> None:
    """Initialise the DB and start the HTTP honeypot (blocking)."""
    from .http_server import serve

    init_db(config.db_path)
    serve(config)


def _run_api(config: Config) -> None:
    """Start the read-only dashboard API with uvicorn (blocking)."""
    import uvicorn

    init_db(config.db_path)
    # Pass the DB path to the app via an environment variable so the FastAPI
    # module can be imported without a config object.
    os.environ["HONEYPOT_DB"] = str(config.db_path)
    uvicorn.run("api.main:app", host=config.host, port=config.api_port, log_level="info")


def _run_all(config: Config) -> None:
    """Run SSH, HTTP and the API concurrently on background threads."""
    from .http_server import serve as serve_http
    from .ssh_server import serve as serve_ssh

    init_db(config.db_path)
    log = logging.getLogger("honeypot")

    threading.Thread(target=serve_ssh, args=(config,), daemon=True).start()
    threading.Thread(target=serve_http, args=(config,), daemon=True).start()
    log.info("SSH + HTTP honeypots started; starting API (Ctrl-C to stop)")
    try:
        _run_api(config)
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown.
        log.info("shutting down")


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the chosen subcommand.

    Returns a process exit code (0 on success).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    log = logging.getLogger("honeypot")

    # The base config honours HONEYPOT_* env vars (see base_config); the
    # per-subcommand --port flag is layered on top of it.
    config = base_config()

    try:
        if args.command == "ssh":
            _run_ssh(config.with_overrides(ssh_port=args.port))
        elif args.command == "http":
            _run_http(config.with_overrides(http_port=args.port))
        elif args.command == "api":
            _run_api(config.with_overrides(api_port=args.port))
        elif args.command == "seed":
            from .seed import seed_database

            count = seed_database(args.out)
            log.info("seeded %d sessions into %s", count, args.out)
        elif args.command == "all":
            _run_all(config)
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown.
        log.info("interrupted")
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

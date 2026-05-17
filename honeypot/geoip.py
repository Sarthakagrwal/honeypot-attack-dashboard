"""IP geolocation with graceful degradation.

Wraps a DB-IP IP-to-City Lite ``.mmdb`` database via :mod:`geoip2`. The lookup
is intentionally fault-tolerant: a missing database file, a private/reserved
address, or a genuine lookup miss all return ``None`` instead of raising, so
the honeypot keeps running (and CI passes) with no ``.mmdb`` present.

IP geolocation by DB-IP.com (https://db-ip.com), licensed CC BY 4.0.
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path
from typing import Any

try:  # geoip2 is a hard dependency, but guard the import defensively.
    import geoip2.database
    import geoip2.errors

    _GEOIP2_AVAILABLE = True
except ImportError:  # pragma: no cover - geoip2 is declared in pyproject
    _GEOIP2_AVAILABLE = False

# A geoip2 Reader is documented as thread-safe for reads, but opening it is
# not, so guard reader creation with a lock and cache one reader per path.
_LOCK = threading.Lock()
_READERS: dict[str, Any] = {}

_EMPTY: dict[str, Any] = {
    "country": None,
    "country_code": None,
    "latitude": None,
    "longitude": None,
}


def _is_private(ip: str) -> bool:
    """Return True for private, loopback, link-local or otherwise non-global IPs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # Not an IP at all -> treat as un-geolocatable.
    return not addr.is_global


def _get_reader(db_path: str | Path) -> Any | None:
    """Return a cached geoip2 Reader for ``db_path`` or ``None`` if unavailable."""
    if not _GEOIP2_AVAILABLE:
        return None
    path = Path(db_path)
    if not path.is_file():
        return None
    key = str(path.resolve())
    with _LOCK:
        reader = _READERS.get(key)
        if reader is None:
            try:
                reader = geoip2.database.Reader(key)
            except (OSError, ValueError):
                return None
            _READERS[key] = reader
        return reader


def lookup(ip: str, db_path: str | Path) -> dict[str, Any]:
    """Geolocate ``ip`` using the ``.mmdb`` at ``db_path``.

    Always returns a dict with keys ``country``, ``country_code``,
    ``latitude`` and ``longitude``; any of them may be ``None``. This function
    never raises — callers can rely on it under all failure modes.
    """
    if _is_private(ip):
        return dict(_EMPTY)

    reader = _get_reader(db_path)
    if reader is None:
        return dict(_EMPTY)

    try:
        resp = reader.city(ip)
    except Exception:  # noqa: BLE001 - any geoip2 error degrades to empty.
        return dict(_EMPTY)

    return {
        "country": resp.country.name,
        "country_code": resp.country.iso_code,
        "latitude": resp.location.latitude,
        "longitude": resp.location.longitude,
    }


def close_readers() -> None:
    """Close and forget all cached readers (used by tests for clean teardown)."""
    with _LOCK:
        for reader in _READERS.values():
            try:
                reader.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup.
                pass
        _READERS.clear()

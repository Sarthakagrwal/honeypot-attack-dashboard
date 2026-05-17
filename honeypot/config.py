"""Central configuration for the honeypot.

All tunable parameters live on a single frozen :class:`Config` dataclass so
that every component (SSH, HTTP, API, seeder) reads consistent settings and
nothing can mutate them at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

# Repository root: <repo>/honeypot/config.py -> parents[1] is <repo>.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DATA_DIR = _REPO_ROOT / "data"


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration.

    Ports default to non-privileged values (>1024) so the honeypot runs as an
    unprivileged user — never as root. On a real deployment a host-level
    ``iptables`` redirect (see ``deploy/VPS-DEPLOYMENT.md``) forwards port 22
    traffic to :pyattr:`ssh_port` without granting the process root.
    """

    # --- Network ---
    host: str = "127.0.0.1"
    ssh_port: int = 2222
    http_port: int = 8080
    api_port: int = 8000

    # --- Filesystem paths ---
    db_path: Path = field(default_factory=lambda: _DATA_DIR / "honeypot.db")
    host_key_path: Path = field(
        default_factory=lambda: _DATA_DIR / "host_keys" / "ssh_host_rsa_key"
    )
    geoip_db_path: Path = field(default_factory=lambda: _DATA_DIR / "dbip-city-lite.mmdb")

    # --- Safety limits ---
    max_connections: int = 50
    conn_timeout: float = 30.0
    grant_session_after: int = 3
    max_auth_attempts: int = 8
    max_command_length: int = 4096
    max_commands_per_session: int = 200

    def with_overrides(self, **changes: object) -> Config:
        """Return a copy of this config with the given fields replaced."""
        return replace(self, **changes)


# A module-level default instance for convenience. Callers that need custom
# values should build their own Config (or use ``with_overrides``) rather than
# mutating this one — it is frozen, so mutation raises.
DEFAULT = Config()

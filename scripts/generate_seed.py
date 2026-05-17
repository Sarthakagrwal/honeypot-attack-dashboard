#!/usr/bin/env python3
"""Build the synthetic capture DB and write the dashboard's demo snapshot.

This script:

1. seeds a deterministic SQLite database via :func:`honeypot.seed.seed_database`;
2. builds the export payload with :func:`honeypot.export.build_export` — the
   *same* builder the live API uses — so ``demo-data.json`` and ``/api/export``
   always share an identical shape;
3. writes that payload to ``web/public/demo-data.json``, which is committed and
   is the data the deployed GitHub Pages dashboard renders.

Run it from anywhere::

    python scripts/generate_seed.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the repo root importable when run as a bare script.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from honeypot.db import connect_ro  # noqa: E402
from honeypot.export import build_export  # noqa: E402
from honeypot.seed import seed_database  # noqa: E402

DB_PATH = _REPO_ROOT / "data" / "honeypot.db"
DEMO_JSON = _REPO_ROOT / "web" / "public" / "demo-data.json"


def main() -> int:
    """Seed the database and write ``web/public/demo-data.json``."""
    print(f"Seeding synthetic attack history into {DB_PATH} ...")
    count = seed_database(DB_PATH)
    print(f"  wrote {count} sessions")

    conn = connect_ro(DB_PATH)
    try:
        export = build_export(conn)
    finally:
        conn.close()

    DEMO_JSON.parent.mkdir(parents=True, exist_ok=True)
    DEMO_JSON.write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")

    stats = export["stats"]
    print(f"  demo snapshot -> {DEMO_JSON}")
    print(
        "  totals: "
        f"{stats['total_sessions']} sessions, "
        f"{stats['unique_ips']} unique IPs, "
        f"{stats['auth_attempts']} auth attempts, "
        f"{stats['commands']} commands"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

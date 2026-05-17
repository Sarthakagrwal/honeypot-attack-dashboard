#!/usr/bin/env bash
#
# fetch_geoip.sh — download the DB-IP IP-to-City Lite database.
#
# The honeypot uses a MaxMind-format .mmdb file to geolocate attacker IPs for
# the dashboard map. We use the free DB-IP "IP to City Lite" database, which
# is redistributed monthly as an npm package mirrored on the jsDelivr CDN.
#
# DB-IP Lite data is licensed CC BY 4.0 — attribution to DB-IP.com is required
# and is shown in the dashboard footer and README.
#
# Usage:
#   ./deploy/scripts/fetch_geoip.sh [target-dir]
#
# The file is written as <target-dir>/dbip-city-lite.mmdb (default target-dir
# is the repo's data/ directory), which matches Config.geoip_db_path. The
# honeypot degrades gracefully if the file is absent, so this step is optional.

set -euo pipefail

# Resolve the repo root from this script's location (deploy/scripts/..).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET_DIR="${1:-${REPO_ROOT}/data}"
OUT="${TARGET_DIR}/dbip-city-lite.mmdb"

# jsDelivr serves the latest published @ip-location-db/dbip-city-lite package.
# The .mmdb is shipped gzip-compressed inside that package.
URL="https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-city-lite-mmdb/dbip-city-lite.mmdb.gz"

mkdir -p "${TARGET_DIR}"

echo "Downloading DB-IP IP-to-City Lite database..."
echo "  source: ${URL}"
echo "  target: ${OUT}"

# Download to a temporary file, then gunzip into place.
TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${URL}" -o "${TMP}"
elif command -v wget >/dev/null 2>&1; then
  wget -q "${URL}" -O "${TMP}"
else
  echo "error: neither curl nor wget is installed" >&2
  exit 1
fi

gunzip -c "${TMP}" > "${OUT}"

echo "Done. GeoIP database ready at ${OUT}"
echo "(IP geolocation by DB-IP.com — https://db-ip.com — licensed CC BY 4.0)"

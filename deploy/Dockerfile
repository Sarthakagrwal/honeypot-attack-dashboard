# syntax=docker/dockerfile:1
#
# Honeypot engine + read-only dashboard API.
#
# The container runs `honeypot all`, which serves the SSH honeypot, the HTTP
# honeypot and the API together. It runs as a NON-root user — the honeypot
# listens on non-privileged ports (2222 / 8080 / 8000) and a host-side
# iptables redirect (see VPS-DEPLOYMENT.md) sends real port-22 traffic to it.

FROM python:3.13-slim AS base

# Do not write .pyc files; flush stdout/stderr immediately for clean logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so the layer caches across code changes.
COPY pyproject.toml ./
COPY honeypot/ ./honeypot/
COPY api/ ./api/
RUN pip install --no-cache-dir .

# Create an unprivileged user and a data directory it owns.
RUN useradd --create-home --uid 10001 honey \
    && mkdir -p /data \
    && chown -R honey:honey /data /app

USER honey

# The capture DB, host keys and GeoIP database live on a mounted volume.
ENV HONEYPOT_DB=/data/honeypot.db
VOLUME ["/data"]

# SSH honeypot, HTTP honeypot, dashboard API.
EXPOSE 2222 8080 8000

# Bind to 0.0.0.0 inside the container so the published ports are reachable.
CMD ["honeypot", "all"]

# Deploying the honeypot to a VPS

This runbook walks through running the honeypot on a small, **disposable**
internet-facing server so it captures real attack traffic, and pointing the
dashboard at the live API.

> ### Read this first — safety
>
> A honeypot deliberately attracts hostile traffic. Treat the host as
> **untrusted and disposable**:
>
> - Use a **dedicated, cheap VPS** ($5/month is plenty) that runs *nothing
>   else you care about*. Never run this on a machine with personal data,
>   production services, or shared credentials.
> - **Move your real administrative SSH off port 22 before you start** (see
>   step 4). The honeypot takes over port 22; if you do not relocate your
>   admin SSH first you can lock yourself out.
> - The honeypot is *low-interaction*: it simulates services and never
>   executes attacker input (see the project README "Safety" section). It is
>   still prudent to firewall the box, keep the host OS patched, and tear the
>   VPS down when you are finished.
> - Check your VPS provider's acceptable-use policy — running a honeypot is
>   normally fine, but inbound scan traffic to it is expected and high.

---

## 1. Provision the VPS

Create the smallest instance your provider offers (1 vCPU / 1 GB RAM,
Ubuntu 22.04 or 24.04 LTS). Note its public IP. SSH in as a sudo-capable user.

```bash
ssh youruser@YOUR_VPS_IP
sudo apt update && sudo apt upgrade -y
```

## 2. Install Docker

```bash
# Docker's official convenience script.
curl -fsSL https://get.docker.com | sudo sh

# Allow your user to run docker without sudo (log out/in afterwards).
sudo usermod -aG docker "$USER"
```

Log out and back in, then confirm:

```bash
docker --version
docker compose version
```

## 3. Get the code and download the GeoIP database

```bash
git clone https://github.com/Sarthakagrwal/honeypot-attack-dashboard.git
cd honeypot-attack-dashboard

# Download the DB-IP IP-to-City Lite database into ./data (optional but
# recommended — the dashboard map needs it). The honeypot degrades
# gracefully if it is absent.
./deploy/scripts/fetch_geoip.sh ./data
```

`fetch_geoip.sh` writes `data/dbip-city-lite.mmdb`, which the compose file
mounts into the container at `/data/dbip-city-lite.mmdb`.

## 4. Move your real SSH off port 22 — do this BEFORE step 5

The honeypot listens on **2222** inside the container and you will redirect
real port-22 traffic to it. Your genuine admin SSH must therefore move to a
different port first.

Edit `/etc/ssh/sshd_config` (or a drop-in in `/etc/ssh/sshd_config.d/`):

```
Port 22022
```

Apply it and **open a second SSH session on the new port to confirm it works
before closing your current one**:

```bash
sudo systemctl restart ssh
# From your laptop, in a NEW terminal — keep the old session open:
ssh -p 22022 youruser@YOUR_VPS_IP
```

Only once the new-port session works should you continue.

## 5. Start the honeypot

```bash
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f   # watch it boot
```

This starts, in one container running as a non-root user:

| Service        | Container port | Published as          |
| -------------- | -------------- | --------------------- |
| SSH honeypot   | 2222           | `0.0.0.0:2222`        |
| HTTP honeypot  | 8080           | `0.0.0.0:8080`        |
| Dashboard API  | 8000           | `127.0.0.1:8000`      |

The API is bound to localhost on the host on purpose — see step 7 before
exposing it.

## 6. Redirect real port-22 traffic to the honeypot

So that internet SSH scanners actually hit the honeypot, redirect inbound
port 22 to 2222 with an `iptables` NAT rule on the **host** (this does not
need the container to have any privileges):

```bash
# Redirect inbound TCP/22 to the honeypot on 2222.
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Optional: also expose the HTTP honeypot on the familiar port 80.
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

Make the rules survive reboots:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

Your admin SSH on **22022** is unaffected — the redirect only touches port 22.

Verify from your laptop that port 22 now reaches the honeypot (it will offer
a fake OpenSSH banner and "accept" a login after a few tries into a simulated
shell):

```bash
ssh root@YOUR_VPS_IP        # this now hits the honeypot, not your real shell
```

## 7. Point the dashboard at the live API

The dashboard (the GitHub Pages site) reads `VITE_API_BASE`. If that variable
is set at build time it fetches `${VITE_API_BASE}/api/export` from your live
honeypot instead of the bundled demo snapshot.

The API is only bound to `127.0.0.1:8000` on the VPS. To expose it safely:

1. Put a reverse proxy (Caddy or nginx) in front of it with HTTPS — Caddy
   gets you a certificate automatically:

   ```
   # /etc/caddy/Caddyfile
   honeypot-api.example.com {
       reverse_proxy 127.0.0.1:8000
   }
   ```

2. The API only exposes **GET** routes and read-only data, and already sends
   permissive CORS headers, so a static dashboard on another origin can call
   it directly.

3. Rebuild the site with the API base set:

   ```bash
   cd web
   VITE_API_BASE=https://honeypot-api.example.com npm run build
   ```

   Deploy that build (or set `VITE_API_BASE` as a GitHub Actions variable so
   the Pages deploy workflow bakes it in).

Without `VITE_API_BASE` the dashboard simply renders the committed
`demo-data.json` snapshot — which is exactly how the public Pages demo runs.

## 8. Day-to-day operations

```bash
# Tail logs
docker compose -f deploy/docker-compose.yml logs -f

# Inspect captured data directly
docker compose -f deploy/docker-compose.yml exec honeypot \
  python -c "import sqlite3,os; c=sqlite3.connect(os.environ['HONEYPOT_DB']); \
print('sessions:', c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0])"

# Update to the latest code
git pull
docker compose -f deploy/docker-compose.yml up -d --build

# Stop the honeypot
docker compose -f deploy/docker-compose.yml down
```

## 9. Tear-down

When you are done, destroy the VPS entirely (do not just stop the container).
A honeypot host has, by design, been probed continuously by hostile traffic;
the cleanest end state is a deleted instance.

```bash
docker compose -f deploy/docker-compose.yml down -v   # also removes the volume
# then delete the VPS from your provider's console
```

# Knock-Knock Installation Guide

Knock-Knock can be installed most simply and universally using Docker, but also can be configured to run without Docker on Ubuntu/Debian and RHEL/CentOS/Fedora systems. All of these setups require a few prerequisites.

## Prerequisites

All installation methods require:

- Server with root access
- Public IP address (for receiving attacks)
- Ability to expose port 22 to internet traffic
- **Real SSH moved to a non-standard port** (the honeypot needs port 22)

### Move Real SSH to a Different Port

**Do this first** or you will lock yourself out.

```bash
# Edit SSH config
nano /etc/ssh/sshd_config
# Change: Port 22
# To:     Port 2222   (or any unused port)

# Restart SSH (do this in a screen/tmux session or have console access)
systemctl restart sshd

# Test new port before disconnecting!
ssh -p 2222 user@your-server
```

### Open Firewall Ports

Open the ports for whichever honeypots you plan to run, plus the web dashboard. For example, with UFW:

```bash
# Web dashboard (default port 8080)
ufw allow 8080/tcp

# Honeypot ports — open only the ones you plan to run (these should be open to everyone)
# Default protocols (enabled out of the box):
ufw allow 21/tcp     # FTP
ufw allow 22/tcp     # SSH honeypot
ufw allow 23/tcp     # Telnet
ufw allow 25/tcp     # SMTP
ufw allow 80/tcp     # HTTP
ufw allow 445/tcp    # SMB
ufw allow 587/tcp    # SMTP (submission)
ufw allow 3389/tcp   # RDP
ufw allow 5060       # SIP (TCP + UDP)

# Optional protocols (not enabled by default — add to ENABLED_PROTOCOLS in .env to activate):
ufw allow 1880/tcp   # Node-RED (NRED)
ufw allow 1883/tcp   # MQTT
ufw allow 8883/tcp   # MQTT over TLS
ufw allow 502/tcp    # Modbus TCP (MODB)

# Your real SSH port
ufw allow 2222/tcp   # or whatever you chose
```

If you're not using UFW, open the equivalent ports in your firewall.

The web dashboard runs on port 8080 by default. You can access it at `http://your-server-ip:8080`. To change the port, set the `WEB_PORT` environment variable.

### MaxMind Account (GeoIP)

Knock-Knock uses MaxMind GeoLite2 databases for IP geolocation. You need a free MaxMind account.

1. Register at https://www.maxmind.com/en/geolite2/signup
2. In your account dashboard, generate a license key
3. Note your **Account ID** and **License Key** — you'll need them below

---

## Option 1: Docker (Simplest, Universal)

Complete the [Prerequisites](#prerequisites) above first.

**Install Docker (skip if already installed):**
```bash
curl -fsSL https://get.docker.com | sh
```

### Clone the Repository

```bash
cd /root
git clone https://github.com/djkurlander/knock-knock.git
cd knock-knock
```

### Configure MaxMind Credentials

```bash
cp .env.example .env
nano .env   # Fill in your Account ID and License Key
```

### Networking: host (default, Linux) vs bridge

`.env.example` ships with `COMPOSE_FILE=docker-compose.host.yml` active, so a fresh install
uses **host networking** — recommended on a Linux server:

- Honeypots see the **real attacker source IP** (bridge NAT can mask it, and UDP/SIP return
  paths are fragile through DNAT).
- Self-identity **redaction works automatically** (the container sees the host's public IP/PTR).
- **No port list to maintain** — only the honeypots in `ENABLED_PROTOCOLS` bind their host
  ports, via the per-protocol `*_PORT` vars. Nothing else to configure; no override file.

Because each enabled honeypot binds the host port directly, **move real sshd off :22 first**
(see [Move Real SSH to a Different Port](#move-real-ssh-to-a-different-port)). To leave a port
free for the host, drop that protocol from `ENABLED_PROTOCOLS` — it won't be spawned and won't bind.

**Bridge networking (Docker Desktop / macOS / Windows, or if you prefer container isolation):**
host networking is Linux-only, so on other platforms comment out `COMPOSE_FILE` in `.env` to fall
back to `docker-compose.yml`. Bridge publishes ports via an override file — copy the example and
remove any ports you don't want exposed:

```bash
# In .env, comment out:  # COMPOSE_FILE=docker-compose.host.yml
cp docker-compose.override.yml.example docker-compose.override.yml
nano docker-compose.override.yml   # Remove ports you don't need
```

With bridge, keep the `ports:` list and `ENABLED_PROTOCOLS` in sync — Docker binds ports
independently of which honeypots are running. (Host networking has no such list, so nothing to sync.)

### Start

```bash
# Pull and start (uses pre-built image from ghcr.io)
docker compose up -d
```

The `geoipupdate` container downloads the GeoIP databases on first start and refreshes them weekly. The monitor waits until the databases are ready before processing knocks — you'll see `⏳ Waiting for GeoIP databases...` in the logs until the download completes.

### Verify

```bash
docker compose logs -f honeypot-monitor
# Should show:
#   ⏳ Waiting for GeoIP databases...  (briefly, during first-time download)
#   ✅ GeoIP databases loaded
#   🚀 Knock-Knock Monitor Active...

docker compose logs web   # Should show uvicorn startup
```

That's it. Four containers (Redis, geoipupdate, honeypot+monitor, web) start automatically and restart on failure.

**Useful commands:**
```bash
docker compose logs -f              # Follow all logs
docker compose restart              # Restart all services
docker compose down                 # Stop everything
docker compose up -d --build        # Rebuild after code changes
```

See [Optional Configuration](#optional-configuration) for various site-specific settings, and [Troubleshooting](#troubleshooting) if you run into issues.

---

## Option 2: Ubuntu/Debian

Complete the [Prerequisites](#prerequisites) above first.

### GeoIP Databases

```bash
apt install -y geoipupdate
```

Configure your MaxMind credentials in `/etc/GeoIP.conf`:
```
AccountID your_account_id
LicenseKey your_license_key
DatabaseDirectory /usr/share/GeoIP
```

Download the databases and set up weekly auto-updates (MaxMind updates databases every Tuesday):
```bash
geoipupdate

# Ensure databases are at /usr/share/GeoIP (some distros use /var/lib/GeoIP)
[ ! -e /usr/share/GeoIP ] && ln -s /var/lib/GeoIP /usr/share/GeoIP

# Verify
ls /usr/share/GeoIP/GeoLite2-*.mmdb

# Weekly auto-update
crontab -e
# Add line:
0 3 * * 3 /usr/bin/geoipupdate
```

### System Dependencies

```bash
apt update
apt install -y redis-server python3.12 python3.12-venv
systemctl enable redis-server
systemctl start redis-server

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### Clone and Setup

```bash
cd /root
git clone https://github.com/djkurlander/knock-knock.git
cd knock-knock

uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
vi .env   # Set SOURCE_ID, enable SSL, configure auto-ban, etc.
```

See `.env.example` for all available options with descriptions.

### Install Systemd Services

```bash
cp systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable knock-monitor knock-web
systemctl start knock-monitor knock-web
```

### Verify

```bash
systemctl status knock-monitor knock-web

journalctl -u knock-monitor -f    # Should show "Honeypot Active" and "Monitor Active"
journalctl -u knock-web -f        # Should show uvicorn startup

# Test from another machine
ssh test@your-server-ip
# Open http://your-server-ip in browser
```

See [Optional Configuration](#optional-configuration) for various site-specific settings, and [Troubleshooting](#troubleshooting) if you run into issues.

---

## Option 3: RHEL/CentOS/Fedora

Complete the [Prerequisites](#prerequisites) above first.

### GeoIP Databases

```bash
dnf install -y geoipupdate
```

Configure your MaxMind credentials in `/etc/GeoIP.conf`:
```
AccountID your_account_id
LicenseKey your_license_key
DatabaseDirectory /usr/share/GeoIP
```

Download the databases and set up weekly auto-updates (MaxMind updates databases every Tuesday):
```bash
geoipupdate

# Verify
ls /usr/share/GeoIP/GeoLite2-*.mmdb

# Weekly auto-update
crontab -e
# Add line:
0 3 * * 3 /usr/bin/geoipupdate
```

### System Dependencies

```bash
dnf install -y redis python3.12
systemctl enable redis
systemctl start redis

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### Clone and Setup

```bash
cd /root
git clone https://github.com/djkurlander/knock-knock.git
cd knock-knock

uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
vi .env   # Set SOURCE_ID, enable SSL, configure auto-ban, etc.
```

See `.env.example` for all available options with descriptions.

### Install Systemd Services

The Redis service name may differ on RHEL-based systems:

```bash
cp systemd/*.service /etc/systemd/system/

# Update the Redis dependency in unit files
# Change "After=... redis-server.service" to "After=... redis.service"
sed -i 's/redis-server.service/redis.service/g' /etc/systemd/system/knock-monitor.service
sed -i 's/redis-server.service/redis.service/g' /etc/systemd/system/knock-web.service

systemctl daemon-reload
systemctl enable knock-monitor knock-web
systemctl start knock-monitor knock-web
```

### Verify

```bash
systemctl status knock-monitor knock-web

journalctl -u knock-monitor -f    # Should show "Honeypot Active" and "Monitor Active"
journalctl -u knock-web -f        # Should show uvicorn startup

# Test from another machine
ssh test@your-server-ip
# Open http://your-server-ip in browser
```

See [Optional Configuration](#optional-configuration) for various site-specific settings, and [Troubleshooting](#troubleshooting) if you run into issues.

---

## Optional Configuration

Most configuration is done via `.env` — see `.env.example` for all available options with descriptions. The sections below cover the most common customizations.

### Saving Individual Knocks (`SAVE_KNOCKS`)

By default, the monitor only updates aggregated intel tables (top usernames, passwords, countries, ISPs, IPs). To also store every individual knock in per-protocol SQLite tables for later analysis, set `SAVE_KNOCKS` in `.env`. Can result in large databases depending on traffic and protocols chosen.

```bash
# All protocols:
SAVE_KNOCKS=true

# Selective — only specific protocols:
SAVE_KNOCKS=SIP,SMTP
```

Restart after changing:
```bash
# Docker
docker compose up -d

# Systemd
systemctl restart knock-monitor
```

### Selecting Protocols (`ENABLED_PROTOCOLS`)

By default, the eight core honeypots run: SSH, TNET, FTP, RDP, SMB, SIP, HTTP, SMTP. Additional protocols — MQTT, NRED (Node-RED), and MODB (Modbus TCP) — are available but not enabled by default. You do not need to run all protocols; enable only the ones that make sense for your deployment.

To customise which protocols run, set `ENABLED_PROTOCOLS` in `.env`:

```bash
# Run a subset of the defaults:
ENABLED_PROTOCOLS=SSH,TNET,FTP,SMB,SIP,HTTP,SMTP

# Add optional protocols:
ENABLED_PROTOCOLS=SSH,TNET,FTP,RDP,SMB,SIP,HTTP,SMTP,MQTT,NRED,MODB
```

**Docker:** also remove the corresponding port from `docker-compose.override.yml` — Docker binds ports regardless of which honeypots are running.

### Enabling HTTPS

Place your SSL certificate and private key in the `certs/` directory:
```
certs/cert.pem   # Certificate or fullchain
certs/key.pem    # Private key
```

**Docker and Systemd:** Add to `.env`:
```
ENABLE_SSL=true
# Optional — defaults to certs/key.pem and certs/cert.pem
# KNOCK_KEYFILE=certs/key.pem
# KNOCK_CERTFILE=certs/cert.pem
```

Then restart:
```bash
# Docker
docker compose up -d

# Systemd
systemctl restart knock-web
```

### Visitor Logging (`LOG_VISITORS`)

Disabled by default. Set `LOG_VISITORS=true` in `.env` to log dashboard visitors (IP, geolocation, referrer, user agent) to `data/visitors.db`. Note that storing visitor IPs may have privacy implications depending on your jurisdiction — see `extras/visitor-logging/` for reporting tools and details.

### IP Blocklist

To immediately reject connections from specific IPs, add them to `data/blocklist.txt` (one per line). The file is loaded into Redis at monitor startup; to apply changes while running, restart `knock-monitor`. Lines starting with `#` are ignored.

### Hiding Your Server IP

By default the web dashboard is publicly accessible on port 8080. This is fine for most deployments — there is nothing sensitive in the dashboard and no authentication to bypass.

If you want to hide your server's real IP address (so bots can't correlate the honeypot with your dashboard domain, or bypass Cloudflare to hammer the dashboard directly), see `extras/cloudflare-ufw/README.md` for a complete guide to:

- Restricting dashboard access to Cloudflare proxy IPs only
- Using a Cloudflare Origin Rule to keep visitors on standard ports (80/443)
- Docker-specific setup using nginx to enforce IP restrictions

### Multi-Server / Aggregator Mode

Knock-Knock supports multiple honeypot servers forwarding all knocks to a single aggregator for a unified dashboard. Feeder servers run the honeypots; the aggregator receives their knock streams, enriches with GeoIP, writes to its database, and serves the combined view. Each knock is tagged with a `SOURCE_ID` identifying which server captured it.

**Aggregator** — set in `.env`:
```bash
INGEST_PORT=9999   # TCP port to receive knock streams
SOURCE_ID=agg1
```

Restrict the ingest port to feeder IPs only — it must not be open to the internet:
```bash
ufw allow from <feeder-ip-1> to any port 9999/tcp
ufw allow from <feeder-ip-2> to any port 9999/tcp
```

**Each feeder** — set in `.env`:
```bash
AGGREGATOR_HOST=your-aggregator-ip-or-hostname
AGGREGATOR_PORT=9999   # default 9999
SOURCE_ID=nyc1         # unique name shown in the dashboard
```

Restart `knock-monitor` on all servers after making changes.

---

## Troubleshooting

### Port 22 already in use
```bash
ss -tlnp | grep :22
# Make sure real SSH is moved to another port first
```

### GeoIP lookups returning Unknown (Docker)
```bash
docker compose logs honeypot-monitor | grep -i geoip
# Should show "✅ GeoIP databases loaded"
# If stuck on "⏳ Waiting...", check geoipupdate logs:
docker compose logs geoipupdate
# Verify credentials in .env are correct
```

### GeoIP lookups failing (Systemd)
```bash
ls -la /usr/share/GeoIP/GeoLite2-*.mmdb
# If missing, ensure /etc/GeoIP.conf includes: DatabaseDirectory /usr/share/GeoIP
# Then re-run: geoipupdate
```

### Redis connection errors
```bash
redis-cli ping   # Should return PONG
systemctl status redis-server   # or: systemctl status redis
```

### WebSocket not connecting
- Check browser console for errors
- Verify SSL certificates are valid
- Check if behind reverse proxy (Cloudflare, nginx) - may need WebSocket passthrough config

### View database contents
```bash
sqlite3 /root/knock-knock/data/knock_knock.db "SELECT * FROM knocks_ssh ORDER BY id DESC LIMIT 5;"
# Default per-protocol tables: knocks_ssh, knocks_tnet, knocks_ftp, knocks_rdp, knocks_smb, knocks_sip, knocks_http, knocks_smtp
# Optional protocol tables (if enabled): knocks_mqtt, knocks_nred, knocks_modb
```

### Database errors after upgrading

If the monitor logs errors about missing columns after a `git pull`, run the migration script before restarting:

```bash
source .venv/bin/activate
python extras/db-migrations/updatedb.py
./restart.sh
```

## Maintenance

```bash
# Restart all services (systemd)
./restart.sh

# Reset all data (clear database and Redis)
./restart.sh --reset-all

# Update GeoIP databases (systemd only — Docker handles this automatically)
geoipupdate

# Rotate SSL certs (if using Let's Encrypt)
certbot renew
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /root/knock-knock/certs/key.pem
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /root/knock-knock/certs/cert.pem
systemctl restart knock-web   # or: docker compose restart web
```

### Upgrading

After pulling new code with `git pull`, update dependencies and apply any database schema changes before restarting:

```bash
# Systemd
source .venv/bin/activate
uv pip install -r requirements.txt
python extras/db-migrations/updatedb.py
./restart.sh

# Docker
docker compose exec honeypot-monitor python extras/db-migrations/updatedb.py
docker compose restart
```

`updatedb.py` automatically backs up the database before making changes (timestamped file in `data/`). Options:

```bash
python extras/db-migrations/updatedb.py --no-backup          # skip backup
python extras/db-migrations/updatedb.py --backup mybackup.db # custom backup name
python extras/db-migrations/updatedb.py --no-smtp-backfill   # schema only, skip the SMTP body backfill
python extras/db-migrations/updatedb.py --keep-body-column   # keep the now-empty knocks_smtp.body column
```

It is safe to run multiple times — all operations are idempotent.

**Multi-server aggregators running SMTP** need one additional one-time step after `updatedb.py` — see [Upgrading a multi-server aggregator](extras/db-migrations/README.md#upgrading-a-multi-server-aggregator). A single-server honeypot needs nothing extra.

## Testing

The repository includes two test suites:

**Unit tests** — pure function tests with no network or database dependencies. These run in CI before every Docker image build.

```bash
.venv/bin/pip3 install pytest
python -m pytest tests/test_unit.py -v
```

**Integration tests** — start each honeypot on a high port, send a real credential attempt, and verify a knock is logged. Run locally only (CI runners block arbitrary port binding).

```bash
.venv/bin/pip3 install pytest
python -m pytest tests/test_honeypot_knocks.py -v
```

Run both suites together locally:

```bash
python -m pytest tests/ -v
```

## Security Notes

- The honeypot runs as root to bind port 22 - this is intentional
- Never expose the SQLite database or Redis to the network
- Keep your real SSH on a non-standard port
- Consider IP blocklisting repeat offenders via `data/blocklist.txt`
- The honeypot always rejects authentication - no shell access is ever granted


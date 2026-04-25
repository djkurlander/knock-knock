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

# Honeypot ports (enable as needed — these should be open to everyone)
ufw allow 21/tcp     # FTP
ufw allow 22/tcp     # SSH honeypot
ufw allow 23/tcp     # Telnet
ufw allow 25/tcp     # SMTP
ufw allow 80/tcp     # HTTP
ufw allow 445/tcp    # SMB
ufw allow 587/tcp    # SMTP (submission)
ufw allow 3389/tcp   # RDP
ufw allow 5060       # SIP (TCP + UDP)

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
uv pip install asyncssh==2.22.0 geoip2 redis fastapi uvicorn[standard] python-dotenv impacket phonenumbers
```

### Install Systemd Services

Sample unit files are in the `systemd/` directory:

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
uv pip install asyncssh==2.22.0 geoip2 redis fastapi uvicorn[standard] python-dotenv impacket phonenumbers
```

### Install Systemd Services

Sample unit files are in the `systemd/` directory. The Redis service name may differ on RHEL-based systems:

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

### Saving Individual Knocks (`--save-knocks`)

By default, the monitor only updates aggregated intel tables (top usernames, passwords, countries, ISPs, IPs). To also store every individual knock in per-protocol SQLite tables for later analysis, enable the `--save-knocks` flag. This uses more disk space (~600 MB/year at typical traffic levels).

To save only specific protocols, pass a comma-separated list: `--save-knocks=SIP,SMTP`. Only the specified protocols will get knock tables created.

**Docker:** Copy the example override file and uncomment the `--save-knocks` command:
```bash
cp docker-compose.override.yml.example docker-compose.override.yml
# Edit docker-compose.override.yml and uncomment the honeypot-monitor command
docker compose up -d
```

**Systemd:** Append `--save-knocks` to the `ExecStart` line in `/etc/systemd/system/knock-monitor.service`, then reload:
```bash
systemctl daemon-reload
systemctl restart knock-monitor
```

### Selecting Protocols (`ENABLED_PROTOCOLS`)

By default, all honeypots run (SSH, TNET, FTP, RDP, SMB, SIP, HTTP, SMTP). To run only specific protocols, set the `ENABLED_PROTOCOLS` environment variable to a comma-separated list.

**Docker:** Copy the example override file (if you haven't already) and uncomment the `ENABLED_PROTOCOLS` setting:
```bash
cp docker-compose.override.yml.example docker-compose.override.yml
# Edit docker-compose.override.yml and uncomment/edit the ENABLED_PROTOCOLS line
docker compose up -d
```

**Systemd:** Uncomment and edit the `Environment=ENABLED_PROTOCOLS=` line in `/etc/systemd/system/knock-monitor.service`, then reload:
```bash
systemctl daemon-reload
systemctl restart knock-monitor
```

### Enabling HTTPS

Place your SSL certificate and private key in the `certs/` directory:
```
certs/cert.pem   # Certificate or fullchain
certs/key.pem    # Private key
```

**Docker:** Copy the example override file (if you haven't already) and uncomment the SSL settings:
```bash
cp docker-compose.override.yml.example docker-compose.override.yml
# Edit docker-compose.override.yml and uncomment ENABLE_SSL and the certs volume
docker compose up -d
```

**Systemd:** In `/etc/systemd/system/knock-web.service`, replace the HTTP `ExecStart` line with the commented-out HTTPS block, then reload:
```bash
systemctl daemon-reload
systemctl restart knock-web
```

### IP Blocklist

To immediately reject connections from specific IPs, add them to `data/blocklist.txt` (one per line). The file is loaded into Redis at monitor startup; to apply changes while running, restart `knock-monitor`. Lines starting with `#` are ignored.

### Hiding Your Server IP

By default the web dashboard is publicly accessible on port 8080. This is fine for most deployments — there is nothing sensitive in the dashboard and no authentication to bypass.

If you want to hide your server's real IP address (so bots can't correlate the honeypot with your dashboard domain, or bypass Cloudflare to hammer the dashboard directly), see `extras/cloudflare-ufw/README.md` for a complete guide to:

- Restricting dashboard access to Cloudflare proxy IPs only
- Using a Cloudflare Origin Rule to keep visitors on standard ports (80/443)
- Docker-specific setup using nginx to enforce IP restrictions

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
# Per-protocol tables: knocks_ssh, knocks_tnet, knocks_ftp, knocks_rdp, knocks_smb, knocks_sip, knocks_http, knocks_smtp
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

## Security Notes

- The honeypot runs as root to bind port 22 - this is intentional
- Never expose the SQLite database or Redis to the network
- Keep your real SSH on a non-standard port
- Consider IP blocklisting repeat offenders via `data/blocklist.txt`
- The honeypot always rejects authentication - no shell access is ever granted

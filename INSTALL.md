# Knock-Knock Installation Guide

Knock-Knock can be installed most simply and universally using Docker, but also can be configured to run without Docker on Ubuntu/Debian and RHEL/CentOS/Fedora systems. All of these setups require a few prerequisites.

## Prerequisites

All installation methods require:

- Server with root access
- Public IP address (for receiving SSH attacks)
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

### GeoIP Databases

Knock-Knock uses MaxMind GeoLite2 databases for IP geolocation. You need a free MaxMind account.

1. Create account at https://www.maxmind.com/en/geolite2/signup
2. Generate a license key in your account dashboard, download the config file, and save it as /etc/GeoIP.conf on your server.
3. Install and configure geoipupdate:

**Debian/Ubuntu:**
```bash
apt install -y geoipupdate
```

**RHEL/CentOS/Fedora:**
```bash
dnf install -y geoipupdate
```

Then download the databases:
```bash
# Edit /etc/GeoIP.conf and set your AccountID and LicenseKey
# Then:
geoipupdate

# Ensure databases are at /usr/share/GeoIP (some distros use /var/lib/GeoIP)
[ ! -e /usr/share/GeoIP ] && ln -s /var/lib/GeoIP /usr/share/GeoIP

# Verify
ls /usr/share/GeoIP/GeoLite2-*.mmdb
```

Set up weekly auto-updates:
```bash
crontab -e
# Add line:
0 3 * * 3 /usr/bin/geoipupdate
```

### SSH Host Key

The honeypot needs an RSA key to present to connecting clients. Generate this after cloning the repo:

```bash
cd /root/knock-knock
ssh-keygen -t rsa -b 2048 -f server.key -N ""
rm server.key.pub
chmod 600 server.key
```

### SSL Certificates (Optional)

The web dashboard runs over HTTP by default. Skip this section if you don't need HTTPS.

If you want HTTPS, place your certificate and key at `certs/key.pem` and `certs/cert.pem`. Any certificate provider works — just copy the files into place. Two common options:

**Self-Signed (testing/LAN):**
```bash
mkdir -p /root/knock-knock/certs
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /root/knock-knock/certs/key.pem \
    -out /root/knock-knock/certs/cert.pem \
    -days 365 \
    -subj "/CN=localhost"
chmod 600 /root/knock-knock/certs/*.pem
```

**Let's Encrypt (free, auto-renewing):**
```bash
apt install -y certbot   # or: dnf install -y certbot
certbot certonly --standalone -d your-domain.com

mkdir -p /root/knock-knock/certs
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /root/knock-knock/certs/key.pem
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /root/knock-knock/certs/cert.pem
chmod 600 /root/knock-knock/certs/*.pem

systemctl enable certbot.timer
```

---

## Option 1: Docker (Simplest)

Complete the [Prerequisites](#prerequisites) above first.

**Install Docker (skip if already installed):**
```bash
curl -fsSL https://get.docker.com | sh
```

Then clone the repo:
```bash
cd /root
git clone https://github.com/djkurlander/knock-knock.git
cd knock-knock
```

Make sure `server.key` and GeoIP databases are in place (see Prerequisites), then:

```bash
# Build and start
docker compose up -d

# Verify
docker compose logs honeypot-monitor   # Should show "Monitor Active"
docker compose logs web                # Should show uvicorn startup
```

That's it. Three containers (Redis, honeypot+monitor, web) start automatically and restart on failure.

**Useful commands:**
```bash
docker compose logs -f              # Follow all logs
docker compose restart              # Restart all services
docker compose down                 # Stop everything
docker compose up -d --build        # Rebuild after code changes
```

To save individual knock records to SQLite (uses more disk, see Option 2 notes), edit `docker-compose.yml` and add `--save-knocks` to the honeypot-monitor command.

**Enabling SSL (HTTPS):** Uncomment `ENABLE_SSL=true`, swap the port mapping from `80:80` to `443:443`, and uncomment the `certs` volume in `docker-compose.yml`. Requires SSL certificates in `certs/` (see Prerequisites).

---

## Option 2: Ubuntu/Debian

Complete the [Prerequisites](#prerequisites) above first.

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
uv pip install paramiko geoip2 redis fastapi uvicorn[standard] python-dotenv
```

### Install Systemd Services

Sample unit files are in the `systemd/` directory:

```bash
cp systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable knock-monitor knock-web
systemctl start knock-monitor knock-web
```

By default the monitor does not save individual knock records to SQLite (only aggregated intel tables are updated). To store every knock for research queries, add `--save-knocks` to the `ExecStart` line in `knock-monitor.service`. This will use significantly more disk space (~600MB+/year).

**Enabling SSL (HTTPS):** Swap the commented-out HTTPS `ExecStart` block in `knock-web.service` for the HTTP one. Requires SSL certificates in `certs/` (see Prerequisites).

### Firewall

```bash
ufw allow 22/tcp     # Honeypot
ufw allow 80/tcp     # Dashboard (or 443/tcp if using HTTPS)
ufw allow 2222/tcp   # Your real SSH
ufw enable
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

---

## Option 3: RHEL/CentOS/Fedora

Complete the [Prerequisites](#prerequisites) above first.

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
uv pip install paramiko geoip2 redis fastapi uvicorn[standard] python-dotenv
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

By default the monitor does not save individual knock records to SQLite (only aggregated intel tables are updated). To store every knock for research queries, add `--save-knocks` to the `ExecStart` line in `knock-monitor.service`. This will use significantly more disk space (~600MB+/year).

**Enabling SSL (HTTPS):** Swap the commented-out HTTPS `ExecStart` block in `knock-web.service` for the HTTP one. Requires SSL certificates in `certs/` (see Prerequisites).

### Firewall

```bash
firewall-cmd --permanent --add-port=22/tcp     # Honeypot
firewall-cmd --permanent --add-port=80/tcp     # Dashboard (or 443/tcp if using HTTPS)
firewall-cmd --permanent --add-port=2222/tcp   # Your real SSH
firewall-cmd --reload
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

---

## Troubleshooting

### Port 22 already in use
```bash
ss -tlnp | grep :22
# Make sure real SSH is moved to another port first
```

### GeoIP lookups failing
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
sqlite3 /root/knock-knock/data/knock_knock.db "SELECT * FROM knocks ORDER BY id DESC LIMIT 5;"
```

## Maintenance

```bash
# Restart all services (systemd)
./restart.sh

# Reset all data (clear database and Redis)
./restart.sh --reset-all

# Update GeoIP databases
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

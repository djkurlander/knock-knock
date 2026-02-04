# Knock-Knock Installation Guide

This guide walks through installing Knock-Knock on a fresh Linux server (Debian/Ubuntu-based).

## Prerequisites

- Linux server with root access
- Public IP address (for receiving SSH attacks)
- Domain name (optional, for valid SSL)

## 1. System Dependencies

```bash
# Update package lists
apt update

# Install Redis
apt install -y redis-server
systemctl enable redis-server
systemctl start redis-server

# Install Python 3.12+ and uv
apt install -y python3.12 python3.12-venv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

## 2. GeoIP Databases

Knock-Knock uses MaxMind GeoLite2 databases for IP geolocation. You'll need a free MaxMind account.

1. Create account at https://www.maxmind.com/en/geolite2/signup
2. Generate a license key in your account dashboard
3. Install and configure geoipupdate:

```bash
apt install -y geoipupdate

# Edit /etc/GeoIP.conf with your credentials:
cat > /etc/GeoIP.conf << 'EOF'
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /usr/share/GeoIP
EOF

# Download databases
geoipupdate

# Verify installation
ls -la /usr/share/GeoIP/
# Should show: GeoLite2-City.mmdb, GeoLite2-ASN.mmdb
```

Set up automatic updates (databases update weekly):
```bash
# Add to root crontab
crontab -e
# Add line:
0 3 * * 3 /usr/bin/geoipupdate
```

## 3. Clone and Setup Project

```bash
cd /root
git clone https://github.com/YOUR_USERNAME/knock-knock.git
cd knock-knock

# Create virtual environment with uv
uv venv

# Activate and install dependencies
source .venv/bin/activate
uv pip install paramiko geoip2 redis fastapi uvicorn[standard] python-dotenv
```

## 4. Generate SSH Host Key

The honeypot needs an RSA key to present to connecting clients:

```bash
cd /root/knock-knock
ssh-keygen -t rsa -b 2048 -f server.key -N ""
# This creates server.key (private) and server.key.pub (public)
# Only server.key is needed
rm server.key.pub
chmod 600 server.key
```

## 5. SSL Certificates

The web dashboard requires HTTPS. Choose one option:

### Option A: Self-Signed (Testing)
```bash
mkdir -p /root/knock-knock/certs
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /root/knock-knock/certs/key.pem \
    -out /root/knock-knock/certs/cert.pem \
    -days 365 \
    -subj "/CN=localhost"
chmod 600 /root/knock-knock/certs/*.pem
```

### Option B: Let's Encrypt (Production)
```bash
apt install -y certbot

# Stop any service on port 80 temporarily
certbot certonly --standalone -d your-domain.com

# Copy/link certs
mkdir -p /root/knock-knock/certs
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /root/knock-knock/certs/key.pem
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /root/knock-knock/certs/cert.pem
chmod 600 /root/knock-knock/certs/*.pem

# Set up auto-renewal
systemctl enable certbot.timer
```

## 6. Move Real SSH to Different Port

**Critical**: The honeypot must bind to port 22. Move your real SSH first or you'll lock yourself out.

```bash
# Edit SSH config
nano /etc/ssh/sshd_config
# Change: Port 22
# To:     Port 2222   (or any unused port)

# Restart SSH (do this in a screen/tmux session or have console access)
systemctl restart sshd

# Test new port before disconnecting
ssh -p 2222 user@your-server

# Update firewall if applicable
ufw allow 2222/tcp
```

## 7. Create Systemd Services

Create three service files:

### /etc/systemd/system/knock-honeypot.service
```ini
[Unit]
Description=SSH Honeypot Decoy Service
After=network.target

[Service]
WorkingDirectory=/root/knock-knock
ExecStart=/root/knock-knock/.venv/bin/python honeypot.py
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

### /etc/systemd/system/knock-monitor.service
```ini
[Unit]
Description=Knock-Knock SSH Log Monitor
After=network.target redis-server.service

[Service]
User=root
WorkingDirectory=/root/knock-knock
ExecStart=/root/knock-knock/.venv/bin/python monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### /etc/systemd/system/knock-web.service
```ini
[Unit]
Description=Knock-Knock FastAPI Web Server
After=network.target redis-server.service knock-monitor.service

[Service]
User=root
WorkingDirectory=/root/knock-knock
ExecStart=/root/knock-knock/.venv/bin/python3 -m uvicorn main:app \
    --host 0.0.0.0 \
    --port 443 \
    --ssl-keyfile /root/knock-knock/certs/key.pem \
    --ssl-certfile /root/knock-knock/certs/cert.pem \
    --proxy-headers \
    --forwarded-allow-ips='*' \
    --workers 2 \
    --timeout-keep-alive 30 \
    --log-level warning
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start services:
```bash
systemctl daemon-reload
systemctl enable knock-honeypot knock-monitor knock-web
systemctl start knock-honeypot knock-monitor knock-web
```

## 8. Firewall Configuration

```bash
# Allow honeypot SSH
ufw allow 22/tcp

# Allow HTTPS dashboard
ufw allow 443/tcp

# Ensure your real SSH port is allowed
ufw allow 2222/tcp

# Enable firewall
ufw enable
```

## 9. Verify Installation

```bash
# Check all services are running
systemctl status knock-honeypot knock-monitor knock-web

# Check logs
journalctl -u knock-honeypot -f   # Should show "Honeypot Active"
journalctl -u knock-monitor -f    # Should show "Monitor Active"
journalctl -u knock-web -f        # Should show uvicorn startup

# Test honeypot (from another machine)
ssh test@your-server-ip
# Should reject auth but honeypot logs the attempt

# View dashboard
# Open https://your-server-ip in browser
```

## 10. Optional: Email Reports

To receive daily attack reports, configure SMTP:

```bash
cp .env.example .env
nano .env
# Fill in your SMTP credentials
```

## Troubleshooting

### Port 22 already in use
```bash
# Find what's using port 22
ss -tlnp | grep :22
# Make sure real SSH is moved to another port first
```

### GeoIP lookups failing
```bash
# Verify databases exist
ls -la /usr/share/GeoIP/GeoLite2-*.mmdb
# Re-run geoipupdate if missing
```

### Redis connection errors
```bash
redis-cli ping   # Should return PONG
systemctl status redis-server
```

### WebSocket not connecting
- Check browser console for errors
- Verify SSL certificates are valid
- Check if behind reverse proxy (Cloudflare, nginx) - may need WebSocket passthrough config

### View database contents
```bash
sqlite3 /root/knock-knock/knock_knock.db "SELECT * FROM knocks ORDER BY id DESC LIMIT 5;"
```

## Maintenance

```bash
# Restart all services
./restart.sh

# Reset all data (clear database and Redis)
./restart.sh --reset-all

# Update GeoIP databases
geoipupdate

# Rotate SSL certs (if using Let's Encrypt)
certbot renew
cp /etc/letsencrypt/live/your-domain.com/privkey.pem /root/knock-knock/certs/key.pem
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /root/knock-knock/certs/cert.pem
systemctl restart knock-web
```

## Security Notes

- The honeypot runs as root to bind port 22 - this is intentional
- Never expose the SQLite database or Redis to the network
- Keep your real SSH on a non-standard port
- Consider IP blocklisting repeat offenders via `blocklist.txt`
- The honeypot always rejects authentication - no shell access is ever granted

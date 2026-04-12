# Hiding Your Server IP with Cloudflare

This guide is **optional**. By default, Knock-Knock's web dashboard runs on port 8080 and is accessible to anyone who knows your server's IP. That's fine for most deployments.

If you want to hide your server's real IP — so your dashboard is only reachable through Cloudflare's proxy and bots can't reach it directly — follow this guide.

## Why bother?

- Bots that discover your origin IP can bypass Cloudflare and hit the dashboard directly
- More importantly, they can correlate the IP with the honeypot and know it's a trap
- Cloudflare also gives you DDoS protection, caching, and HTTPS for free

## Prerequisites

- Cloudflare account (free tier is fine) with your domain pointed at your server
- DNS record for your domain set to **proxied** (orange cloud icon)
- SSL mode set to **Full (strict)** in Cloudflare SSL/TLS settings
- A Cloudflare **Origin CA certificate** in `certs/cert.pem` and `certs/key.pem`
  (Generate one in Cloudflare dashboard → SSL/TLS → Origin Server)

## Overview

The approach:
1. Web dashboard runs on port 8080 (not 80 or 443)
2. A **Cloudflare Origin Rule** forwards visitor traffic (443) → your server's port 8080
3. UFW restricts port 8080 to Cloudflare IP ranges only — direct access is blocked
4. Visitors always see standard HTTPS — they never know about port 8080

Port 80 remains open to everyone as a honeypot port (HTTP honeypot captures web scanners).

---

## Setup

### 1. Cloudflare Origin Rule

In the Cloudflare dashboard for your domain:

- **Rules** → **Origin Rules** → **Add Rule** (Custom)
- Name: anything (e.g. "Route to port 8080")
- Match: **All incoming requests** (leave as default — no custom expression needed)
- Action: **Rewrite** → Destination Port → `8080`
- Save

This applies to all proxied traffic for this domain, including WebSocket connections.

### 2. Enable HTTPS on the web UI

Place your Cloudflare Origin CA certificate in the `certs/` directory:
```
certs/cert.pem   # Origin CA certificate
certs/key.pem    # Private key
```

**Systemd:** In `/etc/systemd/system/knock-web.service`, enable the HTTPS `ExecStart` block (swap the commented and uncommented versions), then:
```bash
systemctl daemon-reload && systemctl restart knock-web
```

**Docker:** See the Docker section below.

### 3. UFW — restrict port 8080 to Cloudflare IPs

```bash
ufw default deny incoming
ufw default allow outgoing

# Honeypot ports — open to all (intentional)
ufw allow 22/tcp    # SSH honeypot
ufw allow 23/tcp    # Telnet
ufw allow 21/tcp    # FTP
ufw allow 25/tcp    # SMTP
ufw allow 80/tcp    # HTTP honeypot
ufw allow 445/tcp   # SMB
ufw allow 587/tcp   # SMTP submission
ufw allow 3389/tcp  # RDP
ufw allow 5060      # SIP

# Your real SSH port
ufw allow 2222/tcp  # replace with your actual port

# Port 8080 (web dashboard) — Cloudflare IPs only
for cidr in $(curl -sf https://www.cloudflare.com/ips-v4) $(curl -sf https://www.cloudflare.com/ips-v6); do
    ufw allow from "$cidr" to any port 8080 proto tcp comment "Cloudflare"
done

ufw enable
```

### 4. Keep Cloudflare IPs up to date (cron)

Cloudflare occasionally adds or removes IP ranges. The included script fetches the latest and syncs UFW rules:

```bash
chmod +x extras/cloudflare-ufw/update-cloudflare-ufw.sh

crontab -e
# Add:
0 4 * * * /bin/bash /root/knock-knock/extras/cloudflare-ufw/update-cloudflare-ufw.sh >> /var/log/cloudflare-ufw.log 2>&1
```

### 5. Verify

```bash
# Direct access to your server IP should be blocked
curl -k https://YOUR_SERVER_IP:8080 --max-time 5
# Expected: connection refused or timeout

# Access via Cloudflare domain should work
curl https://your-domain.com
```

---

## Docker: nginx reverse proxy

**Docker bypasses UFW** by inserting its own iptables rules — so UFW alone can't restrict Docker-published ports. The solution is to put **nginx** in front of the web container, since nginx is a host process that UFW can control.

### Architecture

```
Cloudflare (443) → Origin Rule → server:8080 (nginx, host process, UFW-restricted)
                                      ↓
                               127.0.0.1:8081 (web container, localhost only)
```

### 1. Create a `.env` file

Docker Compose reads this for port binding variable substitution:

```bash
cat >> /root/knock-knock/.env << 'EOF'
WEB_PORT=8081
WEB_LISTEN=127.0.0.1
EOF
```

This binds the web container to `127.0.0.1:8081` — unreachable from outside, accessible to nginx on the host.

### 2. Update `docker-compose.override.yml`

Add to your override (create from `.example` if needed):

```yaml
  web:
    environment:
      - ENABLE_SSL=true
      - WEB_PORT=8081
    volumes:
      - ./certs:/app/certs:ro
```

### 3. Install and configure nginx

```bash
apt install -y nginx
```

Create `/etc/nginx/sites-available/knock-knock`:

```nginx
server {
    listen 8080 ssl;
    server_name YOUR_DOMAIN;

    ssl_certificate     /root/knock-knock/certs/cert.pem;
    ssl_certificate_key /root/knock-knock/certs/key.pem;

    include /etc/nginx/cloudflare_ips.conf;

    location / {
        proxy_pass https://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_ssl_verify off;
    }
}
```

Enable it:
```bash
ln -s /etc/nginx/sites-available/knock-knock /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
```

### 4. Generate the Cloudflare IP include file

```bash
NGINX_IP_INCLUDE=/etc/nginx/cloudflare_ips.conf \
    bash extras/cloudflare-ufw/update-cloudflare-ufw.sh

nginx -t && systemctl enable nginx && systemctl start nginx
```

### 5. Start Docker

```bash
docker compose down && docker compose up -d
```

### 6. Keep the nginx IP list up to date (cron)

```bash
crontab -e
# Add (note the NGINX_IP_INCLUDE variable):
0 4 * * * NGINX_IP_INCLUDE=/etc/nginx/cloudflare_ips.conf /bin/bash /root/knock-knock/extras/cloudflare-ufw/update-cloudflare-ufw.sh >> /var/log/cloudflare-ufw.log 2>&1
```

The script reloads nginx automatically after updating the IP list (`nginx -t && systemctl reload nginx`).

---

## Notes

- Redis (port 6379) listens on localhost only — no firewall rule needed
- The update script logs to `/var/log/cloudflare-ufw.log`
- On systemd servers, UFW handles port 8080 restriction directly (no nginx needed)
- On Docker servers, nginx handles the restriction since Docker bypasses UFW
- WebSocket connections (`wss://`) work through the Cloudflare Origin Rule automatically

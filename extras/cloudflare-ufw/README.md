# Cloudflare UFW Setup for Knock-Knock

## Why?

If your Knock-Knock dashboard is served through Cloudflare, you want to hide your server's real IP address. Bots that discover the origin IP can bypass Cloudflare and access the web server directly — or worse, correlate the IP with the honeypot.

This guide sets up UFW (Uncomplicated Firewall) so that only Cloudflare's proxy servers can reach your web port, while the honeypot and your real SSH port remain accessible.

## Prerequisites

- Cloudflare DNS proxying enabled for your domain (orange cloud icon)
- Your real SSH port (not port 22, which the honeypot uses)

## Setup

### 1. Install and enable UFW

```bash
apt install ufw
```

### 2. Set default policy

```bash
ufw default deny incoming
ufw default allow outgoing
```

### 3. Allow required ports

```bash
# Honeypot SSH (public — this is the whole point)
ufw allow 22/tcp

# Your real SSH port (replace 20791 with yours)
ufw allow 20791/tcp

# Web port from Cloudflare IPs only
for cidr in $(curl -sf https://www.cloudflare.com/ips-v4) $(curl -sf https://www.cloudflare.com/ips-v6); do
    ufw allow from "$cidr" to any port 443 proto tcp comment "Cloudflare"
done
```

If you serve HTTP instead of HTTPS, replace `443` with `80`.

### 4. Enable UFW

```bash
ufw enable
```

Verify with `ufw status`. You should see your SSH port, port 22, and ~22 Cloudflare CIDR rules for port 443.

### 5. Daily Cloudflare IP updates (cron)

Cloudflare occasionally adds or removes IP ranges. The included `update-cloudflare-ufw.sh` script fetches the latest ranges and syncs UFW rules accordingly — adding new ones and removing stale ones.

```bash
# Make it executable
chmod +x extras/cloudflare-ufw/update-cloudflare-ufw.sh

# Add to root's crontab (runs daily at 4am)
crontab -e
```

Add this line:

```
0 4 * * * /bin/bash /path/to/knock-knock/extras/cloudflare-ufw/update-cloudflare-ufw.sh >> /var/log/cloudflare-ufw.log 2>&1
```

### 6. Update main.py for real client IPs

Behind Cloudflare, `websocket.client.host` will be a Cloudflare proxy IP, not the visitor's real IP. The main project's `main.py` includes a `get_client_ip()` helper that checks headers in this order:

1. `CF-Connecting-IP` (Cloudflare's real client IP header)
2. `X-Forwarded-For` (first entry)
3. Direct connection IP (fallback for non-Cloudflare setups)

No extra configuration needed — it works automatically whether or not you use Cloudflare.

## Verification

```bash
# Confirm UFW is active
ufw status

# Test: direct HTTPS to your server IP should be refused
curl -k https://YOUR_SERVER_IP --max-time 5
# Expected: connection refused or timeout

# Test: access via your Cloudflare domain should work
curl -k https://your-domain.com
# Expected: normal page response
```

## Notes

- Redis (port 6379) listens on localhost only by default — no UFW rule needed
- If you add other services later, remember to open their ports in UFW
- The update script logs to `/var/log/cloudflare-ufw.log` — check it if rules seem wrong

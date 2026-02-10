# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Knock-Knock is an SSH honeypot monitoring system that captures unauthorized SSH login attempts and displays real-time attack data through a live web dashboard. It can be deployed via Docker or as three coordinated systemd services.

## Commands

### Service Management (Production)
```bash
# Restart all services
./restart.sh

# Reset all data and restart
./restart.sh --reset-all

# Individual service control
systemctl start|stop|restart|status knock-honeypot knock-monitor knock-web

# Docker
docker compose up -d
docker compose down
docker compose logs -f
```

### Development (Direct Execution)
```bash
source .venv/bin/activate

# SSH honeypot (port 22)
python honeypot.py

# Log monitor + geo-enricher (add --save-knocks to store individual knocks in SQLite)
python monitor.py

# Log monitor reading from stdin (Docker mode)
python honeypot.py 2>&1 | python monitor.py --stdin

# Web server (HTTP, port 80)
python3 -m uvicorn main:app --host 0.0.0.0 --port 80 \
  --proxy-headers --forwarded-allow-ips='*' --workers 2

# Web server (HTTPS, port 443)
python3 -m uvicorn main:app --host 0.0.0.0 --port 443 \
  --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem \
  --proxy-headers --forwarded-allow-ips='*' --workers 2
```

### Debugging
```bash
# Service logs
journalctl -u knock-honeypot -f
journalctl -u knock-monitor -f
journalctl -u knock-web -f

# Database queries
sqlite3 data/knock_knock.db "SELECT * FROM knocks ORDER BY id DESC LIMIT 10;"

# Redis connectivity
redis-cli ping
```

## Architecture

```
SSH Attacker → honeypot.py (port 22) → stdout / journalctl logs
                                              ↓
                                       monitor.py (parses logs, GeoIP lookup)
                                              ↓
                                    SQLite DB (data/) + Redis pub/sub
                                              ↓
                                       main.py (FastAPI, port 80/443)
                                              ↓
                                    Browser WebSocket → Live Dashboard
```

**Three Services:**
- `honeypot.py`: Paramiko SSH server that accepts connections, logs credentials, always rejects auth
- `monitor.py`: Tails journalctl (or reads stdin with `--stdin`) for `[*] KNOCK |` events, performs GeoIP lookups, updates intel tables in SQLite, publishes to Redis. Individual knocks are only saved to SQLite with `--save-knocks`
- `main.py`: FastAPI server with WebSocket endpoint `/ws`, subscribes to Redis, broadcasts to all connected browsers

**Data Flow:**
- Inter-service communication via Redis pub/sub channel `radiation_stream`
- Stats cached in memory (10-min refresh), periodic sync every 60 seconds
- SQLite databases in `data/` directory for persistence

**Deployment modes:**
- **Docker:** `docker compose up -d` — honeypot stdout is piped to monitor via `--stdin`
- **Systemd:** Three unit files in `systemd/` — monitor tails journalctl

## Key Files

| File | Purpose |
|------|---------|
| `honeypot.py` | SSH honeypot with `SSHHoneypot` class |
| `monitor.py` | Log parser, GeoIP enrichment, DB writes, Redis publish |
| `main.py` | FastAPI server, `ConnectionManager`, `GlobalStatsCache`, WebSocket |
| `index.html` | Single-page dashboard with WebSocket client |
| `restart.sh` | Systemd service orchestration |
| `Dockerfile` | Single image for honeypot-monitor and web containers |
| `docker-compose.yml` | Three-service Docker deployment |

## Data Directory

All persistent data lives in `data/`:
- `data/knock_knock.db` — main attack database
- `data/visitors.db` — dashboard visitor tracking
- `data/blocklist.txt` — IPs to reject immediately

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_HOST` | `localhost` | Redis server hostname (set to `redis` in Docker) |
| `DB_DIR` | `data` | Directory for SQLite databases and blocklist |
| `ENABLE_SSL` | unset | Set to `true` in Docker for HTTPS |
| `LOG_VISITORS` | unset | Set to `true` to log dashboard visitors to `visitors.db` |

## Database Schema

```sql
-- Main attack log (only populated with --save-knocks)
knocks(id, timestamp, ip_address, iso_code, city, country, isp, username, password)

-- Intelligence tables (aggregated counts with indexed hits for fast top-N queries)
user_intel(username PRIMARY KEY, hits, last_seen)     -- INDEX on hits DESC
pass_intel(password PRIMARY KEY, hits, last_seen)     -- INDEX on hits DESC
country_intel(iso_code PRIMARY KEY, country, hits, last_seen)  -- INDEX on hits DESC
isp_intel(isp PRIMARY KEY, hits, last_seen)           -- INDEX on hits DESC
ip_intel(ip PRIMARY KEY, hits, last_seen, lat, lng)   -- INDEX on hits DESC, stores coordinates

-- Uptime tracking for KPM calculation
monitor_heartbeats(id, timestamp)
```

Intel tables are updated on each knock via `INSERT ... ON CONFLICT DO UPDATE`. Top-N queries use the hits index (~100 rows) instead of GROUP BY on knocks (all rows).

## External Dependencies

- Redis server (localhost:6379 or via `REDIS_HOST` env var)
- GeoIP databases at `/usr/share/GeoIP/GeoLite2-{City,ASN}.mmdb`
- SSL certificates in `certs/` directory (optional, for HTTPS)
- Python 3.12 with `uv` virtual environment (systemd) or Docker

## Redis Keys

- `knock:total_global` - Total attack count
- `knock:last_time` - Unix timestamp of last knock
- `knock:last_lat` - Latitude of last knock location
- `knock:last_lng` - Longitude of last knock location
- `knock:recent` - Last 100 knocks (JSON list, used for initial page load)
- `radiation_stream` - Pub/sub channel for real-time events

## Frontend Features

- **3D Globe** (globe.gl): Displays attack location, rotates on new knocks
- **Live Feed**: Real-time attack log with username/password/location
- **Leaderboards**: Top countries, usernames, passwords, ISPs
- **Responsive**: Mobile carousel with swipe navigation, desktop grid layout
- **WebSocket**: Auto-reconnect, live updates without polling

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Knock-Knock is an SSH honeypot monitoring system that captures unauthorized SSH login attempts and displays real-time attack data through a live web dashboard. It runs as three coordinated systemd services.

## Commands

### Service Management (Production)
```bash
# Restart all services
./restart.sh

# Reset all data and restart
./restart.sh --reset-all

# Individual service control
systemctl start|stop|restart|status knock-honeypot knock-monitor knock-web
```

### Development (Direct Execution)
```bash
source .venv/bin/activate

# SSH honeypot (port 22)
python honeypot.py

# Log monitor + geo-enricher
python monitor.py

# Web server (port 443 with SSL)
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
sqlite3 knock_knock.db "SELECT * FROM knocks ORDER BY id DESC LIMIT 10;"

# Redis connectivity
redis-cli ping
```

## Architecture

```
SSH Attacker → honeypot.py (port 22) → journalctl logs
                                              ↓
                                       monitor.py (parses logs, GeoIP lookup)
                                              ↓
                                    SQLite DB + Redis pub/sub
                                              ↓
                                       main.py (FastAPI, port 443)
                                              ↓
                                    Browser WebSocket → Live Dashboard
```

**Three Services:**
- `honeypot.py`: Paramiko SSH server that accepts connections, logs credentials, always rejects auth
- `monitor.py`: Tails journalctl for `[*] KNOCK |` events, performs GeoIP lookups, stores in SQLite, publishes to Redis
- `main.py`: FastAPI server with WebSocket endpoint `/ws`, subscribes to Redis, broadcasts to all connected browsers

**Data Flow:**
- Inter-service communication via Redis pub/sub channel `radiation_stream`
- Stats cached in memory (10-min refresh), periodic sync every 60 seconds
- SQLite database `knock_knock.db` for persistence

## Key Files

| File | Purpose |
|------|---------|
| `honeypot.py` | SSH honeypot with `SSHHoneypot` class |
| `monitor.py` | Log parser, GeoIP enrichment, DB writes, Redis publish |
| `main.py` | FastAPI server, `ConnectionManager`, `GlobalStatsCache`, WebSocket |
| `index.html` | Single-page dashboard with WebSocket client |
| `restart.sh` | Systemd service orchestration |

## Database Schema

```sql
-- Main attack log
knocks(id, timestamp, ip_address, iso_code, city, country, isp, username, password)

-- Intelligence aggregation
user_intel(username, hits, last_seen)
pass_intel(password, hits, last_seen)

-- Uptime tracking for KPM calculation
monitor_heartbeats(id, timestamp)
```

## External Dependencies

- Redis server on localhost:6379
- GeoIP databases at `/usr/share/GeoIP/GeoLite2-{City,ASN}.mmdb`
- SSL certificates in `certs/` directory
- Python 3.12 with `uv` virtual environment

## Redis Keys

- `knock:total_global` - Total attack count
- `knock:wall_of_shame` - Sorted set of country attack counts
- `radiation_stream` - Pub/sub channel for real-time events

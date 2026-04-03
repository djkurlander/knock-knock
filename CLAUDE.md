# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Knock-Knock is a multi-protocol honeypot monitoring system that captures unauthorized login attempts on SSH (port 22), Telnet (port 23), and SMTP (port 587), and displays real-time attack data through a live web dashboard. It can be deployed via Docker or as two coordinated systemd services.

## Commands

### Service Management (Production)
```bash
# Restart all services
./restart.sh

# Reset all data and restart (blocklist is preserved)
./restart.sh --reset-all

# Reset blocklist only (deletes blocklist.txt + clears knock:blocked in Redis)
python monitor.py --reset-blocklist

# Individual service control
systemctl start|stop|restart|status knock-monitor knock-web

# Docker
docker compose up -d
docker compose down
docker compose logs -f
```

### Development (Direct Execution)
```bash
source .venv/bin/activate

# Individual honeypots (ports 22, 23, 587)
python ssh_honeypot.py
python telnet_honeypot.py
python smtp_honeypot.py

# Log monitor + geo-enricher — spawns all three honeypots as subprocesses
# Add --save-knocks to store individual knocks in SQLite (all protocols)
# Add --save-knocks=SIP,SMTP to store only specific protocols
python monitor.py

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
# Service logs (systemd)
journalctl -u knock-monitor -f
journalctl -u knock-web -f

# Service logs (Docker)
docker compose logs -f honeypot-monitor
docker compose logs -f web

# Database queries
sqlite3 data/knock_knock.db "SELECT * FROM knocks ORDER BY id DESC LIMIT 10;"

# Redis connectivity
redis-cli ping

# Check per-protocol feed lists
redis-cli llen knock:recent:ssh
redis-cli llen knock:recent:tnet
redis-cli llen knock:recent:smtp

# Watch for SMTP connections (even without AUTH — honeypot logs every connect)
journalctl -u knock-monitor -f | grep SMTP
```

## Architecture

```
SSH Attacker  → ssh_honeypot.py  (port 22)  ─┐
Telnet Attacker → telnet_honeypot.py (port 23) ─┼→ stdout → monitor.py
SMTP Attacker → smtp_honeypot.py (port 587) ─┘        (GeoIP, DB, Redis)
                                                              ↓
                                                  SQLite DB (data/) + Redis pub/sub
                                                              ↓
                                                   main.py (FastAPI, port 80/443)
                                                              ↓
                                               Browser WebSocket → Live Dashboard
```

**Two Services:**
- `monitor.py`: Spawns all three honeypots as subprocesses, merges their stdout via a shared `queue.Queue`, performs GeoIP lookups, updates SQLite intel tables, publishes to Redis. Individual knocks saved to per-protocol SQLite tables with `--save-knocks` (all) or `--save-knocks=SIP,SMTP` (selective). Honeypots check `knock:blocked` Redis set on each connection to reject blocked IPs instantly.
- `main.py`: FastAPI server with WebSocket endpoint `/ws`, subscribes to Redis, broadcasts to all connected browsers.

**Data Flow:**
- Monitor spawns honeypots as subprocesses and reads their stdout (both systemd and Docker)
- Each honeypot emits JSON: `{"type": "KNOCK", "proto": "SSH"|"TNET"|"SMTP", "ip": ..., "user": ..., "pass": ...}`
- Inter-service communication via Redis pub/sub channel `knocks_stream`
- Stats cached in memory, refreshed every 60 seconds and broadcast to all clients
- SQLite databases in `data/` directory for persistence

**Deployment modes:**
- **Docker:** `docker compose up -d` — monitor spawns all honeypots internally
- **Systemd:** Two unit files in `systemd/` — monitor spawns all honeypots internally

## Key Files

| File | Purpose |
|------|---------|
| `ssh_honeypot.py` | SSH honeypot (port 22) using paramiko |
| `telnet_honeypot.py` | Telnet honeypot (port 23), raw socket with IAC negotiation |
| `smtp_honeypot.py` | SMTP honeypot (port 587), AUTH LOGIN + AUTH PLAIN |
| `monitor.py` | Spawns honeypots, GeoIP enrichment, DB writes, Redis publish |
| `main.py` | FastAPI server, `ConnectionManager`, `GlobalStatsCache`, WebSocket |
| `constants.py` | Shared protocol enum: `PROTO` dict and `PROTO_NAME` reverse lookup |
| `index.html` | Single-page dashboard with WebSocket client |
| `restart.sh` | Service orchestration (systemd and Docker) |
| `Dockerfile` | Single image for honeypot-monitor and web containers |
| `docker-compose.yml` | Docker deployment (Redis, honeypot+monitor, web) |
| `stats.py` | CLI utility for printing database statistics |
| `dbtool.py` | DB management: `--list-tables`, `--backup`, `--remove-knocks` |
| `extras/` | Optional utilities (Cloudflare UFW rules, texture generation, visitor reports) |

## Data Directory

All persistent data lives in `data/`:
- `data/knock_knock.db` — main attack database
- `data/visitors.db` — dashboard visitor tracking
- `data/blocklist.txt` — IPs to reject immediately (durable source of truth; seeded into Redis on startup)

**Note:** `blocklist.txt` and `knock:blocked` survive `--reset-all` intentionally. Use `--reset-blocklist` to clear them.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_HOST` | `localhost` | Redis server hostname (set to `redis` in Docker) |
| `DB_DIR` | `data` | Directory for SQLite databases and blocklist |
| `ENABLE_SSL` | unset | Set to `true` in `docker-compose.yml` for HTTPS |
| `LOG_VISITORS` | unset | Set to `true` to log dashboard visitors to `visitors.db` |
| `SMTP_HOSTNAME` | reverse DNS | Override SMTP banner/cert hostname (default: reverse DNS of server IP) |

## Protocol Enum

Defined in `constants.py`, imported by both `monitor.py` and `main.py`:

```python
PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3}
PROTO_NAME = {v: k for k, v in PROTO.items()}
```

## Database Schema

```sql
-- Per-protocol knock tables (only populated with --save-knocks; only saved protocols get tables)
-- Common columns: id, timestamp, ip_address, iso_code, city, region, country, isp, asn
knocks_ssh(... username, password)
knocks_tnet(... username, password)
knocks_ftp(... username, password)
knocks_smtp(... username, password, smtp_stage, smtp_mail_from, smtp_rcpt_to, subject, body)
knocks_mail(... username, password, smtp_stage, smtp_mail_from, smtp_rcpt_to, subject, body)
knocks_sip(... sip_method, sip_dial_string, sip_dial_number, sip_call_id, sip_cseq, sip_extension, sip_dial_country, sip_dial_country_name, sip_dial_lat, sip_dial_lng)
knocks_smb(... username, smb_share, smb_version, smb_domain, smb_host)
knocks_rdp(... username, rdp_source, domain)

-- ALL intel tables (aggregated counts, indexed hits for fast top-N queries)
user_intel(username PRIMARY KEY, hits, last_seen)               -- INDEX on hits DESC
pass_intel(password PRIMARY KEY, hits, last_seen)               -- INDEX on hits DESC
country_intel(iso_code PRIMARY KEY, country, hits, last_seen)   -- INDEX on hits DESC
isp_intel(isp PRIMARY KEY, hits, last_seen, asn)                -- INDEX on hits DESC
ip_intel(ip PRIMARY KEY, hits, last_seen, lat, lng)             -- INDEX on hits DESC

-- Per-protocol intel tables (same structure, composite PK)
user_intel_proto(username, proto INTEGER, hits, last_seen)      -- INDEX on (proto, hits DESC)
pass_intel_proto(password, proto INTEGER, hits, last_seen)      -- INDEX on (proto, hits DESC)
country_intel_proto(iso_code, proto INTEGER, country, hits, last_seen)
isp_intel_proto(isp, proto INTEGER, hits, last_seen, asn)
ip_intel_proto(ip, proto INTEGER, hits, last_seen, lat, lng)

-- SIP toll fraud destination tracking (only created when SIP is enabled)
dial_intel(number TEXT PRIMARY KEY, hits, first_seen, last_seen, country, country_name, lat, lng)

-- Uptime tracking for KPM calculation
monitor_heartbeats(id, uptime_minutes)
```

Each knock writes 10 upserts: 5 to ALL tables + 5 to `_proto` tables. ALL tables serve as fast rollup for the ALL leaderboard; `_proto` tables serve per-protocol leaderboards.

## Redis Keys

- `knock:total_global` - Total attack count (all protocols)
- `knock:uptime_minutes` - Monitor uptime in minutes
- `knock:last_time` - Unix timestamp of last knock
- `knock:last_lat` - Latitude of last knock location
- `knock:last_lng` - Longitude of last knock location
- `knock:recent` - Last 100 knocks, all protocols (JSON list)
- `knock:recent:ssh` - Last 100 SSH knocks
- `knock:recent:tnet` - Last 100 Telnet knocks
- `knock:recent:smtp` - Last 100 SMTP knocks
- `knock:blocked` - Set of blocked IPs (seeded from `blocklist.txt` on startup; checked by honeypot on each connection)
- `knocks_stream` - Pub/sub channel for real-time events

## Globe Rendering Rules

The pane globes are paused when idle (`pauseAnimation()`). **Any change to globe scene state (polygon data, point data, styles) will NOT be visible until the animation loop runs a frame.** Always follow scene changes with:
```javascript
if (paneGlobeDesktop && paneGlobeVisible.desktop) paneGlobeDesktop.resumeAnimation();
if (paneGlobeMobile && paneGlobeVisible.mobile) paneGlobeMobile.resumeAnimation();
schedulePaneGlobePause();
```
`refreshHeatGlobe()` and `applyGlobeStyle()` already do this. Any new function that modifies pane globe state must too.

Additionally, `polygonsData(sameRef)` may be short-circuited by globe.gl — always pass `[...countriesData]` to guarantee the polygon digest runs and accessor functions are re-evaluated.

**Polygon stroke alpha bug (globe.gl):** Three.js `LineSegments` materials are created with `transparent: false` when the first stroke color is a fully opaque hex value (e.g. `#00ff41`). If a later style switch changes the stroke accessor to an `rgba()` with alpha < 1, the material's `transparent` flag stays `false` and the alpha is ignored — rendering the stroke at full brightness. Workaround: use only fully opaque `rgb()` stroke colors in all globe styles. A page refresh clears it (materials are recreated from scratch).

## Frontend Features

- **3D Globe** (globe.gl): Displays attack location, rotates on new knocks; heat map mode extrudes countries by hit count
- **Protocol Filter**: Cycles ALL → SSH → TNET → SMTP → ALL; filters live feed, leaderboards, globe rotation, and heat map
- **Live Feed**: Real-time attack log with protocol badge, username/password/location
- **Leaderboards**: Top countries, usernames, passwords, ISPs, IPs — per-protocol or ALL
- **Trivia & Jokes**: Context about why usernames/passwords are chosen, plus knock-knock jokes
- **Sound Effects**: Optional audio notifications for new knocks
- **About**: Project info section
- **Classic Mode**: Automatically activates when only one protocol is active — hides protocol switcher, cycle buttons, proto badges, proto chip pulses, and Proto Stats pane for a clean single-protocol UI. Header label changes from "Total Knocks" to "[PROTO] Knocks"
- **`?show` URL Parameter**: Subset which protocols are visible (e.g., `?show=SSH`, `?show=SSH,RDP`). Intersected with server's enabled protocols; invalid values fall back to all enabled. Single-protocol `?show` triggers classic mode. When filtered, header stats (total, KPM, ago) reflect only the active protocols, computed client-side from `protoBreakdownCache` and `lastKnockTimeByProto`
- **Debug Mode**: Overlay via `?debug` URL parameter
- **Responsive**: Mobile carousel with swipe navigation, desktop grid layout
- **WebSocket**: Auto-reconnect, live updates without polling

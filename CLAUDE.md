# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Knock-Knock is a multi-protocol honeypot monitoring system that captures unauthorized login attempts across eight protocols (SSH, Telnet, FTP, RDP, SMB, SIP, HTTP, SMTP) and displays real-time attack data through a live web dashboard. It can be deployed via Docker or as two coordinated systemd services.

## Commands

### Service Management (Production)
```bash
# Restart all services
./restart.sh

# Reset all data and restart (blocklist is preserved)
./restart.sh --reset-all

# Reset blocklist only (deletes blocklist.txt + clears knock:blocked:* in Redis)
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

# Individual honeypots
python honeypots/ssh_honeypot_asyncssh.py   # SSH (port 22, active version)
python honeypots/telnet_honeypot.py          # Telnet (port 23)
python honeypots/ftp_honeypot.py             # FTP (port 21)
python honeypots/rdp_honeypot.py             # RDP (port 3389)
python honeypots/smb_honeypot.py             # SMB (port 445)
python honeypots/sip_honeypot.py             # SIP (port 5060)
python honeypots/http_honeypot.py            # HTTP (ports 80 and 443)
python honeypots/smtp_honeypot.py            # SMTP (ports 25 and 587)

# Log monitor + geo-enricher — spawns all honeypots as subprocesses
# CLI flags (or equivalent env vars in .env / systemd unit):
# --save-knocks / SAVE_KNOCKS=true       store individual knocks in SQLite (all protocols)
# --save-knocks=SIP,SMTP / SAVE_KNOCKS=SIP,SMTP   selective protocols only
# --max-knocks=5000 / MAX_KNOCKS=5000    auto-ban IPs exceeding a threshold (global)
# --max-knocks=5000,RDP:50 / MAX_KNOCKS=5000,RDP:50   per-protocol overrides
# --ban-duration=30 / BAN_DURATION=30   ban length in days (0 = permanent)
python monitor.py

# Web server — reads WEB_PORT, WEB_LISTEN, ENABLE_SSL, KNOCK_KEYFILE, KNOCK_CERTFILE from env
python main.py
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
sqlite3 data/knock_knock.db "SELECT * FROM knocks_ssh ORDER BY id DESC LIMIT 10;"

# Redis connectivity
redis-cli ping

# Check per-protocol feed lists
redis-cli llen knock:recent:ssh
redis-cli llen knock:recent:tnet
redis-cli llen knock:recent:ftp
redis-cli llen knock:recent:rdp
redis-cli llen knock:recent:smb
redis-cli llen knock:recent:sip
redis-cli llen knock:recent:http
redis-cli llen knock:recent:smtp

# Check protocol knock counts
redis-cli hgetall knock:proto_counts

# Check enabled protocols
redis-cli get knock:config:enabled_protocols
```

## Architecture

```
SSH Attacker    → honeypots/ssh_honeypot_asyncssh.py  (port 22)   ─┐
Telnet Attacker → honeypots/telnet_honeypot.py         (port 23)   ─┤
FTP Attacker    → honeypots/ftp_honeypot.py            (port 21)   ─┤
RDP Attacker    → honeypots/rdp_honeypot.py            (port 3389) ─┤→ stdout → monitor.py
SMB Attacker    → honeypots/smb_honeypot.py            (port 445)  ─┤      (GeoIP, DB, Redis)
SIP Attacker    → honeypots/sip_honeypot.py            (port 5060) ─┤              ↓
HTTP Attacker   → honeypots/http_honeypot.py           (ports 80,443)─┤  SQLite DB (data/) + Redis pub/sub
SMTP Attacker   → honeypots/smtp_honeypot.py           (ports 25,587)┘              ↓
                                                                       main.py (FastAPI, port 8080/8443)
                                                                                      ↓
                                                                    Browser WebSocket → Live Dashboard
```

**Two Services:**
- `monitor.py`: Spawns all honeypots as subprocesses, merges their stdout via a shared `queue.Queue`, performs GeoIP lookups, updates SQLite intel tables, publishes to Redis. Individual knocks saved to per-protocol SQLite tables with `--save-knocks` (all) or `--save-knocks=SIP,SMTP` (selective). Honeypots check `knock:blocked:{ip}` Redis keys on each connection to reject blocked IPs instantly.
- `main.py`: FastAPI server with WebSocket endpoint `/ws`, subscribes to Redis, broadcasts to all connected browsers.

**Data Flow:**
- Monitor spawns honeypots as subprocesses and reads their stdout (both systemd and Docker)
- Each honeypot emits JSON: `{"type": "KNOCK", "proto": "SSH"|"TNET"|"FTP"|..., "ip": ..., "user": ..., "pass": ...}`
- Inter-service communication via Redis pub/sub channel `knocks_stream`
- Stats cached in memory, refreshed every 60 seconds and broadcast to all clients
- SQLite databases in `data/` directory for persistence

**Multi-server / aggregator mode:**
- Set `AGGREGATOR_HOST` on feeder servers to forward all knocks to a central aggregator
- Set `INGEST_PORT` on the aggregator to accept incoming knock streams
- `SOURCE_ID` identifies each feeder server in the dashboard

**Deployment modes:**
- **Docker:** `docker compose up -d` — monitor spawns all honeypots internally
- **Systemd:** Two unit files in `systemd/` — monitor spawns all honeypots internally

## Key Files

| File | Purpose |
|------|---------|
| `honeypots/ssh_honeypot_asyncssh.py` | SSH honeypot (port 22) — active version using asyncssh |
| `honeypots/ssh_honeypot.py` | SSH honeypot — legacy paramiko version (kept as fallback) |
| `honeypots/telnet_honeypot.py` | Telnet honeypot (port 23), raw socket with IAC negotiation |
| `honeypots/ftp_honeypot.py` | FTP honeypot (port 21) |
| `honeypots/rdp_honeypot.py` | RDP honeypot (port 3389), NLA/CredSSP handshake |
| `honeypots/smb_honeypot.py` | SMB honeypot (port 445), SMB1/2/3 with decoy file shares |
| `honeypots/sip_honeypot.py` | SIP honeypot (port 5060 UDP+TCP), captures toll fraud dial attempts |
| `honeypots/http_honeypot.py` | HTTP honeypot (ports 80 and 443), captures web scanning and exploit attempts |
| `honeypots/smtp_honeypot.py` | SMTP honeypot (ports 25 and 587), AUTH LOGIN + AUTH PLAIN |
| `honeypots/stub_honeypot.py` | Minimal stub for adding new protocol honeypots |
| `monitor.py` | Spawns honeypots, GeoIP enrichment, DB writes, Redis publish |
| `main.py` | FastAPI server, `ConnectionManager`, `GlobalStatsCache`, WebSocket |
| `constants.py` | Shared protocol enum, UI order, metadata, and `DEFAULT_ENABLED_PROTOCOLS` |
| `index.html` | Single-page dashboard with WebSocket client |
| `summary.html` | Alternate compact dashboard view (kept in sync with index.html) |
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
- `data/geocode_cache.json` — SIP dial number geocode cache

**Note:** `blocklist.txt` and `knock:blocked:*` keys survive `--reset-all` intentionally. Use `--reset-blocklist` to clear them.

## Port Configuration

The web UI runs on port 8080 by default (`WEB_PORT=8080`). Most deployments just open port 8080 to the world — there's nothing sensitive in the dashboard. See `extras/cloudflare-ufw/README.md` for optional IP restriction via Cloudflare.

### Default (no Cloudflare)
- Honeypot ports (21, 22, 23, 25, 80, 445, 587, 3389, 5060): open to all — intentional
- Port 8080 (web UI): open to all, accessible at `http://your-server-ip:8080`

### Cloudflare-protected deployment
Use a Cloudflare Origin Rule (443 → 8080) so visitors connect on standard HTTPS while the web UI runs on 8080, restricted to Cloudflare IPs only.

**Systemd deployments:**
- Port 8080: UFW restricts to Cloudflare IPs via `extras/cloudflare-ufw/update-cloudflare-ufw.sh`
- `knock-web.service` runs uvicorn on `${WEB_PORT:-8080}` with SSL (Cloudflare Origin CA cert)

**Docker deployments:**
Docker bypasses UFW, so nginx enforces the restriction instead:
- nginx listens on 8080, enforces Cloudflare IP allowlist, proxies to the web container on an internal port
- Web container: set `WEB_LISTEN=127.0.0.1` and a non-public `WEB_PORT` in `.env`
- `docker-compose.override.yml`: `ENABLE_SSL=true`, matching `WEB_PORT`, certs volume
- nginx IP list auto-updated via `NGINX_IP_INCLUDE=/etc/nginx/cloudflare_ips.conf` in crontab

### HTTP honeypot and port 80
Port 80 is open to all — it's a honeypot port. Port 443 can also be mapped to the HTTP honeypot; it auto-enables TLS when `HTTP_PORT=443` (or `--ssl-cert`/`--ssl-key` flags are provided). On the Docker server, nginx owns port 8080; port 80 goes to the honeypot container.

---

## Environment Variables

### Core / Infrastructure

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_HOST` | `localhost` | Redis server hostname (set to `redis` in Docker) |
| `REDIS_DB` | `0` | Redis database index |
| `DB_DIR` | `data` | Directory for SQLite databases, blocklist, and caches |
| `ENABLED_PROTOCOLS` | all protocols | Comma-separated list of active protocols with optional port overrides, e.g. `SSH,SMTP:25,SMTP:587,HTTP:80,HTTP:443`. Empty string = ingest-only mode (no local honeypots). |

### Web Server (`main.py`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ENABLE_SSL` | unset | Set to `true` to enable HTTPS |
| `WEB_PORT` | `8080` | Port the web UI listens on |
| `WEB_LISTEN` | `0.0.0.0` | Interface the web UI binds to |
| `LOG_VISITORS` | unset | Set to `true` to log dashboard visitors to `visitors.db` |
| `LOG_UNHANDLED_HTTP` | unset | Set to `true` to log 404s in the web server |

### Monitor (`monitor.py`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SOURCE_ID` | hostname | Identifier for this server in multi-server deployments |
| `AGGREGATOR_HOST` | unset | Hostname of central aggregator to forward knocks to |
| `AGGREGATOR_PORT` | `9999` | TCP port of the aggregator ingest listener |
| `INGEST_PORT` | unset | TCP port to listen on for incoming knock streams (aggregator role) |
| `TRACE_KNOCK` | unset | Set to `true` to print full knock details to stdout |
| `SAVE_KNOCKS` | unset | `true` or `1` = save all protocols; comma-separated = selective (e.g. `SIP,SMTP`) |
| `MAX_KNOCKS` | unset | Auto-ban threshold, same syntax as `--max-knocks` (e.g. `5000` or `5000,RDP:500`) |
| `BAN_DURATION` | `30` | Auto-ban duration in days (`0` = permanent) |
| `MAIL_FORENSICS_MAX` | `100` | Max raw SMTP messages to retain in Redis forensics buffer |
| `REDACT_SELF_IPS` | unset | Comma-separated IPs to redact from knock output (self-protection) |
| `REDACT_SELF_HOSTS` | unset | Comma-separated hostnames to redact |
| `REDACT_SELF_DOMAINS` | unset | Comma-separated domain suffixes to redact |
| `REDACT_SELF_HOST_SUFFIXES` | unset | Comma-separated hostname suffixes to redact |

### SSH Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `SSH_PORT` | `22` | Listening port |
| `SSH_HOST_KEY_PATH` | `data/server.key` | RSA host key path |
| `SSH_ED25519_KEY_PATH` | `data/server_ed25519.key` | Ed25519 host key path |
| `SSH_PROFILE` | `openssh_8_9_ubuntu` | Banner/fingerprint profile to emulate |
| `SSH_LOGIN_TIMEOUT` | `120` | Seconds before unauthenticated connection is dropped |
| `SSH_MAX_AUTH_ATTEMPTS` | `6` | Max auth attempts per connection |

### SMTP Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `SMTP_HOSTNAME` | reverse DNS | Override SMTP banner and certificate hostname |
| `SMTP_FINGERPRINT` | `postfix` | MTA fingerprint to emulate |
| `SMTP587_REQUIRE_AUTH` | `false` | Require AUTH on port 587 before accepting mail |
| `SMTP_TLS_CERT_PATH` | `data/smtp.crt` | TLS certificate path (auto-generated if missing) |
| `SMTP_TLS_KEY_PATH` | `data/smtp.key` | TLS key path |
| `SMTP_TRACE` | unset | Set to `true` to trace all SMTP sessions to stdout |
| `SMTP_TRACE_IP` | unset | Trace only sessions from this specific IP |

### SMB Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `SMB_PORT` | `445` | Listening port |
| `SMB_DECOY_DIR` | `honeypots/decoys` | Directory of decoy share folders. Loaded at startup; zero FS access after that. Falls back to hardcoded `PUBLIC/passwords.txt` if missing or empty. |
| `SMB_SERVER_NAME` | hostname | NetBIOS server name advertised |
| `SMB_SERVER_DOMAIN` | unset | Domain name advertised in SMB negotiation |
| `SMB_QUARANTINE_DIR` | unset | Directory to save uploaded files from attackers |
| `SMB_DEDUP_WINDOW_SEC` | `60` | Seconds to suppress duplicate knocks from the same IP |
| `SMB_NBSS_MAX` | `4194304` | Max NetBIOS session message size (4 MB) |
| `SMB_TRACE` | unset | Set to `true` to trace SMB sessions to stdout |
| `SMB_TRACE_IP` | unset | Trace only sessions from this specific IP |

### SIP Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `SIP_PORT` | `5060` | Listening port (UDP + TCP) |
| `SIP_REALM` | `asterisk` | SIP realm in authentication challenge |
| `SIP_AUTH_CHALLENGE_MODE` | `mixed` | `always`, `never`, or `mixed` |
| `SIP_INVITE_MODE` | `answer` | How to respond to INVITE: `answer` or `reject` |
| `SIP_MAX_MESSAGES_PER_CONN` | `6` | Max SIP messages per connection |
| `SIP_CONN_TIMEOUT` | `20` | Connection timeout in seconds |
| `SIP_DEDUP_WINDOW_SEC` | `60` | Seconds to suppress duplicate knocks from the same IP |
| `SIP_TRACE` | unset | Set to `true` to trace SIP sessions to stdout |
| `SIP_TRACE_IP` | unset | Trace only sessions from this specific IP |

### HTTP Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `HTTP_PORT` | `80` | Listening port |
| `HTTP_TIMEOUT` | `15` | Connection timeout in seconds |
| `HTTP_MAX_HEADERS` | `8192` | Max header bytes to read |
| `HTTP_MAX_BODY` | `4096` | Max body bytes to read |
| `HTTPS_CERT_PATH` | `data/https.crt` | TLS certificate for HTTPS port (if enabled) |
| `HTTPS_KEY_PATH` | `data/https.key` | TLS key |
| `HTTP_TRACE` | unset | Set to `true` to trace HTTP requests to stdout |
| `HTTP_TRACE_IP` | unset | Trace only requests from this specific IP |

### RDP Honeypot

| Variable | Default | Purpose |
|----------|---------|---------|
| `RDP_TRACE` | unset | Set to `true` to trace RDP sessions to stdout |
| `RDP_TRACE_IP` | unset | Trace only sessions from this specific IP |
| `RDP_MAX_NLA_ATTEMPTS` | `3` | Max NLA authentication rounds |
| `RDP_CLASSIC_CAPTURE` | `false` | Also capture classic RDP (non-NLA) credentials |

## Protocol Enum

Defined in `constants.py`, imported by both `monitor.py` and `main.py`:

```python
PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3, 'FTP': 5, 'SIP': 6, 'SMB': 7, 'HTTP': 8}
PROTO_NAME = {v: k for k, v in PROTO.items()}  # reverse lookup: 0 → 'SSH' etc.

PROTOCOL_UI_ORDER = ['SSH', 'TNET', 'FTP', 'RDP', 'SMB', 'SIP', 'HTTP', 'SMTP']
DEFAULT_ENABLED_PROTOCOLS = list(PROTOCOL_UI_ORDER)
```

`PROTOCOL_META` in `constants.py` holds per-protocol display name, default port, and capability flags (`supports_user_panel`, `supports_pass_panel`, etc.).

## Database Schema

```sql
-- Per-protocol knock tables (only populated with --save-knocks; only enabled protocols get tables)
-- Common columns: id, timestamp, ip_address, iso_code, city, region, country, isp, asn
knocks_ssh(... username, password)
knocks_tnet(... username, password)
knocks_ftp(... username, password)
knocks_smtp(... username, password, smtp_stage, smtp_mail_from, smtp_rcpt_to, subject, body)
knocks_sip(... sip_method, sip_dial_string, sip_dial_number, sip_call_id, sip_cseq,
           sip_extension, sip_dial_country, sip_dial_country_name, sip_dial_lat, sip_dial_lng)
knocks_smb(... username, smb_action, smb_share, smb_file, smb_version, smb_domain, smb_host)
knocks_rdp(... username, rdp_source, domain)
knocks_http(... http_method, http_path, http_user_agent, http_body)

-- ALL intel tables (aggregated counts, indexed hits for fast top-N queries)
user_intel(username PRIMARY KEY, hits, last_seen)               -- INDEX on hits DESC
pass_intel(password PRIMARY KEY, hits, last_seen)               -- INDEX on hits DESC
country_intel(iso_code PRIMARY KEY, country, hits, last_seen)   -- INDEX on hits DESC
isp_intel(isp PRIMARY KEY, hits, last_seen, asn)                -- INDEX on hits DESC
ip_intel(ip PRIMARY KEY, hits, last_seen, lat, lng,
         hits_since_cleared, ban_until, ban_count)              -- INDEX on hits DESC

-- Per-protocol intel tables (same structure, composite PK)
user_intel_proto(username, proto INTEGER, hits, last_seen)      -- INDEX on (proto, hits DESC)
pass_intel_proto(password, proto INTEGER, hits, last_seen)      -- INDEX on (proto, hits DESC)
country_intel_proto(iso_code, proto INTEGER, country, hits, last_seen)
isp_intel_proto(isp, proto INTEGER, hits, last_seen, asn)
ip_intel_proto(ip, proto INTEGER, hits, last_seen, lat, lng)

-- SIP toll fraud destination tracking (only created when SIP is enabled)
dial_intel(number TEXT PRIMARY KEY, hits, first_seen, last_seen, country, country_name, lat, lng)

-- Multi-server source tracking
sources(id INTEGER PRIMARY KEY, source_id TEXT UNIQUE, display_name, hits, first_seen, last_seen, active)

-- Uptime tracking for KPM calculation (single-row, upserted each minute)
monitor_heartbeats(id INTEGER PRIMARY KEY, uptime_minutes INTEGER)
```

Each knock writes 10 upserts: 5 to ALL tables + 5 to `_proto` tables. ALL tables serve as fast rollup for the ALL leaderboard; `_proto` tables serve per-protocol leaderboards.

`ip_intel.hits_since_cleared` resets to 0 when an IP is banned (used with `--max-knocks` auto-ban). `ban_until` is a Unix timestamp (nullable); `ban_count` is the lifetime ban counter.

## Redis Keys

| Key | Type | Purpose |
|-----|------|---------|
| `knock:total_global` | string | Total attack count (all protocols) |
| `knock:proto_counts` | hash | Per-protocol knock counts, e.g. `{SSH: 12345, SMTP: 6789}` |
| `knock:source_counts` | hash | Per-source-server knock counts |
| `knock:uptime_minutes` | string | Total monitor uptime in minutes |
| `knock:uptime:{proto}` | string | Per-protocol uptime minutes (e.g. `knock:uptime:ssh`) |
| `knock:last_time` | string | Unix timestamp of last knock (any protocol) |
| `knock:last_time:{proto}` | string | Unix timestamp of last knock per protocol |
| `knock:last_lat` | string | Latitude of last knock location |
| `knock:last_lng` | string | Longitude of last knock location |
| `knock:recent` | list | Last 100 knocks, all protocols (JSON) |
| `knock:recent:{proto}` | list | Last 100 knocks per protocol (e.g. `knock:recent:ssh`) |
| `knock:config:enabled_protocols` | string | JSON array of enabled protocol names |
| `knock:config:protocol_meta` | string | JSON object of per-protocol metadata |
| `knock:blocked:{ip}` | string | Set if IP is blocked; has TTL if ban expires, no TTL for permanent blocks |
| `knock:is_aggregator` | string | Set to `"1"` if this monitor is running as an aggregator |
| `knock:diag:{proto}:no_knock` | list | Last 500 non-knock events per protocol (diagnostic) |
| `knock:diag:{proto}:last` | string | Most recent diagnostic event for a protocol |
| `knock:diag:{proto}:reason_counts` | hash | Counts of no-knock reasons per protocol |
| `knock:forensics:mail_raw` | list | Raw SMTP session forensics buffer (up to `MAIL_FORENSICS_MAX`) |
| `knock:alerted:{tag}` | string | Cooldown key used by `knock-watch.sh` (TTL-based; not used by the app) |
| `knocks_stream` | pub/sub | Real-time event channel between monitor and web server |

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

- **3D Globe** (globe.gl): Displays attack location, rotates on new knocks; heat map mode extrudes countries by hit count with a color scale legend
- **Protocol Filter**: Dropdown selector on each pane (mobile) and a header switcher (desktop); choose ALL or any single protocol to filter the live feed, leaderboards, globe rotation, and heat map
- **Live Feed**: Real-time attack log with protocol badge, username/password/location
- **Leaderboards**: Top countries, usernames, passwords, ISPs, IPs — per-protocol or ALL
- **Trivia & Jokes**: Context about why usernames/passwords are chosen, plus knock-knock jokes
- **Sound Effects**: Optional audio notifications for new knocks (off by default; UI interaction sounds also respect the mute state)
- **About**: Project info section
- **Classic Mode**: Automatically activates when only one protocol is active — hides protocol switcher, cycle buttons, proto badges, proto chip pulses, and Proto Stats pane for a clean single-protocol UI. Header label changes from "Total Knocks" to "[PROTO] Knocks"
- **`?show` URL Parameter**: Subset which protocols are visible (e.g., `?show=SSH`, `?show=SSH,RDP`). Intersected with server's enabled protocols; invalid values fall back to all enabled. Single-protocol `?show` triggers classic mode. When filtered, header stats (total, KPM, ago) reflect only the active protocols, computed client-side from `protoBreakdownCache` and `lastKnockTimeByProto`
- **Debug Mode**: Overlay via `?debug` URL parameter
- **Responsive**: Mobile carousel with swipe navigation, desktop grid layout
- **WebSocket**: Auto-reconnect, live updates without polling

# Knock-Knock

A real-time SSH honeypot monitoring system with a live web dashboard showing global attack attempts.

## Features

- **SSH Honeypot**: Captures unauthorized login attempts on port 22
- **Real-time Dashboard**: Live WebSocket updates showing attacks as they happen
- **3D Globe**: Interactive globe that rotates to show attack locations
- **Attack Analytics**: Top usernames, passwords, ISPs, and countries
- **GeoIP Enrichment**: City, country, and ISP lookup for each attacker IP
- **Mobile & Desktop**: Responsive design with carousel navigation on mobile

## Architecture

```
SSH Attacker → honeypot.py (port 22) → stdout (piped)
                                              ↓
                                       monitor.py (GeoIP lookup)
                                              ↓
                                    SQLite + Redis pub/sub
                                              ↓
                                       main.py (FastAPI)
                                              ↓
                                    WebSocket → Live Dashboard
```

**Two Services:**
- `honeypot.py` + `monitor.py` - Honeypot logs credentials to stdout, piped to monitor for GeoIP enrichment and storage
- `main.py` - FastAPI server with WebSocket endpoint for live updates

## Requirements

- Python 3.12+
- Redis server
- MaxMind GeoLite2 databases (City and ASN)
- SSL certificates (optional, for HTTPS)

## Quick Start

```bash
# Install dependencies
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt

# Start all services
./restart.sh

# View logs
journalctl -u knock-monitor -u knock-web -f
```

## Database

SQLite database (`knock_knock.db`) stores:
- Individual attack records with full details
- Aggregated intel tables for fast leaderboard queries
- IP geolocation cache with lat/lng coordinates

## Live Demo

Visit [knock-knock.net](https://knock-knock.net) to see the dashboard in action.

## License

MIT

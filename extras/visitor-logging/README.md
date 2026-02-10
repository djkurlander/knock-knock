# Visitor Logging

Optional add-on that logs dashboard visitors to a separate SQLite database and sends periodic email reports. Useful for understanding how popular your Knock-Knock instance is and where visitors come from.

## How It Works

1. **main.py** (core project) has built-in visitor logging gated behind the `LOG_VISITORS=true` environment variable. When enabled, each WebSocket connection logs the visitor's IP, GeoIP location, ISP, referrer, and user agent to `data/visitors.db`.

2. **visitor_report.py** (this directory) queries that database and emails you a summary — daily, weekly, or monthly.

## Setup

### 1. Enable visitor logging

Set the `LOG_VISITORS` environment variable:

**Systemd:**
```ini
# In your knock-web.service unit file
Environment=LOG_VISITORS=true
```

**Docker:**
```yaml
# In docker-compose.yml, under the web service
environment:
  - LOG_VISITORS=true
```

Restart the web service after enabling.

### 2. Configure email reports

Copy the included `.env.example` to your project root as `.env` and edit it:

```bash
REPORT_EMAIL_TO=you@example.com
REPORT_EMAIL_FROM=knock-knock@yourdomain.com
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=465
SMTP_USER=you@example.com
SMTP_PASS=your-app-password
EXCLUDE_IPS=your.home.ip,your-hostname.example.com
```

`EXCLUDE_IPS` accepts both IP addresses and hostnames (resolved at runtime). This keeps your own visits out of the reports.

### 3. Schedule reports via cron

```bash
crontab -e
```

Add entries like these (adjust times and paths):

```
# Daily report at midnight Pacific
0 7,8 * * * [ "$(TZ=America/Los_Angeles date +\%H)" = "00" ] && /path/to/.venv/bin/python /path/to/extras/visitor-logging/visitor_report.py --day

# Weekly report on Sundays
0 7,8 * * 0 [ "$(TZ=America/Los_Angeles date +\%H)" = "00" ] && /path/to/.venv/bin/python /path/to/extras/visitor-logging/visitor_report.py --week

# Monthly report on the 1st
0 7,8 1 * * [ "$(TZ=America/Los_Angeles date +\%H)" = "00" ] && /path/to/.venv/bin/python /path/to/extras/visitor-logging/visitor_report.py --month
```

The `TZ` trick runs at midnight Pacific regardless of server timezone.

### 4. Manual reports

```bash
python extras/visitor-logging/visitor_report.py --day     # Last 24 hours
python extras/visitor-logging/visitor_report.py --week    # Last 7 days
python extras/visitor-logging/visitor_report.py --month   # Previous calendar month
python extras/visitor-logging/visitor_report.py --days 3  # Custom range
```

Without email configured, reports print to stdout.

## Database

Visitor data is stored in `data/visitors.db`:

```sql
visitors(id, timestamp, ip, city, region, country, iso_code, isp, asn, referrer, user_agent)
```

This is separate from the main `knock_knock.db` attack database.

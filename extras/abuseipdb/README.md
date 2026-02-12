# AbuseIPDB Reporter for Knock-Knock

## What It Does

Reports attacker IPs from the honeypot to [AbuseIPDB](https://www.abuseipdb.com/) via their bulk-report API. Queries the `ip_intel` table for IPs seen within a configurable lookback window (default: 24 hours) and submits them in a single request.

Works regardless of whether `--save-knocks` is enabled — the `ip_intel` table is always populated.

## Setup

### 1. Get an API key

- Create a free account at [abuseipdb.com](https://www.abuseipdb.com/)
- Go to **User Account → API** and generate a key

### 2. Export the key

```bash
export ABUSEIPDB_API_KEY="your-api-key-here"
```

For cron, add it directly to the crontab command (see below).

## Usage

### Dry run (preview without submitting)

```bash
python extras/abuseipdb/report.py --dry-run
```

### Submit reports

```bash
python extras/abuseipdb/report.py
```

### Custom lookback window

```bash
# Report IPs seen in the last 12 hours
python extras/abuseipdb/report.py --hours 12
```

## Cron Setup

Run nightly at 3 AM:

```bash
crontab -e
```

Add this line:

```
0 3 * * * ABUSEIPDB_API_KEY="your-key" /path/to/knock-knock/.venv/bin/python /path/to/knock-knock/extras/abuseipdb/report.py >> /var/log/abuseipdb-report.log 2>&1
```

## Notes

- **Rate limits:** Free tier allows 5 bulk reports per day, each up to 10,000 IPs
- **Categories:** Each IP is reported under categories 18 (Brute-Force) and 22 (SSH)
- **Deduplication:** AbuseIPDB deduplicates reports from the same source, so overlapping lookback windows are safe
- **No extra dependencies:** Uses only the Python standard library

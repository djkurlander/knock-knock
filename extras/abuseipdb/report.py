#!/usr/bin/env python3
"""Report honeypot attacker IPs to AbuseIPDB via the bulk-report API."""

import argparse
import csv
import io
import json
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / os.environ.get('DB_DIR', 'data') / 'knock_knock.db'

API_URL = 'https://api.abuseipdb.com/api/v2/bulk-report'
CATEGORIES = '18,22'  # Brute-Force, SSH
MAX_ROWS = 10_000


def fetch_ips(hours):
    """Return list of (ip, hits, last_seen) from ip_intel within the lookback window."""
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        'SELECT ip, hits, last_seen FROM ip_intel WHERE last_seen >= ? ORDER BY hits DESC LIMIT ?',
        (cutoff, MAX_ROWS),
    ).fetchall()
    conn.close()
    return rows


def build_csv(rows):
    """Build AbuseIPDB bulk-report CSV from ip_intel rows."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['IP', 'Categories', 'ReportDate', 'Comment'])
    for ip, hits, last_seen in rows:
        # Convert stored timestamp to ISO 8601 with UTC timezone
        dt = datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        report_date = dt.isoformat()
        comment = f'SSH honeypot brute-force attempt ({hits} total hits)'
        writer.writerow([ip, CATEGORIES, report_date, comment])
    return buf.getvalue()


def submit(csv_data, api_key):
    """POST CSV to AbuseIPDB bulk-report endpoint. Returns parsed JSON response."""
    boundary = '----KnockKnockBulkReport'
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="csv"; filename="report.csv"\r\n'
        f'Content-Type: text/csv\r\n'
        f'\r\n'
        f'{csv_data}\r\n'
        f'--{boundary}--\r\n'
    ).encode()

    req = urllib.request.Request(API_URL, data=body, method='POST')
    req.add_header('Key', api_key)
    req.add_header('Accept', 'application/json')
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description='Report attacker IPs to AbuseIPDB')
    parser.add_argument('--hours', type=int, default=24, help='Lookback window in hours (default: 24)')
    parser.add_argument('--dry-run', action='store_true', help='Preview CSV without submitting')
    args = parser.parse_args()

    api_key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not api_key and not args.dry_run:
        print('Error: ABUSEIPDB_API_KEY environment variable is required', file=sys.stderr)
        sys.exit(1)

    if not DB_PATH.exists():
        print(f'Error: database not found at {DB_PATH}', file=sys.stderr)
        sys.exit(1)

    rows = fetch_ips(args.hours)
    if not rows:
        print(f'No IPs found in the last {args.hours} hours.')
        return

    csv_data = build_csv(rows)
    print(f'Found {len(rows)} IPs from the last {args.hours} hours.')

    if args.dry_run:
        print()
        print(csv_data)
        return

    print('Submitting to AbuseIPDB...')
    try:
        result = submit(csv_data, api_key)
    except urllib.error.HTTPError as e:
        print(f'FAILED: HTTP {e.code} — {e.reason}', file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f'FAILED: {e.reason}', file=sys.stderr)
        sys.exit(1)

    saved = result.get('data', {}).get('savedReports', 0)
    errors = result.get('errors', [])
    if errors:
        print(f'FAILED: {saved} IPs accepted, but errors occurred:')
        for err in errors:
            print(f'  {err.get("detail", err)}', file=sys.stderr)
        sys.exit(1)
    else:
        print(f'SUCCESS: {saved} IPs reported.')


if __name__ == '__main__':
    main()

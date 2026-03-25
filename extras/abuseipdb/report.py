#!/usr/bin/env python3
"""Report honeypot attacker IPs to AbuseIPDB via the bulk-report API."""

import argparse
import csv
import io
import json
import os
import socket
import sqlite3
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / os.environ.get('DB_DIR', 'data') / 'knock_knock.db'

# --- Load .env file if it exists ---
env_path = PROJECT_ROOT / '.env'
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())


def resolve_exclusions(exclusion_str):
    """Resolve a comma-separated list of IPs, domains, and prefixes to exclude."""
    exact = set()
    prefixes = []
    for entry in filter(None, exclusion_str.split(',')):
        entry = entry.strip()
        if not entry:
            continue
        if entry.endswith('*'):
            prefixes.append(entry[:-1])
        elif any(c.isalpha() for c in entry):
            try:
                ips = socket.gethostbyname_ex(entry)[2]
                exact.update(ips)
            except socket.gaierror:
                print(f"Warning: Could not resolve {entry}")
        else:
            exact.add(entry)
    return exact, prefixes


_exact_ips, _prefix_ips = resolve_exclusions(os.environ.get('EXCLUDE_IPS', ''))


def is_excluded(ip):
    """Check if an IP matches any exclusion (exact or prefix)."""
    return ip in _exact_ips or any(ip.startswith(p) for p in _prefix_ips)


# AbuseIPDB category sets per protocol integer
# 5=FTP Brute-Force, 11=Email Spam, 18=Brute-Force, 22=SSH
PROTO_CATEGORIES = {
    0: ({18, 22}, 'SSH'),
    1: ({18},     'Telnet'),
    2: ({18},     'SMTP'),
    3: ({18},     'RDP'),
    4: ({11, 18}, 'MAIL'),
    5: ({5, 18},  'FTP'),
    6: ({18, 15}, 'SIP'),    # 15=Hacking
    7: ({18},     'SMB'),
}

API_URL = 'https://api.abuseipdb.com/api/v2/bulk-report'
MAX_ROWS = 10_000


def _has_table(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def fetch_ips(hours, proto_filter=None):
    """
    Return list of (ip, total_hits, last_seen, proto_names, categories_str)
    within the lookback window, grouped by IP.

    Uses ip_intel_proto when available (multiprotocol schema), otherwise
    falls back to ip_intel (SSH-only / pre-migration schema).
    """
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    has_proto = _has_table(conn, 'ip_intel_proto')

    if has_proto:
        if proto_filter:
            placeholders = ','.join('?' * len(proto_filter))
            rows = conn.execute(
                f'SELECT ip, GROUP_CONCAT(proto), SUM(hits), MAX(last_seen) '
                f'FROM ip_intel_proto '
                f'WHERE last_seen >= ? AND proto IN ({placeholders}) '
                f'GROUP BY ip ORDER BY SUM(hits) DESC LIMIT ?',
                [cutoff] + proto_filter + [MAX_ROWS],
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT ip, GROUP_CONCAT(proto), SUM(hits), MAX(last_seen) '
                'FROM ip_intel_proto '
                'WHERE last_seen >= ? '
                'GROUP BY ip ORDER BY SUM(hits) DESC LIMIT ?',
                (cutoff, MAX_ROWS),
            ).fetchall()
    else:
        if proto_filter:
            print('Warning: --proto filter ignored (database has no per-protocol tables)', file=sys.stderr)
        rows = conn.execute(
            'SELECT ip, NULL, hits, last_seen '
            'FROM ip_intel '
            'WHERE last_seen >= ? '
            'ORDER BY hits DESC LIMIT ?',
            (cutoff, MAX_ROWS),
        ).fetchall()

    conn.close()

    result = []
    for ip, protos_str, total_hits, last_seen in rows:
        if protos_str is not None:
            proto_ints = [int(p) for p in protos_str.split(',')]
        else:
            proto_ints = [0]  # assume SSH for legacy schema
        categories = set()
        names = []
        for p in proto_ints:
            cats, name = PROTO_CATEGORIES.get(p, ({18}, f'proto{p}'))
            categories |= cats
            names.append(name)
        categories_str = ','.join(str(c) for c in sorted(categories))
        result.append((ip, total_hits, last_seen, names, categories_str))

    return result


def build_csv(rows):
    """Build AbuseIPDB bulk-report CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['IP', 'Categories', 'ReportDate', 'Comment'])
    for ip, total_hits, last_seen, proto_names, categories_str in rows:
        dt = datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        report_date = dt.isoformat()
        proto_list = ', '.join(proto_names)
        comment = f'Knock-Knock honeypot brute-force: {proto_list} ({total_hits} total hits)'
        writer.writerow([ip, categories_str, report_date, comment])
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


def parse_proto_filter(proto_str):
    """Convert comma-separated protocol names to list of proto integers."""
    name_to_int = {name.upper(): i for i, (_, name) in PROTO_CATEGORIES.items()}
    result = []
    for name in proto_str.upper().split(','):
        name = name.strip()
        if name not in name_to_int:
            print(f'Error: unknown protocol {name!r}. Valid: {", ".join(name_to_int)}', file=sys.stderr)
            sys.exit(1)
        result.append(name_to_int[name])
    return result


def main():
    parser = argparse.ArgumentParser(description='Report attacker IPs to AbuseIPDB')
    parser.add_argument('--hours', type=int, default=24, help='Lookback window in hours (default: 24)')
    parser.add_argument('--proto', type=str, default=None, help='Filter by protocol(s), e.g. SSH,RDP')
    parser.add_argument('--dry-run', action='store_true', help='Preview CSV without submitting')
    args = parser.parse_args()

    api_key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not api_key and not args.dry_run:
        print('Error: ABUSEIPDB_API_KEY environment variable is required', file=sys.stderr)
        sys.exit(1)

    if not DB_PATH.exists():
        print(f'Error: database not found at {DB_PATH}', file=sys.stderr)
        sys.exit(1)

    proto_filter = parse_proto_filter(args.proto) if args.proto else None
    all_rows = fetch_ips(args.hours, proto_filter)
    rows = [r for r in all_rows if not is_excluded(r[0])]
    excluded = len(all_rows) - len(rows)

    if not rows:
        print(f'No IPs found in the last {args.hours} hours.')
        return

    csv_data = build_csv(rows)
    print(f'Found {len(rows)} IPs from the last {args.hours} hours.' +
          (f' ({excluded} excluded)' if excluded else ''))

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

#!/usr/bin/env python3
"""
Visitor report script (daily, weekly, or monthly).

Usage:
  python visitor_report.py --day      # Last 24 hours
  python visitor_report.py --week     # Last 7 days
  python visitor_report.py --month    # Previous calendar month (auto-calculated)
  python visitor_report.py --days N   # Last N days (custom)

Configure email settings in .env file or via environment variables.
"""
import argparse
import calendar
import sqlite3
import smtplib
import socket
from email.mime.text import MIMEText
from datetime import datetime, timedelta, date
import os
from pathlib import Path

# --- Load .env file if it exists ---
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())

# --- Configuration ---
VISITORS_DB = '/root/knock-knock/visitors.db'
EMAIL_TO = os.environ.get('REPORT_EMAIL_TO', 'your-email@example.com')
EMAIL_FROM = os.environ.get('REPORT_EMAIL_FROM', 'knock-knock@knock-knock.net')
SMTP_HOST = os.environ.get('SMTP_HOST', 'localhost')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')

# --- IPs to exclude from reports (e.g., your own IPs or domains) ---
def resolve_exclusions(exclusion_str):
    """Resolve a comma-separated list of IPs and/or domain names to a set of IPs."""
    excluded = set()
    for entry in filter(None, exclusion_str.split(',')):
        entry = entry.strip()
        if not entry:
            continue
        # Check if it looks like a domain (has letters) vs an IP (only digits, dots, colons)
        if any(c.isalpha() for c in entry):
            try:
                # Resolve domain to IP(s)
                ips = socket.gethostbyname_ex(entry)[2]
                excluded.update(ips)
            except socket.gaierror:
                print(f"Warning: Could not resolve {entry}")
        else:
            excluded.add(entry)
    return excluded

EXCLUDE_IPS = resolve_exclusions(os.environ.get('EXCLUDE_IPS', ''))

def get_visitors(days):
    """Get visitors from the last N days, excluding specified IPs."""
    conn = sqlite3.connect(VISITORS_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')

    cur.execute("""
        SELECT ip, city, region, country, iso_code, isp, referrer, user_agent,
               COUNT(*) as visit_count
        FROM visitors
        WHERE timestamp >= ?
        GROUP BY ip
        ORDER BY MAX(timestamp) DESC
    """, (since,))

    visitors = [dict(row) for row in cur.fetchall() if row['ip'] not in EXCLUDE_IPS]
    conn.close()
    return visitors


def get_referrers_for_ip(days, ip):
    """Get unique referrers for a specific IP."""
    conn = sqlite3.connect(VISITORS_DB)
    cur = conn.cursor()
    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    cur.execute("""
        SELECT DISTINCT referrer FROM visitors
        WHERE timestamp >= ? AND ip = ? AND referrer IS NOT NULL AND referrer != ''
    """, (since, ip))
    referrers = [row[0] for row in cur.fetchall()]
    conn.close()
    return referrers

def get_visitor_summary(days):
    """Get summary stats for the last N days, excluding specified IPs."""
    visitors = get_visitors(days)

    # Total connections (sum of all visit counts)
    total = sum(v['visit_count'] for v in visitors)

    # Unique IPs (already grouped)
    unique_ips = len(visitors)

    # Top countries (by total connections)
    country_counts = {}
    for v in visitors:
        if v['country']:
            country_counts[v['country']] = country_counts.get(v['country'], 0) + v['visit_count']
    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]

    # Top ISPs (by total connections)
    isp_counts = {}
    for v in visitors:
        if v['isp']:
            isp_counts[v['isp']] = isp_counts.get(v['isp'], 0) + v['visit_count']
    top_isps = sorted(isp_counts.items(), key=lambda x: -x[1])[:10]

    return {
        'total': total,
        'unique_ips': unique_ips,
        'top_countries': top_countries,
        'top_isps': top_isps
    }

def format_report(period_name, days):
    """Format the visitor report."""
    visitors = get_visitors(days)
    summary = get_visitor_summary(days)

    report = []
    report.append(f"KNOCK-KNOCK.NET - {period_name} Visitor Report")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 50)
    report.append("")
    report.append(f"Total visits ({days} day{'s' if days > 1 else ''}): {summary['total']}")
    report.append(f"Unique IPs: {summary['unique_ips']}")
    report.append("")

    report.append("TOP COUNTRIES:")
    for country, cnt in summary['top_countries']:
        report.append(f"  {country}: {cnt}")
    report.append("")

    report.append("TOP ISPs:")
    for isp, cnt in summary['top_isps']:
        report.append(f"  {isp}: {cnt}")
    report.append("")

    report.append("=" * 50)
    report.append("VISITOR DETAILS:")
    report.append("")

    # Limit details based on period
    limit = 100 if days == 1 else 200 if days == 7 else 300
    for v in visitors[:limit]:
        loc = ", ".join(filter(None, [v['city'], v['region'], v['country']]))
        count_str = f"({v['visit_count']} connections)" if v['visit_count'] > 1 else "(1 connection)"
        report.append(f"{v['ip']} {count_str}")
        report.append(f"  Location: {loc or 'Unknown'}")
        report.append(f"  ISP: {v['isp'] or 'Unknown'}")
        if v.get('user_agent'):
            report.append(f"  User-Agent: {v['user_agent']}")
        # Show referrers if any
        referrers = get_referrers_for_ip(days, v['ip'])
        for ref in referrers:
            report.append(f"  Referral: {ref}")
        report.append("")

    if len(visitors) > limit:
        report.append(f"... and {len(visitors) - limit} more visitors")

    return "\n".join(report)

def send_email(report, period_name, total_visitors):
    """Send the report via email."""
    msg = MIMEText(report)
    msg['Subject'] = f"Knock-Knock.net {period_name} Visitor Report - {total_visitors} Visitors"
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        # Use SSL for port 465, STARTTLS for port 587
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls()
                server.ehlo()

        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)

        server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        server.quit()
        print(f"Report sent to {EMAIL_TO}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        print("\nReport contents:")
        print(report)

def get_previous_month_days():
    """Calculate the number of days in the previous month."""
    today = date.today()
    if today.month == 1:
        prev_month, prev_year = 12, today.year - 1
    else:
        prev_month, prev_year = today.month - 1, today.year
    return calendar.monthrange(prev_year, prev_month)[1]

def main():
    parser = argparse.ArgumentParser(description='Send visitor report email.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--day', action='store_true', help='Report for last 24 hours')
    group.add_argument('--week', action='store_true', help='Report for last 7 days')
    group.add_argument('--month', action='store_true', help='Report for previous calendar month')
    group.add_argument('--days', type=int, metavar='N', help='Report for last N days')
    args = parser.parse_args()

    if args.day:
        period_name, days = 'Daily', 1
    elif args.week:
        period_name, days = 'Weekly', 7
    elif args.month:
        days = get_previous_month_days()
        period_name = 'Monthly'
    else:
        days = args.days
        period_name = f'{days}-Day'

    summary = get_visitor_summary(days)
    report = format_report(period_name, days)
    send_email(report, period_name, summary['total'])

if __name__ == "__main__":
    main()

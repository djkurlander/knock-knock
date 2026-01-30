#!/usr/bin/env python3
"""
Daily visitor report script.
Run via cron: 0 0 * * * /root/knock-knock/.venv/bin/python /root/knock-knock/daily_report.py

Configure email settings in .env file or via environment variables.
"""
import sqlite3
import smtplib
import socket
from email.mime.text import MIMEText
from datetime import datetime, timedelta
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

def get_daily_visitors():
    """Get visitors from the last 24 hours, excluding specified IPs."""
    conn = sqlite3.connect(VISITORS_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    cur.execute("""
        SELECT timestamp, ip, city, region, country, iso_code, isp
        FROM visitors
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
    """, (yesterday,))

    visitors = [dict(row) for row in cur.fetchall() if row['ip'] not in EXCLUDE_IPS]
    conn.close()
    return visitors

def get_visitor_summary():
    """Get summary stats for the last 24 hours, excluding specified IPs."""
    visitors = get_daily_visitors()  # Already filtered

    # Total visitors
    total = len(visitors)

    # Unique IPs
    unique_ips = len(set(v['ip'] for v in visitors))

    # Top countries
    country_counts = {}
    for v in visitors:
        if v['country']:
            country_counts[v['country']] = country_counts.get(v['country'], 0) + 1
    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]

    # Top ISPs
    isp_counts = {}
    for v in visitors:
        if v['isp']:
            isp_counts[v['isp']] = isp_counts.get(v['isp'], 0) + 1
    top_isps = sorted(isp_counts.items(), key=lambda x: -x[1])[:10]

    return {
        'total': total,
        'unique_ips': unique_ips,
        'top_countries': top_countries,
        'top_isps': top_isps
    }

def format_report():
    """Format the daily report."""
    visitors = get_daily_visitors()
    summary = get_visitor_summary()
    
    report = []
    report.append(f"KNOCK-KNOCK.NET - Daily Visitor Report")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 50)
    report.append("")
    report.append(f"Total visits (24h): {summary['total']}")
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
    
    for v in visitors[:100]:  # Limit to 100 entries
        loc = ", ".join(filter(None, [v['city'], v['region'], v['country']]))
        report.append(f"{v['timestamp']} | {v['ip']}")
        report.append(f"  Location: {loc or 'Unknown'}")
        report.append(f"  ISP: {v['isp'] or 'Unknown'}")
        report.append("")
    
    return "\n".join(report)

def send_email(report):
    """Send the report via email."""
    msg = MIMEText(report)
    msg['Subject'] = f"Knock-Knock.net Visitor Report - {datetime.now().strftime('%Y-%m-%d')}"
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

if __name__ == "__main__":
    report = format_report()
    send_email(report)

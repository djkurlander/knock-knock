#!/usr/bin/env python3
"""
Daily visitor report script.
Run via cron: 0 0 * * * /root/knock-knock/.venv/bin/python /root/knock-knock/daily_report.py

Configure email settings below or via environment variables.
"""
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import os

# --- Configuration ---
VISITORS_DB = '/root/knock-knock/visitors.db'
EMAIL_TO = os.environ.get('REPORT_EMAIL_TO', 'your-email@example.com')
EMAIL_FROM = os.environ.get('REPORT_EMAIL_FROM', 'knock-knock@knock-knock.net')
SMTP_HOST = os.environ.get('SMTP_HOST', 'localhost')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')

def get_daily_visitors():
    """Get visitors from the last 24 hours."""
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
    
    visitors = [dict(row) for row in cur.fetchall()]
    conn.close()
    return visitors

def get_visitor_summary():
    """Get summary stats for the last 24 hours."""
    conn = sqlite3.connect(VISITORS_DB)
    cur = conn.cursor()
    
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    
    # Total visitors
    cur.execute("SELECT COUNT(*) FROM visitors WHERE timestamp >= ?", (yesterday,))
    total = cur.fetchone()[0]
    
    # Unique IPs
    cur.execute("SELECT COUNT(DISTINCT ip) FROM visitors WHERE timestamp >= ?", (yesterday,))
    unique_ips = cur.fetchone()[0]
    
    # Top countries
    cur.execute("""
        SELECT country, COUNT(*) as cnt FROM visitors
        WHERE timestamp >= ? AND country IS NOT NULL
        GROUP BY country ORDER BY cnt DESC LIMIT 10
    """, (yesterday,))
    top_countries = cur.fetchall()
    
    # Top ISPs
    cur.execute("""
        SELECT isp, COUNT(*) as cnt FROM visitors
        WHERE timestamp >= ? AND isp IS NOT NULL
        GROUP BY isp ORDER BY cnt DESC LIMIT 10
    """, (yesterday,))
    top_isps = cur.fetchall()
    
    conn.close()
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
        if SMTP_USER and SMTP_PASS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        
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

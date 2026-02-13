#!/usr/bin/env python3
"""Print knock-knock database statistics."""

import argparse
import sqlite3

DB_PATH = 'data/knock_knock.db'

def main():
    parser = argparse.ArgumentParser(description='Print knock-knock database statistics.')
    parser.add_argument('--min', type=int, metavar='N',
                        help='Report how many items have hits >= N')
    parser.add_argument('--max', type=int, metavar='N',
                        help='Report how many items have hits <= N')
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM knocks")
    knocks = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM country_intel")
    countries = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM user_intel")
    usernames = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM pass_intel")
    passwords = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM isp_intel")
    isps = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM ip_intel")
    ips = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM monitor_heartbeats")
    minutes = cur.fetchone()[0]

    # Min/max counts if requested
    tables = [
        ('country_intel', 'countries'),
        ('user_intel', 'usernames'),
        ('pass_intel', 'passwords'),
        ('isp_intel', 'isps'),
        ('ip_intel', 'ips'),
    ]
    above = {}
    below = {}

    if args.min is not None:
        for table, name in tables:
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE hits >= ?", (args.min,))
            above[name] = cur.fetchone()[0]

    if args.max is not None:
        for table, name in tables:
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE hits <= ?", (args.max,))
            below[name] = cur.fetchone()[0]

    conn.close()

    days = minutes // 1440
    hours = (minutes % 1440) // 60
    mins = minutes % 60

    def format_stat(name, total):
        parts = [f"{total:,}"]
        if args.min is not None:
            parts.append(f"{above[name]:,} >= {args.min}")
        if args.max is not None:
            parts.append(f"{below[name]:,} <= {args.max}")
        if len(parts) > 1:
            return f"{parts[0]} ({', '.join(parts[1:])})"
        return parts[0]

    print(f"Knocks:    {knocks:,}")
    print(f"Countries: {format_stat('countries', countries)}")
    print(f"Usernames: {format_stat('usernames', usernames)}")
    print(f"Passwords: {format_stat('passwords', passwords)}")
    print(f"ISPs:      {format_stat('isps', isps)}")
    print(f"IPs:       {format_stat('ips', ips)}")
    print(f"Operative: {days}d {hours}h {mins}m")

if __name__ == "__main__":
    main()

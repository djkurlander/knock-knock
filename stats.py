#!/usr/bin/env python3
"""Print knock-knock database statistics."""

import sqlite3

DB_PATH = 'knock_knock.db'

def main():
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

    conn.close()

    days = minutes // 1440
    hours = (minutes % 1440) // 60
    mins = minutes % 60

    print(f"Knocks:    {knocks:,}")
    print(f"Countries: {countries:,}")
    print(f"Usernames: {usernames:,}")
    print(f"Passwords: {passwords:,}")
    print(f"ISPs:      {isps:,}")
    print(f"IPs:       {ips:,}")
    print(f"Collected: {days}d {hours}h {mins}m")

if __name__ == "__main__":
    main()

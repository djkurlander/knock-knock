#!/usr/bin/env python3
"""ip_ban.py — manual IP ban management for Knock-Knock."""
import argparse
import os
import sqlite3
import time
from datetime import datetime, timezone

import redis

DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_DB = int(os.environ.get('REDIS_DB', '0'))


def get_redis():
    try:
        r = redis.Redis(host=REDIS_HOST, port=6379, db=REDIS_DB, decode_responses=True)
        r.ping()
        return r
    except Exception as e:
        print(f"⚠️  Redis unavailable ({e}) — SQLite updated but Redis not synced")
        return None


def fmt_ban_until(ban_until):
    if ban_until is None:
        return "not banned"
    if ban_until == 0:
        return "permanent"
    dt = datetime.fromtimestamp(ban_until)
    remaining = ban_until - int(time.time())
    if remaining <= 0:
        return f"expired ({dt.strftime('%Y-%m-%d %H:%M')})"
    days = remaining // 86400
    return f"until {dt.strftime('%Y-%m-%d %H:%M')} ({days}d remaining)"


def cmd_list(args):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    now = int(time.time())
    rows = conn.execute(
        "SELECT ip, ban_until, hits_since_cleared, hits, last_seen, ban_count FROM ip_intel "
        "WHERE ban_until IS NOT NULL ORDER BY ban_until ASC"
    ).fetchall()
    conn.close()
    if not rows:
        print("No banned IPs.")
        return
    active = [(ip, bu, hsb, h, ls, bc) for ip, bu, hsb, h, ls, bc in rows if bu == 0 or bu > now]
    expired = [(ip, bu, hsb, h, ls, bc) for ip, bu, hsb, h, ls, bc in rows if bu != 0 and bu <= now]
    if active:
        print(f"{'IP':<20} {'Ban':<38} {'Since reset':>11} {'Total hits':>10} {'Bans':>5}  Last seen")
        print("-" * 102)
        for ip, ban_until, hits_since_cleared, hits, last_seen, ban_count in active:
            print(f"{ip:<20} {fmt_ban_until(ban_until):<38} {hits_since_cleared or 0:>14} {hits or 0:>10} {ban_count or 0:>5}  {last_seen or '—'}")
    if expired:
        print(f"\n{len(expired)} expired ban(s) still in db (ban_until in past — will be ignored):")
        for ip, ban_until, _, _, _, _ in expired:
            print(f"  {ip}  expired {datetime.fromtimestamp(ban_until).strftime('%Y-%m-%d %H:%M')}")


def cmd_ban(args):
    ip = args.ban
    days = args.days
    now = int(time.time())
    ban_until = 0 if days == 0 else now + days * 86400

    conn = sqlite3.connect(DB_PATH, timeout=10)
    existing = conn.execute("SELECT ip FROM ip_intel WHERE ip=?", (ip,)).fetchone()
    if existing:
        conn.execute("UPDATE ip_intel SET hits_since_cleared=0, ban_until=? WHERE ip=?", (ban_until, ip))
    else:
        conn.execute(
            "INSERT INTO ip_intel (ip, hits, last_seen, hits_since_cleared, ban_until) VALUES (?,0,?,0,?)",
            (ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ban_until)
        )
    conn.commit()
    conn.close()

    r = get_redis()
    if r:
        if ban_until == 0:
            r.set(f"knock:blocked:{ip}", 1)
        else:
            r.set(f"knock:blocked:{ip}", 1, ex=ban_until - now)

    dur_str = "permanently" if days == 0 else f"for {days} day(s)"
    print(f"🚫 Banned {ip} {dur_str}")


def cmd_unban(args):
    ip = args.unban
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("UPDATE ip_intel SET ban_until=NULL WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

    r = get_redis()
    if r:
        r.delete(f"knock:blocked:{ip}")

    print(f"✅ Unbanned {ip}")


def cmd_clear_all(args):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    count = conn.execute("SELECT COUNT(*) FROM ip_intel WHERE ban_until IS NOT NULL").fetchone()[0]
    conn.execute("UPDATE ip_intel SET ban_until=NULL WHERE ban_until IS NOT NULL")
    conn.commit()
    conn.close()

    r = get_redis()
    if r:
        deleted = 0
        for key in r.scan_iter("knock:blocked:*"):
            r.delete(key)
            deleted += 1
        print(f"✅ Cleared {count} ban(s) from SQLite, {deleted} key(s) from Redis")
    else:
        print(f"✅ Cleared {count} ban(s) from SQLite (Redis unavailable)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock IP ban manager")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List all banned IPs")
    group.add_argument("--ban", metavar="IP", help="Ban an IP address")
    group.add_argument("--unban", metavar="IP", help="Lift a ban")
    group.add_argument("--clear-all", action="store_true", help="Clear all bans")
    parser.add_argument("--days", type=int, default=0,
                        help="Ban duration in days (default: 0 = permanent, used with --ban)")
    args = parser.parse_args()

    if args.list:
        cmd_list(args)
    elif args.ban:
        cmd_ban(args)
    elif args.unban:
        cmd_unban(args)
    elif args.clear_all:
        cmd_clear_all(args)

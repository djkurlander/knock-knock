#!/usr/bin/env python3
"""SIP ban reprieve — bounded census reactivation.

Give currently-blocked, SIP-dominant IPs a small remaining budget so they
re-activate for a *bounded* SIP census, then auto-re-ban after ~(SIP MAX_KNOCKS −
--hits) more knocks. Dry-run by default; pass --apply to commit.

Targets ONLY IPs that are BOTH:
  (a) currently blocked  -> ban_until = 0 (permanent) or a future timestamp, and
  (b) SIP-dominant       -> proto=SIP is their top protocol in ip_intel_proto.

Leaves expired bans, non-SIP bans, lifetime `hits`, and `ban_count` untouched.
`ban_until` is set to NULL (un-banned) so they can dial again; the system re-dates
the ban automatically when each burns its budget. Best run AFTER expanding the RTP
port pool so the census burst can't starve the B2BUA bridge pool.
"""
import argparse
import os
import sys
import time
import sqlite3

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from constants import PROTO  # noqa: E402

SIP_PROTO = PROTO['SIP']
DB = os.path.join(_ROOT, os.environ.get('DB_DIR', 'data'), 'knock_knock.db')


def select_targets(conn):
    now = int(time.time())
    return conn.execute(
        """
        SELECT i.ip,
               (SELECT hits FROM ip_intel_proto WHERE ip = i.ip AND proto = ?) AS sip_hits,
               i.hits_since_cleared, i.ban_until, i.ban_count
        FROM ip_intel i
        WHERE (i.ban_until = 0 OR i.ban_until > ?)
          AND (SELECT hits FROM ip_intel_proto WHERE ip = i.ip AND proto = ?) =
              (SELECT MAX(hits) FROM ip_intel_proto WHERE ip = i.ip)
        ORDER BY sip_hits DESC
        """,
        (SIP_PROTO, now, SIP_PROTO),
    ).fetchall()


def main():
    ap = argparse.ArgumentParser(description="Bounded SIP-ban reprieve for a census window.")
    ap.add_argument('--apply', action='store_true', help='commit changes (default: dry-run)')
    ap.add_argument('--hits', type=int, default=1750,
                    help='hits_since_cleared to set (default 1750 -> ~250 knocks before re-ban)')
    args = ap.parse_args()

    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    targets = select_targets(conn)

    print(f"DB: {DB}")
    print(f"SIP-dominant, currently-blocked IPs to reprieve: {len(targets)}")
    print(f"set hits_since_cleared={args.hits}  ->  ~{2000 - args.hits} knocks before auto-re-ban\n")
    print(f"  {'ip':<18}{'sip_hits':>9}{'hsc_now':>9}  ban_until")
    for r in targets[:15]:
        bu = '0(perm)' if r['ban_until'] == 0 else time.strftime('%Y-%m-%d %H:%M', time.gmtime(r['ban_until']))
        print(f"  {r['ip']:<18}{r['sip_hits']:>9}{r['hits_since_cleared']:>9}  {bu}")
    if len(targets) > 15:
        print(f"  ... and {len(targets) - 15} more")

    if not args.apply:
        print("\nDRY RUN — no changes made. Re-run with --apply to commit.")
        conn.close()
        return

    ips = [r['ip'] for r in targets]
    conn.executemany("UPDATE ip_intel SET ban_until=NULL, hits_since_cleared=? WHERE ip=?",
                     [(args.hits, ip) for ip in ips])
    conn.commit()
    conn.close()

    import redis
    r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379,
                    db=int(os.environ.get('REDIS_DB', '0')), decode_responses=True)
    deleted = sum(r.delete(f"knock:blocked:{ip}") for ip in ips)
    print(f"\nAPPLIED: reprieved {len(ips)} IPs "
          f"(ban_until=NULL, hits_since_cleared={args.hits}); deleted {deleted} redis block keys.")


if __name__ == '__main__':
    main()

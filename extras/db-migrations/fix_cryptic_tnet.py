#!/usr/bin/env python3
"""Remove the Telnet ``<cryptic binary>`` credential noise from the intel tables.

Telnet is a raw line protocol with no command/handshake gate, so non-Telnet traffic on
port 23 (TLS ClientHellos, port scanners, other-protocol probes) was decoded into bogus
credentials and collapsed to the placeholder ``<cryptic binary>`` — which then topped the
password leaderboard. ``telnet_honeypot.py`` now drops these at capture (matching the
structural gating SSH/FTP/RDP/SMB already have); this script removes the *already
accumulated* Telnet contribution from the aggregated intel tables.

It is **surgical**: the same placeholder also appears legitimately for **SMTP** (real bots
that completed ``AUTH LOGIN``/``AUTH PLAIN`` then sent binary creds) and **RDP** (binary NLA
usernames). Those reach the credential stage only through a real protocol exchange, so they
are genuine attempts and are **preserved**. Only the Telnet (``proto=TNET``) part is removed.

The ALL tables (``pass_intel``/``user_intel``) are the per-proto sum, so the Telnet amount is
**subtracted** (read live from the proto row, so it stays exact even under concurrent SMTP/RDP
writes); an ALL row is deleted only if nothing else is left. The ``_proto`` Telnet rows are
deleted outright.

IMPORTANT: restart the honeypot with the Telnet gate live BEFORE running this, so the Telnet
placeholder count is frozen and cannot re-accumulate after cleanup. Idempotent — a second run
is a no-op once the Telnet rows are gone.

Dry-run is the default; use --apply to write. --purge-knocks additionally deletes the matching
per-knock rows from ``knocks_tnet`` (raw history only; the leaderboards read the intel tables,
not ``knocks_tnet``, so this is optional).

    python extras/db-migrations/fix_cryptic_tnet.py                 # dry-run
    python extras/db-migrations/fix_cryptic_tnet.py --apply
    python extras/db-migrations/fix_cryptic_tnet.py --apply --purge-knocks
"""
import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from constants import PROTO  # noqa: E402

PLACEHOLDER = "<cryptic binary>"
TNET = PROTO["TNET"]
DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "knock_knock.db"


def _scalar(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    return row[0] if row and row[0] is not None else 0


def _table_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _knocks_tnet_count(conn):
    if not _table_exists(conn, "knocks_tnet"):
        return 0
    return _scalar(conn, "SELECT COUNT(*) FROM knocks_tnet WHERE username=? OR password=?",
                   (PLACEHOLDER, PLACEHOLDER))


def report(conn):
    print(f"  pass_intel hits = {_scalar(conn, 'SELECT hits FROM pass_intel WHERE password=?', (PLACEHOLDER,))}")
    print(f"  user_intel hits = {_scalar(conn, 'SELECT hits FROM user_intel WHERE username=?', (PLACEHOLDER,))}")
    for proto, name in sorted((p, n) for n, p in PROTO.items()):
        ph = _scalar(conn, "SELECT hits FROM pass_intel_proto WHERE password=? AND proto=?", (PLACEHOLDER, proto))
        uh = _scalar(conn, "SELECT hits FROM user_intel_proto WHERE username=? AND proto=?", (PLACEHOLDER, proto))
        if ph or uh:
            print(f"    proto {proto} ({name}): pass={ph} user={uh}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB), help="path to knock_knock.db")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--purge-knocks", action="store_true",
                    help="also delete matching rows from knocks_tnet (raw history; optional)")
    args = ap.parse_args(argv)

    if not Path(args.db).exists():
        ap.error(f"database not found: {args.db}")

    conn = sqlite3.connect(args.db, timeout=30)
    print(f"Database: {args.db}")
    print(f"Target: remove Telnet (proto={TNET}) '{PLACEHOLDER}' contribution; preserve SMTP/RDP.\n")
    print("BEFORE:")
    report(conn)

    pass_tnet = _scalar(conn, "SELECT hits FROM pass_intel_proto WHERE password=? AND proto=?", (PLACEHOLDER, TNET))
    user_tnet = _scalar(conn, "SELECT hits FROM user_intel_proto WHERE username=? AND proto=?", (PLACEHOLDER, TNET))

    if not pass_tnet and not user_tnet:
        print("\nNothing to do — no Telnet placeholder rows (already clean).")
        conn.close()
        return 0

    if not args.apply:
        extra = f"  + {_knocks_tnet_count(conn)} knocks_tnet rows" if args.purge_knocks else ""
        print(f"\nDRY-RUN: would subtract Telnet pass={pass_tnet}, user={user_tnet} from the "
              f"aggregates and drop the Telnet proto rows.{extra}")
        print("Re-run with --apply. Restart the honeypot with the Telnet gate FIRST so the "
              "count is frozen.")
        conn.close()
        return 0

    knocks_deleted = 0
    try:
        conn.execute("BEGIN")
        conn.execute("UPDATE pass_intel SET hits = hits - ? WHERE password=?", (pass_tnet, PLACEHOLDER))
        conn.execute("UPDATE user_intel SET hits = hits - ? WHERE username=?", (user_tnet, PLACEHOLDER))
        conn.execute("DELETE FROM pass_intel_proto WHERE password=? AND proto=?", (PLACEHOLDER, TNET))
        conn.execute("DELETE FROM user_intel_proto WHERE username=? AND proto=?", (PLACEHOLDER, TNET))
        conn.execute("DELETE FROM pass_intel WHERE password=? AND hits<=0", (PLACEHOLDER,))
        conn.execute("DELETE FROM user_intel WHERE username=? AND hits<=0", (PLACEHOLDER,))
        if args.purge_knocks and _table_exists(conn, "knocks_tnet"):
            knocks_deleted = conn.execute(
                "DELETE FROM knocks_tnet WHERE username=? OR password=?", (PLACEHOLDER, PLACEHOLDER)
            ).rowcount
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise

    print(f"\nAPPLIED: removed Telnet pass={pass_tnet}, user={user_tnet}" +
          (f", knocks_tnet rows={knocks_deleted}" if args.purge_knocks else "") + ".")
    print("AFTER:")
    report(conn)
    conn.close()
    if knocks_deleted:
        print("\n(knocks_tnet rows deleted — run `VACUUM` or `dbtool.py --backup` to reclaim space.)")
    print("Leaderboard reflects this on the next ~60s stats-cache refresh.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

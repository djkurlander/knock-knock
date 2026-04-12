#!/usr/bin/env python3
"""
One-time migration: merge MAIL intel (proto_int=4) into SMTP intel (proto_int=2).

Run BEFORE deploying the code update that removes MAIL from the protocol list:
    python migrate_mail_to_smtp.py data/knock_knock.db

Safe to run multiple times — idempotent (DELETE WHERE proto=4 removes nothing on re-run).
"""
import sys
import sqlite3

TABLES = [
    # (table, key_col)
    ('user_intel_proto',    'username'),
    ('pass_intel_proto',    'password'),
    ('country_intel_proto', 'iso_code'),
    ('isp_intel_proto',     'isp'),
    ('ip_intel_proto',      'ip'),
]

MAIL_PROTO  = 4
SMTP_PROTO  = 2


def migrate(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    cur = conn.cursor()

    total_merged = 0
    total_deleted = 0

    for table, key_col in TABLES:
        # Check how many MAIL rows exist
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE proto = ?", (MAIL_PROTO,))
        mail_count = cur.fetchone()[0]
        if mail_count == 0:
            print(f"  {table}: no MAIL rows — skipping")
            continue

        # Merge MAIL rows into SMTP, summing hits and keeping latest last_seen
        cur.execute(f"""
            INSERT INTO {table} ({key_col}, proto, hits, last_seen)
                SELECT {key_col}, ?, hits, last_seen
                FROM {table} WHERE proto = ?
            ON CONFLICT({key_col}, proto) DO UPDATE SET
                hits      = hits + excluded.hits,
                last_seen = MAX(last_seen, excluded.last_seen)
        """, (SMTP_PROTO, MAIL_PROTO))
        merged = cur.rowcount

        # Delete MAIL rows now that they've been merged
        cur.execute(f"DELETE FROM {table} WHERE proto = ?", (MAIL_PROTO,))
        deleted = cur.rowcount

        conn.commit()
        print(f"  {table}: merged {mail_count} MAIL rows → SMTP, deleted {deleted}")
        total_merged += mail_count
        total_deleted += deleted

    conn.close()
    print(f"\n✅ Migration complete: {total_merged} rows merged, {total_deleted} rows deleted")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path/to/knock_knock.db>")
        sys.exit(1)
    migrate(sys.argv[1])

#!/usr/bin/env python3
"""
Migration: visitors.db v1 → v2

v1: one row per visit (id, timestamp, ip, city, region, country, iso_code, isp, asn, referrer, user_agent)
v2: one row per IP per day (ip, date, city, ..., visit_count, first_seen, last_seen)

Run once:
    python extras/db_migrations/migrate_visitors_v2.py
    python extras/db_migrations/migrate_visitors_v2.py --db /path/to/visitors.db
"""
import argparse
import sqlite3
from pathlib import Path

def migrate(db_path):
    print(f"Migrating {db_path}...")
    conn = sqlite3.connect(db_path)

    # Check if already migrated
    cols = [r[1] for r in conn.execute("PRAGMA table_info(visitors)").fetchall()]
    if 'date' in cols:
        print("Already migrated (date column exists). Nothing to do.")
        conn.close()
        return

    if 'timestamp' not in cols:
        print("ERROR: Unrecognized schema — neither v1 nor v2.")
        conn.close()
        return

    print("Counting rows...")
    total = conn.execute("SELECT COUNT(*) FROM visitors").fetchone()[0]
    print(f"  {total} rows to migrate")

    print("Creating new table...")
    conn.execute("""CREATE TABLE visitors_v2 (
        ip TEXT NOT NULL,
        date TEXT NOT NULL,
        city TEXT,
        region TEXT,
        country TEXT,
        iso_code TEXT,
        isp TEXT,
        asn INTEGER,
        referrer TEXT,
        user_agent TEXT,
        visit_count INTEGER NOT NULL DEFAULT 1,
        first_seen DATETIME,
        last_seen DATETIME,
        PRIMARY KEY (ip, date)
    )""")

    print("Migrating data...")
    conn.execute("""
        INSERT INTO visitors_v2 (ip, date, city, region, country, iso_code, isp, asn, referrer, user_agent,
                                  visit_count, first_seen, last_seen)
        SELECT ip,
               DATE(timestamp) as date,
               city, region, country, iso_code, isp, asn,
               referrer, user_agent,
               COUNT(*) as visit_count,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM visitors
        GROUP BY ip, DATE(timestamp)
    """)

    migrated = conn.execute("SELECT COUNT(*) FROM visitors_v2").fetchone()[0]
    print(f"  {migrated} rows in new table")

    print("Swapping tables...")
    conn.execute("DROP TABLE visitors")
    conn.execute("ALTER TABLE visitors_v2 RENAME TO visitors")
    conn.commit()
    conn.close()
    print("Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(Path(__file__).resolve().parent.parent.parent / "data" / "visitors.db"))
    args = parser.parse_args()
    migrate(args.db)

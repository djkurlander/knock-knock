#!/usr/bin/env python3
"""Knock-knock database management tool."""

import argparse
import os
import sqlite3
import sys

DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'

def list_tables(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    tables = [row[0] for row in cur.fetchall()]
    if not tables:
        print("No tables found.")
        conn.close()
        return
    for table in tables:
        cur.execute(f"SELECT COUNT(*) FROM [{table}]")
        count = cur.fetchone()[0]
        print(f"  {table:30s} {count:>10,} rows")
    # DB file size
    conn.close()
    size = os.path.getsize(db_path)
    if size >= 1_048_576:
        print(f"\nDB size: {size / 1_048_576:.1f} MB")
    else:
        print(f"\nDB size: {size / 1024:.0f} KB")

def backup_db(db_path, name):
    dest = os.path.join(os.path.dirname(db_path), name)
    if os.path.exists(dest):
        print(f"Error: {dest} already exists", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    dest_conn = sqlite3.connect(dest)
    conn.backup(dest_conn)
    dest_conn.execute("VACUUM")
    dest_conn.close()
    conn.close()
    size = os.path.getsize(dest)
    if size >= 1_048_576:
        print(f"Backed up to {dest} ({size / 1_048_576:.1f} MB)")
    else:
        print(f"Backed up to {dest} ({size / 1024:.0f} KB)")

def remove_knocks(db_path, protos, skip_confirm=False):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Find existing knock tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'knocks_%'")
    existing = [row[0] for row in cur.fetchall()]
    if protos is None:
        # Remove all knock tables
        targets = existing
    else:
        targets = [f"knocks_{p.strip().lower()}" for p in protos.split(',')]
        missing = [t for t in targets if t not in existing]
        if missing:
            print(f"Warning: tables not found: {', '.join(missing)}", file=sys.stderr)
        targets = [t for t in targets if t in existing]
    if not targets:
        print("No knock tables to remove.")
        conn.close()
        return
    # Show what will be dropped
    total_rows = 0
    for table in sorted(targets):
        cur.execute(f"SELECT COUNT(*) FROM [{table}]")
        count = cur.fetchone()[0]
        total_rows += count
        print(f"  DROP {table} ({count:,} rows)")
    print(f"\nThis will delete {total_rows:,} rows across {len(targets)} table(s).")
    if not skip_confirm:
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer != 'y':
            print("Aborted.")
            conn.close()
            return
    for table in targets:
        cur.execute(f"DROP TABLE [{table}]")
    conn.commit()
    print("Reclaiming disk space...", end=" ", flush=True)
    cur.execute("VACUUM")
    conn.close()
    size = os.path.getsize(db_path)
    if size >= 1_048_576:
        print(f"done. DB size: {size / 1_048_576:.1f} MB")
    else:
        print(f"done. DB size: {size / 1024:.0f} KB")

def main():
    parser = argparse.ArgumentParser(description='Knock-knock database management tool.')
    parser.add_argument('--list-tables', action='store_true',
                        help='List all tables with row counts')
    parser.add_argument('--backup', metavar='NAME',
                        help='Backup database to data/NAME (safe with concurrent writers)')
    parser.add_argument('--remove-knocks', nargs='?', const=None, default=False, metavar='PROTOS',
                        help='Remove knock tables and VACUUM. Optional: comma-separated protocols (e.g. SIP,SMTP). Default: all')
    parser.add_argument('--yes', '-y', action='store_true',
                        help='Skip confirmation prompts')
    args = parser.parse_args()

    if not os.path.exists(DB_PATH):
        print(f"Error: {DB_PATH} not found", file=sys.stderr)
        sys.exit(1)

    if not any([args.list_tables, args.backup, args.remove_knocks is not False]):
        parser.print_help()
        sys.exit(1)

    if args.backup:
        backup_db(DB_PATH, args.backup)

    if args.remove_knocks is not False:
        remove_knocks(DB_PATH, args.remove_knocks, skip_confirm=args.yes)

    if args.list_tables:
        list_tables(DB_PATH)

if __name__ == "__main__":
    main()

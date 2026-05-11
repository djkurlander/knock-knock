#!/usr/bin/env python3
"""Bring an existing knock-knock SQLite database up to the current schema."""

import argparse
from datetime import datetime
import os
import socket
import sqlite3
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from constants import PROTO, PROTOCOL_META


DB_PATH = os.environ.get("DB_DIR", "data") + "/knock_knock.db"
SOURCE_ID = os.environ.get("SOURCE_ID", socket.gethostname().split(".")[0])

COMMON_KNOCK_COLS = [
    "ip_address TEXT", "iso_code TEXT", "city TEXT", "region TEXT",
    "country TEXT", "isp TEXT", "asn TEXT", "source INTEGER DEFAULT 0",
]
USER_PASS_PROTOS = {k: PROTO[k] for k in ("SSH", "TNET", "FTP")}


def column_sql(column):
    return f"{column.name} {column.type}"


def table_exists(cur, table):
    return cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone() is not None


def quote_ident(name):
    return '"' + str(name).replace('"', '""') + '"'


def table_columns(cur, table):
    if not table_exists(cur, table):
        return []
    return [row[1] for row in cur.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()]


def ensure_columns(cur, table, columns):
    if not table_exists(cur, table):
        return
    existing = set(table_columns(cur, table))
    for name, coltype in columns:
        if name not in existing:
            cur.execute(f"ALTER TABLE {quote_ident(table)} ADD COLUMN {quote_ident(name)} {coltype}")
            print(f"  {table}: added column {name}")


def create_current_schema(cur):
    """Create current tables/indexes so later migrations have valid targets."""
    for meta in PROTOCOL_META.values():
        definition = meta.get("definition")
        if not definition:
            continue
        for extra in definition.extra_tables:
            extra_cols = [column_sql(column) for column in extra.columns]
            cur.execute(f"CREATE TABLE IF NOT EXISTS {quote_ident(extra.name)} ({', '.join(extra_cols)})")

    cur.execute("CREATE TABLE IF NOT EXISTS user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER)")
    cur.execute("""CREATE TABLE IF NOT EXISTS ip_intel (
        ip TEXT PRIMARY KEY,
        hits INTEGER,
        last_seen DATETIME,
        lat REAL,
        lng REAL,
        hits_since_cleared INTEGER NOT NULL DEFAULT 0,
        ban_until INTEGER,
        ban_count INTEGER NOT NULL DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS sources (
        id           INTEGER PRIMARY KEY,
        source_id    TEXT UNIQUE NOT NULL,
        display_name TEXT,
        hits         INTEGER NOT NULL DEFAULT 0,
        first_seen   DATETIME,
        last_seen    DATETIME,
        active       INTEGER NOT NULL DEFAULT 1
    )""")
    cur.execute("INSERT OR IGNORE INTO sources (id, source_id) VALUES (0, ?)", (SOURCE_ID,))

    cur.execute("CREATE TABLE IF NOT EXISTS monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0)")

    cur.execute("CREATE TABLE IF NOT EXISTS user_intel_proto (username TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, PRIMARY KEY (username, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel_proto (password TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, PRIMARY KEY (password, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel_proto (iso_code TEXT, proto INTEGER, country TEXT, hits INTEGER, last_seen DATETIME, PRIMARY KEY (iso_code, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel_proto (isp TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, asn INTEGER, PRIMARY KEY (isp, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_intel_proto (ip TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL, PRIMARY KEY (ip, proto))")

    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_intel_hits ON user_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pass_intel_hits ON pass_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country_intel_hits ON country_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_isp_intel_hits ON isp_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_hits ON ip_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_intel_proto_hits ON user_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pass_intel_proto_hits ON pass_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country_intel_proto_hits ON country_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_isp_intel_proto_hits ON isp_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_proto_hits ON ip_intel_proto(proto, hits DESC)")


def migrate_generic_knocks(cur):
    # Change addressed: individual knock storage moved from one generic "knocks"
    # table to per-protocol tables such as knocks_ssh and knocks_ftp. Old generic
    # rows only preserved username/password, so only user/pass protocols can be
    # migrated with useful protocol-specific fields.
    if not table_exists(cur, "knocks"):
        return

    knock_cols = table_columns(cur, "knocks")
    has_proto = "proto" in knock_cols
    migrated = 0
    for pname, pidx in USER_PASS_PROTOS.items():
        where = f"WHERE proto = {pidx}" if has_proto else ("" if pname == "SSH" else "WHERE 0")
        count = cur.execute(f"SELECT COUNT(*) FROM knocks {where}").fetchone()[0]
        if count == 0:
            continue
        table = f"knocks_{pname.lower()}"
        cols_def = [
            "id INTEGER PRIMARY KEY AUTOINCREMENT",
            "timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))",
        ]
        cols_def += COMMON_KNOCK_COLS + ["username TEXT", "password TEXT"]
        cur.execute(f"CREATE TABLE IF NOT EXISTS {quote_ident(table)} ({', '.join(cols_def)})")
        cur.execute(f"""INSERT INTO {table}
            (timestamp, ip_address, iso_code, city, region, country, isp, asn, username, password)
            SELECT timestamp, ip_address, iso_code, city, region, country, isp, asn, username, password
            FROM knocks {where}""")
        migrated += cur.rowcount

    cur.execute(f"DROP TABLE {quote_ident('knocks')}")
    print(f"  knocks: migrated {migrated} rows into per-protocol tables and dropped old table")


def migrate_column_additions(cur):
    # Change addressed: the IP blocklist feature stores ban state in ip_intel.
    # Databases created before that feature lack these columns.
    ensure_columns(cur, "ip_intel", [
        ("hits_since_cleared", "INTEGER NOT NULL DEFAULT 0"),
        ("ban_until", "INTEGER"),
        ("ban_count", "INTEGER NOT NULL DEFAULT 0"),
    ])

    # Change addressed: multi-source ingest added metadata to sources so the UI
    # can show display names, first/last seen times, hit counts, and active state.
    ensure_columns(cur, "sources", [
        ("display_name", "TEXT"),
        ("hits", "INTEGER NOT NULL DEFAULT 0"),
        ("first_seen", "DATETIME"),
        ("last_seen", "DATETIME"),
        ("active", "INTEGER NOT NULL DEFAULT 1"),
    ])
    cur.execute("INSERT OR IGNORE INTO sources (id, source_id) VALUES (0, ?)", (SOURCE_ID,))

    # Change addressed: individual knock tables gained a source column when
    # multi-source ingest was added. Add it to any existing knocks_* table.
    tables = [
        row[0] for row in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'knocks_%'"
        ).fetchall()
    ]
    for table in tables:
        ensure_columns(cur, table, [("source", "INTEGER DEFAULT 0")])

    # Change addressed: protocol definitions can add columns or extra tables.
    # Existing installations need those declarative columns added once.
    for meta in PROTOCOL_META.values():
        definition = meta.get("definition")
        if not definition:
            continue
        if definition.knock_table:
            ensure_columns(
                cur,
                definition.knock_table,
                [(column.name, column.type) for column in definition.columns],
            )
        for extra in definition.extra_tables:
            ensure_columns(cur, extra.name, [(column.name, column.type) for column in extra.columns])


def seed_proto_intel(cur):
    # Change addressed: leaderboards were originally stored only in aggregate
    # tables. Per-protocol leaderboards were added later; old aggregate rows are
    # treated as SSH because SSH was the original single-protocol default.
    has_all = cur.execute("SELECT 1 FROM ip_intel LIMIT 1").fetchone()
    has_proto = cur.execute("SELECT 1 FROM ip_intel_proto LIMIT 1").fetchone()
    if not has_all or has_proto:
        return

    cur.execute("INSERT OR REPLACE INTO user_intel_proto (username, proto, hits, last_seen) SELECT username, 0, hits, last_seen FROM user_intel")
    cur.execute("INSERT OR REPLACE INTO pass_intel_proto (password, proto, hits, last_seen) SELECT password, 0, hits, last_seen FROM pass_intel")
    cur.execute("INSERT OR REPLACE INTO country_intel_proto (iso_code, proto, country, hits, last_seen) SELECT iso_code, 0, country, hits, last_seen FROM country_intel")
    cur.execute("INSERT OR REPLACE INTO isp_intel_proto (isp, proto, hits, last_seen, asn) SELECT isp, 0, hits, last_seen, asn FROM isp_intel")
    cur.execute("INSERT OR REPLACE INTO ip_intel_proto (ip, proto, hits, last_seen, lat, lng) SELECT ip, 0, hits, last_seen, lat, lng FROM ip_intel")
    print("  *_intel_proto: seeded from aggregate intel tables as SSH")


def migrate_heartbeats(cur):
    # Change addressed: monitor_heartbeats used to store one row per heartbeat
    # timestamp. The current schema stores a single uptime_minutes counter.
    cols = table_columns(cur, "monitor_heartbeats")
    if "timestamp" in cols:
        old_count = cur.execute("SELECT COUNT(*) FROM monitor_heartbeats").fetchone()[0]
        cur.execute("DROP TABLE monitor_heartbeats")
        cur.execute("CREATE TABLE monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0)")
        cur.execute("INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, ?)", (old_count,))
        print(f"  monitor_heartbeats: converted {old_count} timestamp rows to uptime_minutes")

    # Per-protocol uptime columns are now runtime schema: monitor.py adds only
    # the columns needed by the enabled protocols on startup.


def backup_db(db_path, backup_name):
    dest = backup_name
    if not os.path.isabs(dest):
        dest = os.path.join(os.path.dirname(db_path), dest)
    if os.path.exists(dest):
        raise FileExistsError(f"backup already exists: {dest}")

    src = sqlite3.connect(db_path)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    print(f"Backed up {db_path} to {dest}")


def update_db(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.fetchone()
        migrate_generic_knocks(cur)
        create_current_schema(cur)
        migrate_column_additions(cur)
        seed_proto_intel(cur)
        migrate_heartbeats(cur)
        conn.commit()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Update a knock-knock SQLite database schema.")
    parser.add_argument("db_path", nargs="?", default=DB_PATH, help="database path")
    parser.add_argument(
        "--backup",
        metavar="NAME",
        help="backup name/path before updating; default is timestamped in the DB directory",
    )
    parser.add_argument("--no-backup", action="store_true", help="skip the default pre-update backup")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"Error: {args.db_path} not found", file=sys.stderr)
        return 1
    if args.backup and args.no_backup:
        print("Error: --backup and --no-backup cannot be used together", file=sys.stderr)
        return 1

    if not args.no_backup:
        backup_name = args.backup
        if backup_name is None:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_name = f"knock_knock.pre-updatedb.{stamp}.db"
        backup_db(args.db_path, backup_name)

    update_db(args.db_path)
    print("Database update complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())

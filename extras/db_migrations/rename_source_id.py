#!/usr/bin/env python3
"""
Rename or merge a SOURCE_ID in knock_knock.db and Redis.

If the target ID already exists, hits are merged and the old entry is deleted.
Knock rows reference sources by integer ID, so the script remaps those too.

Usage:
    python extras/db_migrations/rename_source_id.py --from ams2 --to AMS2
    python extras/db_migrations/rename_source_id.py --from ams2 --to AMS2 --db /path/to/knock_knock.db
    python extras/db_migrations/rename_source_id.py --from ams2 --to AMS2 --dry-run
"""
import argparse
import os
import sqlite3
from pathlib import Path


def get_redis():
    try:
        import redis
        r = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=6379,
            db=int(os.environ.get('REDIS_DB', '0')),
            decode_responses=True,
        )
        r.ping()
        return r
    except Exception as e:
        print(f"⚠️  Redis unavailable ({e}) — skipping Redis updates")
        return None


def rename_in_sqlite(db_path, old_id, new_id, dry_run):
    conn = sqlite3.connect(db_path, timeout=10)

    # Find all knocks_* tables
    knock_tables = [
        row[0] for row in
        conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'knocks_%'").fetchall()
    ]

    # Look up integer IDs for old and new source
    old_row = conn.execute("SELECT id, hits FROM sources WHERE source_id=?", (old_id,)).fetchone()
    if not old_row:
        print(f"⚠️  No source '{old_id}' found in sources table — nothing to do.")
        conn.close()
        return
    old_int, old_hits = old_row
    print(f"Found source '{old_id}': id={old_int}, {old_hits} hits")

    new_row = conn.execute("SELECT id, hits FROM sources WHERE source_id=?", (new_id,)).fetchone()
    if new_row:
        new_int, new_hits = new_row
        merged_hits = old_hits + new_hits
        print(f"Target '{new_id}' already exists: id={new_int}, {new_hits} hits — will merge (total: {merged_hits})")
    else:
        new_int = None
        print(f"Target '{new_id}' does not exist — simple rename")

    # Count knock rows to be updated (by integer source ID)
    knock_counts = {}
    for table in knock_tables:
        count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE source=?", (old_int,)).fetchone()[0]
        if count:
            knock_counts[table] = count

    if knock_counts:
        print(f"Knock rows to update (source={old_int}):")
        for table, count in knock_counts.items():
            print(f"  {table}: {count} rows")
    else:
        print(f"No rows with source={old_int} in any knocks_* table")

    if dry_run:
        print("Dry run — no changes made.")
        conn.close()
        return

    if new_int is not None:
        # Merge: remap knock rows to new_int, update hits, delete old entry
        for table in knock_tables:
            conn.execute(f"UPDATE {table} SET source=? WHERE source=?", (new_int, old_int))
        conn.execute("UPDATE sources SET hits=? WHERE source_id=?", (merged_hits, new_id))
        conn.execute("DELETE FROM sources WHERE source_id=?", (old_id,))
        print(f"✅ SQLite sources: merged '{old_id}' (id={old_int}) into '{new_id}' (id={new_int}), hits: {merged_hits}")
    else:
        # Simple rename — just update the source_id string, integer ID stays the same
        conn.execute("UPDATE sources SET source_id=? WHERE source_id=?", (new_id, old_id))
        print(f"✅ SQLite sources: renamed '{old_id}' → '{new_id}' (id={old_int} unchanged)")

    conn.commit()
    conn.close()

    if knock_counts:
        print(f"✅ SQLite knocks: updated {sum(knock_counts.values())} rows across {len(knock_counts)} table(s)")


def rename_in_redis(r, old_id, new_id, dry_run):
    old_count = r.hget("knock:source_counts", old_id)
    if old_count is None:
        print(f"⚠️  No entry for '{old_id}' in knock:source_counts")
        return

    new_count = r.hget("knock:source_counts", new_id)
    old_count = int(old_count)

    if new_count:
        merged = old_count + int(new_count)
        print(f"Found knock:source_counts['{old_id}'] = {old_count}, '{new_id}' = {new_count} — will merge (total: {merged})")
        if not dry_run:
            r.hset("knock:source_counts", new_id, merged)
            r.hdel("knock:source_counts", old_id)
            print(f"✅ Redis: merged '{old_id}' into '{new_id}' (hits: {merged})")
    else:
        print(f"Found knock:source_counts['{old_id}'] = {old_count}")
        if not dry_run:
            r.hset("knock:source_counts", new_id, old_count)
            r.hdel("knock:source_counts", old_id)
            print(f"✅ Redis: renamed '{old_id}' → '{new_id}'")

    if dry_run:
        print("Dry run — no Redis changes made.")


def main():
    parser = argparse.ArgumentParser(description="Rename or merge a SOURCE_ID in knock_knock.db and Redis")
    parser.add_argument("--from", dest="old_id", required=True, help="Current (wrong) source ID")
    parser.add_argument("--to", dest="new_id", required=True, help="Target source ID")
    parser.add_argument("--db", default=None, help="Path to knock_knock.db (default: data/knock_knock.db)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without applying")
    args = parser.parse_args()

    db_path = args.db or str(Path(__file__).resolve().parent.parent.parent / "data" / "knock_knock.db")

    if not Path(db_path).exists():
        print(f"Error: database not found at {db_path}")
        raise SystemExit(1)

    if args.dry_run:
        print("=== DRY RUN ===")

    print(f"Renaming/merging source '{args.old_id}' → '{args.new_id}'")
    print(f"Database: {db_path}")
    print()

    rename_in_sqlite(db_path, args.old_id, args.new_id, args.dry_run)

    print()
    r = get_redis()
    if r:
        rename_in_redis(r, args.old_id, args.new_id, args.dry_run)

    if not args.dry_run:
        print()
        print("Done. Restart knock-monitor to rebuild in-memory source mappings.")


if __name__ == "__main__":
    main()

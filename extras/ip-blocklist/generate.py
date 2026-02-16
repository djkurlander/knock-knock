#!/usr/bin/env python3
"""Generate IP blocklist files from ip_intel for public download."""

import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / os.environ.get('DB_DIR', 'data') / 'knock_knock.db'
STATIC_DIR = PROJECT_ROOT / 'static'

REPORTS = [
    ('ip-blocklist-month.txt', 30),
    ('ip-blocklist-year.txt', 365),
]


def generate(db_path, output_dir):
    conn = sqlite3.connect(db_path)
    for filename, days in REPORTS:
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        rows = conn.execute(
            'SELECT ip FROM ip_intel WHERE last_seen >= ? ORDER BY last_seen DESC',
            (cutoff,),
        ).fetchall()
        out = output_dir / filename
        out.write_text('\n'.join(row[0] for row in rows) + '\n')
        print(f'{filename}: {len(rows)} IPs')
    conn.close()


if __name__ == '__main__':
    if not DB_PATH.exists():
        print(f'Error: database not found at {DB_PATH}')
        raise SystemExit(1)
    generate(DB_PATH, STATIC_DIR)

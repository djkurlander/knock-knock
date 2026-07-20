#!/usr/bin/env python3
"""Backfill inline knocks_smtp bodies into the deduped smtp_body_intel table (v3).

Before v3 each SMTP body was stored inline in ``knocks_smtp.body`` — body-only, truncated
at 2 KB, and NOT self-redacted for base64-hidden IPs. v3 moves bodies into a deduped
``smtp_body_intel`` table keyed by ``sha256``, links each knock via ``knocks_smtp.body_id``,
and stores bodies **self-redacted** to stable ``<target-*>`` placeholders. This backfills
existing rows: for each row
with an inline body and no ``body_id`` it retro-redacts the body, dedups it into
``smtp_body_intel`` (``content_type``/``transfer_encoding`` NULL — headers weren't captured
historically), sets ``body_id``, and NULLs the original inline body (removing the
un-redacted copy). Idempotent; dry-run by default.

Redaction is header-less (encodings unknown), so it is best-effort: a literal pass over the
server's identifiers plus a base64-run scan (decode each base64-looking run, redact, re-encode
only runs that actually contained an identifier, so everything else stays byte-identical and
dedup still holds).

Identity — this is the important part (see self_redaction.py):
  * default    — reuse the monitor's OWN redaction (env ``REDACT_SELF_*`` **plus** runtime
                 discovery: outbound IP, getaddrinfo, ``hostname -I``, PTR hosts, derived
                 domains). ``.env`` is loaded first so env supplements are present, exactly
                 as systemd/docker would inject them. Correct for a server scrubbing its OWN
                 (``source=0``) mail. ``updatedb.py`` calls into here for that case.
  * aggregator — feeder-sourced rows (``source!=0``) need OTHER servers' identifiers, which
                 this box cannot discover. Pass the fleet set via ``--fleet FILE`` or
                 ``--self-ip/--self-host/--self-domain`` (repeatable); applied as a union.

    python extras/db-migrations/smtp_body_backfill.py                       # dry-run, local identity
    python extras/db-migrations/smtp_body_backfill.py --apply
    python extras/db-migrations/smtp_body_backfill.py --apply --source 3 --fleet fleet.txt
    python extras/db-migrations/smtp_body_backfill.py --apply --keep-body-column   # keep the emptied column
"""
import argparse
import base64
import binascii
import hashlib
import os
import re
import socket
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from self_redaction import (build_self_redaction_patterns, build_patterns_from_literals,  # noqa: E402
                            apply_redaction, discover_self_identifiers)

DEFAULT_DB = REPO / "data" / "knock_knock.db"
_B64_RUN = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')


def load_dotenv(path=None):
    """Load .env into the environment (without overriding real env) so the monitor's
    discovery picks up the same REDACT_SELF_* supplements systemd/docker would inject."""
    path = Path(path) if path else (REPO / ".env")
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def redact_body(body, redact, b64_scan=True):
    """Literal redact + best-effort base64-run scan. `redact` is a cached str->str function."""
    out = redact(body)
    if not b64_scan or not out:
        return out

    def _sub(m):
        run = m.group(0)
        try:
            dec = base64.b64decode(run).decode("utf-8", "replace")   # complete/padded run
        except (binascii.Error, ValueError):
            b = run.rstrip("=")                                       # truncated mid-group?
            b = b[:len(b) - (len(b) % 4)]                             # keep complete 4-char groups
            if not b:
                return run
            try:
                dec = base64.b64decode(b).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                return run
        red = redact(dec)
        if red == dec:
            return run   # nothing to hide here → leave byte-identical (preserves dedup)
        return base64.encodebytes(red.encode("utf-8", "replace")).decode("ascii").strip()

    return _B64_RUN.sub(_sub, out)


def _table_exists(conn, name):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (name,)).fetchone() is not None


def _columns(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def ensure_schema(conn):
    if "body_id" not in _columns(conn, "knocks_smtp"):
        conn.execute("ALTER TABLE knocks_smtp ADD COLUMN body_id INTEGER")
    if not _table_exists(conn, "smtp_body_intel"):
        conn.execute("""CREATE TABLE smtp_body_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT UNIQUE, body TEXT,
            content_type TEXT, transfer_encoding TEXT, hits INTEGER,
            first_seen DATETIME, last_seen DATETIME)""")


def pending(conn, where_extra=""):
    if not _table_exists(conn, "knocks_smtp") or "body" not in _columns(conn, "knocks_smtp"):
        return 0
    return conn.execute(
        "SELECT COUNT(*) FROM knocks_smtp WHERE body IS NOT NULL AND body_id IS NULL "
        + where_extra).fetchone()[0]


def maybe_drop_body_column(conn, keep=False):
    """Drop the now-empty knocks_smtp.body column once EVERY row is backfilled — gated on
    GLOBAL pending == 0 (all sources), so on an aggregator it only fires after the fleet
    backfill has swept the feeder rows too. No-op if keep=True, if any rows still need
    backfilling, if the column is already gone, or on SQLite < 3.35 (graceful — the empty
    column just stays). Returns True iff it dropped."""
    if keep or pending(conn) != 0 or "body" not in _columns(conn, "knocks_smtp"):
        return False
    try:
        conn.execute("ALTER TABLE knocks_smtp DROP COLUMN body")
        conn.commit()
        return True
    except sqlite3.OperationalError as e:
        print(f"  kept knocks_smtp.body (DROP COLUMN needs SQLite >= 3.35: {e})")
        return False


def backfill(conn, redact, where_extra="", batch=2000, b64_scan=True, progress=None):
    """Backfill rows matching (body set, body_id NULL) [+ where_extra]. Commits per batch;
    idempotent. `redact` is a cached str->str function. Returns rows backfilled."""
    ensure_schema(conn)
    done = 0
    while True:
        rows = conn.execute(
            "SELECT id, timestamp, body FROM knocks_smtp "
            "WHERE body IS NOT NULL AND body_id IS NULL " + where_extra +
            " ORDER BY id LIMIT ?", (batch,)).fetchall()
        if not rows:
            break
        conn.execute("BEGIN")
        try:
            for rid, ts, body in rows:
                red = redact_body(body, redact, b64_scan)
                sha = hashlib.sha256(red.encode("utf-8", "replace")).hexdigest()
                conn.execute(
                    """INSERT INTO smtp_body_intel (sha256, body, content_type, transfer_encoding,
                                                    hits, first_seen, last_seen)
                       VALUES (?, ?, NULL, NULL, 1, ?, ?)
                       ON CONFLICT(sha256) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen""",
                    (sha, red, ts, ts))
                bid = conn.execute("SELECT id FROM smtp_body_intel WHERE sha256=?", (sha,)).fetchone()[0]
                conn.execute("UPDATE knocks_smtp SET body_id=?, body=NULL WHERE id=?", (bid, rid))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        done += len(rows)
        if progress:
            progress(done)
    return done


def _fleet_patterns(args):
    ips, hosts, domains = list(args.self_ip), list(args.self_host), list(args.self_domain)
    if args.fleet:
        for line in Path(args.fleet).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            kind, val = (p.strip() for p in line.split("=", 1))
            {"ip": ips, "host": hosts, "domain": domains}.get(kind, []).append(val)
    return build_patterns_from_literals(ips=ips, hosts=hosts, domains=domains)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--source", type=int, help="restrict to this source id (e.g. a feeder)")
    ap.add_argument("--self-ip", action="append", default=[], help="fleet self IP (repeatable)")
    ap.add_argument("--self-host", action="append", default=[], help="fleet self host (repeatable)")
    ap.add_argument("--self-domain", action="append", default=[], help="fleet self domain (repeatable)")
    ap.add_argument("--fleet", help="file of 'ip=/host=/domain=' lines (aggregator fleet identity)")
    ap.add_argument("--print-identity", action="store_true",
                    help="print this server's resolved self-identifiers (discovery + .env) as "
                         "--fleet file lines and exit; run on each feeder to build the aggregator fleet file")
    ap.add_argument("--no-base64-scan", action="store_true", help="skip the base64-run redaction scan")
    ap.add_argument("--keep-body-column", action="store_true",
                    help="keep the now-empty knocks_smtp.body column (default: drop it once ALL "
                         "rows are backfilled; needs SQLite >= 3.35, graceful no-op otherwise)")
    ap.add_argument("--batch", type=int, default=2000)
    args = ap.parse_args(argv)

    if args.print_identity:
        load_dotenv()
        source_id = os.environ.get("SOURCE_ID", socket.gethostname().split(".")[0])
        ips, hosts, suffixes = discover_self_identifiers()
        print(f"# identity for source '{source_id}' (host {socket.gethostname()}) — discovery + .env")
        print("# paste each feeder's block into the aggregator --fleet file: redaction unions all")
        print("# identifiers; the 'source=' line keys the block to knocks_smtp.source so a knock's")
        print("# body can later be reconstructed by reversing <target-*> to THAT source's identity.")
        print(f"source={source_id}")
        for v in sorted(ips):
            print(f"ip={v}")
        for v in sorted(hosts):
            print(f"host={v}")
        for v in sorted(suffixes):
            print(f"domain={v}")
        return 0

    if not Path(args.db).exists():
        ap.error(f"database not found: {args.db}")

    fleet_mode = bool(args.fleet or args.self_ip or args.self_host or args.self_domain)
    if fleet_mode:
        patterns = _fleet_patterns(args)
        ident = "fleet (explicit identifiers)"
    else:
        load_dotenv()
        patterns = build_self_redaction_patterns()
        ident = "local (this server's env + discovery)"
    redact = lambda s: apply_redaction(s, patterns)  # noqa: E731 — cached patterns, cheap

    where = f"AND source={int(args.source)}" if args.source is not None else ""
    conn = sqlite3.connect(args.db, timeout=60)
    n = pending(conn, where)
    print(f"Database: {args.db}")
    print(f"Redaction identity: {ident} — {len(patterns)} patterns")
    if not patterns:
        print("WARNING: no self identifiers resolved — bodies will be moved/deduped WITHOUT "
              "self-redaction. Set REDACT_SELF_* or pass --self-ip/--fleet if this server "
              "appears in captured mail.")
    print(f"Rows to backfill (body set, body_id NULL{', source '+str(args.source) if args.source is not None else ''}): {n}\n")
    if n == 0:
        print("Nothing to backfill.")
        conn.close()
        return 0

    if not args.apply:
        print("DRY-RUN — re-run with --apply. (once ALL rows are backfilled it drops the now-empty "
              "knocks_smtp.body column; --keep-body-column to keep it.)")
        conn.close()
        return 0

    done = backfill(conn, redact, where_extra=where, batch=args.batch,
                    b64_scan=not args.no_base64_scan, progress=lambda d: print(f"  ...{d} rows"))
    distinct = conn.execute("SELECT COUNT(*) FROM smtp_body_intel").fetchone()[0]
    print(f"\nAPPLIED: backfilled {done} rows into {distinct} distinct smtp_body_intel rows; "
          f"inline bodies scrubbed (body=NULL).")
    if maybe_drop_body_column(conn, keep=args.keep_body_column):
        print("Dropped now-empty knocks_smtp.body column.")
    conn.close()
    print("Run `VACUUM` or `dbtool.py --backup` to reclaim space from the cleared bodies.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

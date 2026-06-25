#!/usr/bin/env python3
"""Relabel NANP toll-free dial targets in dial_intel: 'International Network' → 'North
American Toll-Free'.

Toll-free numbers are non-geographic, so libphonenumber returns no country name and the
SIP honeypot used to fall back to the generic 'International Network'. The honeypot now
labels NANP toll-free as 'North American Toll-Free' (sip_honeypot.py), but existing
`dial_intel` rows keep the old label — and because the in-memory dial cache is seeded
from `dial_intel` at startup and short-circuits recomputation, already-seen numbers never
pick up the new label on their own. This backfills the stored rows.

Surgical & parser-validated: it recomputes each candidate via the honeypot's own
`parse_dial_country()` and updates only rows that the live code classifies as
'North American Toll-Free'. Genuine international networks (+800/+870, malformed numbers)
keep 'International Network'.

After applying, restart the honeypot (`./restart.sh`) so the dial cache re-seeds from the
corrected `dial_intel`.

Dry-run is the default; use --apply to write.

    python extras/db-migrations/fix_tollfree_labels.py            # dry-run
    python extras/db-migrations/fix_tollfree_labels.py --apply
"""
import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "knock_knock.db"
OLD_LABEL = "International Network"
NEW_LABEL = "North American Toll-Free"

sys.path.insert(0, str(ROOT / "honeypots"))
import sip_honeypot as s  # noqa: E402  (provides parse_dial_country)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB), help="path to knock_knock.db")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    args = ap.parse_args(argv)
    if not Path(args.db).exists():
        ap.error(f"database not found: {args.db}")

    conn = sqlite3.connect(args.db, timeout=30)
    rows = conn.execute(
        "SELECT number, hits FROM dial_intel WHERE country_name=?", (OLD_LABEL,)
    ).fetchall()
    relabel = []
    for number, hits in rows:
        _, name, *_ = s.parse_dial_country(number)
        if name == NEW_LABEL:
            relabel.append((number, hits))

    print(f"Database: {args.db}")
    print(f"'{OLD_LABEL}' rows: {len(rows)}  →  reclassify as '{NEW_LABEL}': {len(relabel)}")
    for number, hits in sorted(relabel, key=lambda r: -r[1]):
        print(f"  {number:16} hits={hits}")

    if not relabel:
        print("Nothing to do (already clean).")
        conn.close()
        return 0

    if not args.apply:
        print(f"\nDRY-RUN: would relabel {len(relabel)} row(s). Re-run with --apply, "
              "then ./restart.sh so the dial cache re-seeds.")
        conn.close()
        return 0

    try:
        conn.executemany(
            "UPDATE dial_intel SET country_name=? WHERE number=?",
            [(NEW_LABEL, number) for number, _ in relabel],
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    print(f"\nAPPLIED: relabeled {len(relabel)} row(s). Run ./restart.sh so the dial cache "
          "picks up the corrected labels.")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

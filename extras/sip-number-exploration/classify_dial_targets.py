#!/usr/bin/env python3
"""Pull SIP dial targets from the honeypot DB and classify each via SIPSTACK WHOIS.

Reads the `dial_intel` table (the numbers the SIP honeypot was asked to call),
filters to a country prefix (default NANP / `+1`), looks each up through
sipstack_whois, and writes a TSV with line type, carrier, rate center, and
location alongside the honeypot hit counts.

This is the data-collection step; feed its output to analyze_dial_targets.py.
See ../notes/sip-nanp-line-types-whois.md for the investigation it supports.

Usage:
    python extras/sip-number-exploration/classify_dial_targets.py
    python extras/sip-number-exploration/classify_dial_targets.py \
        --db data/knock_knock.db --prefix +1 --min-hits 1 --out /tmp/nanp.tsv
    # classify a flat file of numbers instead of the DB (one per line):
    python extras/sip-number-exploration/classify_dial_targets.py --numbers-file nums.txt

Reminder: dial strings are attacker-controlled. They are looked up as untrusted
evidence, never executed or dialed.
"""
import argparse
import csv
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sipstack_whois import lookup, to_e164_digits  # noqa: E402

FIELDS = ["number", "hits", "type", "carrier", "rate_center",
          "city", "region", "lata", "cnam", "score", "error"]


def from_db(db_path, prefix, min_hits):
    """Yield (number, hits) from dial_intel for the given E.164 prefix.

    NANP numbers are `+1` + 10 digits = 12 chars; the length guard drops the
    malformed/short rows the honeypot also records."""
    digits = to_e164_digits(prefix)          # '+1' -> '1'
    want_len = 1 + len(digits) + 10          # '+' + cc digits + 10 subscriber
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT number, hits FROM dial_intel "
            "WHERE number LIKE ? AND length(number) = ? AND hits >= ? "
            "ORDER BY hits DESC",
            (prefix + "%", want_len, min_hits),
        ).fetchall()
    finally:
        con.close()
    return rows


def from_file(path):
    with open(path) as f:
        for line in f:
            n = line.strip()
            if n:
                yield (n, "")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=os.path.join(os.environ.get("DB_DIR", "data"),
                                                 "knock_knock.db"),
                    help="path to knock_knock.db (default: data/knock_knock.db)")
    ap.add_argument("--prefix", default="+1",
                    help="E.164 country prefix to select (default: +1 / NANP)")
    ap.add_argument("--min-hits", type=int, default=1,
                    help="only numbers with at least this many hits (default: 1)")
    ap.add_argument("--numbers-file",
                    help="classify numbers from this file (one per line) instead of the DB")
    ap.add_argument("--out", default="-",
                    help="output TSV path, or - for stdout (default: -)")
    ap.add_argument("--sleep", type=float, default=0.25,
                    help="seconds between API calls (default: 0.25)")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N numbers (0 = all)")
    args = ap.parse_args(argv)

    if args.numbers_file:
        src = list(from_file(args.numbers_file))
    else:
        if not os.path.exists(args.db):
            ap.error(f"database not found: {args.db}")
        src = from_db(args.db, args.prefix, args.min_hits)
    if args.limit:
        src = src[:args.limit]

    out = sys.stdout if args.out == "-" else open(args.out, "w", newline="")
    w = csv.DictWriter(out, fieldnames=FIELDS, delimiter="\t")
    w.writeheader()
    n_ok = n_err = 0
    for i, (number, hits) in enumerate(src):
        if i:
            time.sleep(args.sleep)
        rec = lookup(number)
        n_ok += rec["ok"]
        n_err += not rec["ok"]
        w.writerow({
            "number": number, "hits": hits, "type": rec["type"],
            "carrier": rec["carrier"], "rate_center": rec["rate_center"],
            "city": rec["city"], "region": rec["region"],
            "lata": rec["lata"] if rec["lata"] is not None else "",
            "cnam": rec["cnam"], "score": rec["score"], "error": rec["error"],
        })
        out.flush()
    if out is not sys.stdout:
        out.close()
    print(f"classified {len(src)} numbers: {n_ok} resolved, {n_err} errors "
          f"-> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

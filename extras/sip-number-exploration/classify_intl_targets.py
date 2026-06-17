#!/usr/bin/env python3
"""Classify non-NANP SIP dial targets by number type, carrier, and outbound cost.

sipstack WHOIS only covers US/Canada, so for international clusters (+44 / +972 /
+39 / +970 …) this tool uses two offline sources instead:

  - python-phonenumbers: number type (fixed/mobile/premium/VoIP/…), geographic
    area, and carrier (populated for mobiles in most countries).
  - a Telnyx voice rate sheet (CSV): the per-minute outbound termination cost,
    via longest-destination-prefix match — the monetization metric for IRSF,
    where the value is the *cost to call* the destination, not terminating access.

Reads dial targets from the `dial_intel` table (or a file) and writes a TSV for
analyze_intl_targets.py. See ../notes/sip-nanp-line-types-whois.md (NANP analog)
and the planned international follow-up.

Usage:
    python extras/sip-number-exploration/classify_intl_targets.py \
        --prefixes +44,+972,+39,+970 --rates /tmp/rates.csv --out /tmp/intl.tsv

Reminder: dial strings are attacker-controlled — looked up as evidence, never dialed.
"""
import argparse
import csv
import os
import sqlite3
import sys

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder

FIELDS = ["number", "hits", "country", "type", "carrier", "geo",
          "rate", "rate_desc", "error"]

_TYPE_NAME = {getattr(PhoneNumberType, k): k
              for k in dir(PhoneNumberType) if k.isupper()}


def load_rates(path):
    """Build (exact_map, prefix_map) from a Telnyx rate CSV.

    Columns: ISO, Country, Origination Prefixes, Destination Prefixes,
    Description, Interval 1, Interval N, Rate, Price Per Call, Exact Match.
    Rows flagged Exact Match only apply to the full number; everything else is a
    longest-destination-prefix match. Origination-specific ('Local') variants are
    de-prioritized in favor of generic rows."""
    exact, prefix = {}, {}
    if not path or not os.path.exists(path):
        return exact, prefix
    with open(path, newline="") as f:
        r = csv.reader(f)
        next(r, None)  # header
        for row in r:
            if len(row) < 8:
                continue
            dest = (row[3] or "").strip()
            if not dest:
                continue
            try:
                rate = float(row[7]) if row[7] else None
            except ValueError:
                rate = None
            rec = {"rate": rate, "desc": (row[4] or "").strip().strip('"'),
                   "orig": (row[2] or "").strip()}
            if len(row) >= 10 and row[9].strip():      # Exact Match flagged
                exact.setdefault(dest, []).append(rec)
            else:
                prefix.setdefault(dest, []).append(rec)
    return exact, prefix


def _choose(rows):
    """Worst-case representative rate among matches: prefer generic (no
    origination prefix) rows, then take the max rate. Returns (rate, desc)."""
    generic = [x for x in rows if not x["orig"]] or rows
    rated = [x for x in generic if x["rate"] is not None]
    if not rated:
        return None, (generic[0]["desc"] if generic else "")
    best = max(rated, key=lambda x: x["rate"])
    return best["rate"], best["desc"]


def rate_for(digits, exact, prefix):
    if digits in exact:
        return _choose(exact[digits])
    for L in range(len(digits), 0, -1):
        if digits[:L] in prefix:
            return _choose(prefix[digits[:L]])
    return None, ""


def classify(number, exact, prefix):
    out = {k: "" for k in FIELDS}
    out["number"] = number
    digits = "".join(ch for ch in number if ch.isdigit())
    try:
        p = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        out["error"] = f"parse_{e.error_type}"
        return out
    out["country"] = phonenumbers.region_code_for_number(p) or ""
    out["type"] = _TYPE_NAME.get(phonenumbers.number_type(p), "UNKNOWN")
    out["carrier"] = carrier.name_for_number(p, "en") or ""
    out["geo"] = geocoder.description_for_number(p, "en") or ""
    if not phonenumbers.is_valid_number(p):
        out["error"] = "invalid"
    rate, desc = rate_for(digits, exact, prefix)
    out["rate"] = "" if rate is None else f"{rate:.4f}"
    out["rate_desc"] = desc
    return out


def from_db(db_path, prefixes):
    where = " OR ".join("number LIKE ?" for _ in prefixes)
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            f"SELECT number, hits FROM dial_intel WHERE {where} ORDER BY hits DESC",
            tuple(p + "%" for p in prefixes),
        ).fetchall()
    finally:
        con.close()
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    default_rates = os.path.join(here, "rates.csv")
    if not os.path.exists(default_rates):
        default_rates = "/tmp/rates.csv"
    ap.add_argument("--db", default=os.path.join(os.environ.get("DB_DIR", "data"),
                                                 "knock_knock.db"))
    ap.add_argument("--prefixes", default="+44,+972,+39,+970",
                    help="comma-separated E.164 prefixes (default: +44,+972,+39,+970)")
    ap.add_argument("--rates", default=default_rates,
                    help="Telnyx rate CSV (default: ./rates.csv, else /tmp/rates.csv; "
                         "cost omitted if missing)")
    ap.add_argument("--numbers-file", help="classify numbers from a file instead of the DB")
    ap.add_argument("--out", default="-")
    args = ap.parse_args(argv)

    exact, prefix = load_rates(args.rates)
    if not prefix:
        print(f"WARNING: no rates loaded from {args.rates}; cost columns blank",
              file=sys.stderr)

    if args.numbers_file:
        src = [(l.strip(), "") for l in open(args.numbers_file) if l.strip()]
    else:
        if not os.path.exists(args.db):
            ap.error(f"database not found: {args.db}")
        src = from_db(args.db, [p.strip() for p in args.prefixes.split(",")])

    out = sys.stdout if args.out == "-" else open(args.out, "w", newline="")
    w = csv.DictWriter(out, fieldnames=FIELDS, delimiter="\t")
    w.writeheader()
    for number, hits in src:
        rec = classify(number, exact, prefix)
        rec["hits"] = hits
        w.writerow(rec)
    if out is not sys.stdout:
        out.close()
    print(f"classified {len(src)} numbers -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

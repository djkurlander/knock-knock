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

import telnyx_rates

FIELDS = ["number", "hits", "country", "type", "carrier", "geo",
          "rate", "rate_desc", "error"]

_TYPE_NAME = {getattr(PhoneNumberType, k): k
              for k in dir(PhoneNumberType) if k.isupper()}


def classify(number, rate_conn):
    out = {k: "" for k in FIELDS}
    out["number"] = number
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
    if rate_conn is not None:
        rate_rec = telnyx_rates.lookup(number, con=rate_conn)
        rate = rate_rec.get("rate_per_minute")
        out["rate"] = "" if rate is None else f"{rate:.4f}"
        out["rate_desc"] = rate_rec.get("description") or ""
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

    rate_conn = None
    try:
        rate_conn = telnyx_rates.connect(csv_path=args.rates)
    except FileNotFoundError:
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
        rec = classify(number, rate_conn)
        rec["hits"] = hits
        w.writerow(rec)
    if rate_conn is not None:
        rate_conn.close()
    if out is not sys.stdout:
        out.close()
    print(f"classified {len(src)} numbers -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

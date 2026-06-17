#!/usr/bin/env python3
"""Categorize classified SIP dial targets: line type, carrier, urban/rural, concentration.

Reads the TSV produced by classify_dial_targets.py and prints:
  - line-type mix (VoIP / Wireline / Wireless / unresolved), by count and by hits
  - the VoIP ratio and the wholesale-CLEC-VoIP share
  - carrier / telco breakdown
  - an urban vs rural/small-town split by rate center (heuristic)
  - the genuine landline (Wireline) and Wireless listings
  - hit concentration and sequential-DID-block clustering

See ../notes/sip-nanp-line-types-whois.md for the findings and interpretation.

Usage:
    python extras/sip-number-exploration/analyze_dial_targets.py /tmp/nanp.tsv
    python extras/sip-number-exploration/classify_dial_targets.py | \
        python extras/sip-number-exploration/analyze_dial_targets.py -
"""
import argparse
import collections
import csv
import re
import sys

# Wholesale / CLEC VoIP carrier signatures (the bulk-DID providers fraud rides on).
WHOLESALE_VOIP = re.compile(
    r"BANDWIDTH|ONVOY|INTELIQUENT|PEERLESS|TELNYX|TWILIO|LEVEL 3|GLOBAL CROSSING|"
    r"SINCH|COMMIO|THINQ|VOXBONE|VOIP|O1 COMM|ISP TELECOM|LOCAL ACCESS|XO |"
    r"US LEC|MCIMETRO|FIBERNETICS|IRISTEL|CAS COMM|SUNSET FIBER|EAGLE COMM",
    re.I,
)

# Hand-curated rural / small-town rate centers (pop ~<15k, unincorporated, or
# independent rural-ILEC territory). Heuristic — extend to taste; the API does
# not return an urban/rural flag, so this is a judgement layer on rate-center name.
RURAL_RATE_CENTERS = {
    "Angels Camp", "Georgetown", "Ruidoso", "Winterset", "Jewell", "Natural Dam",
    "Indian Springs", "Pretty Prairie", "Fork", "Dryden", "Eastover", "Cloverdale",
    "Valley City", "Cobb Mountain", "California City", "Bloomingburg", "St Helena",
    "Hatton", "Snyder", "Follansbee", "Manistee", "Wright", "McGill", "Clinton",
    "Goddard", "Cooksville", "Dalton", "Chester", "Florence", "Slave Lake",
    "Sedalia", "Fernley", "Hobbs", "Acton", "Goldsboro", "Parkersburg Zone 1",
    "Moses Lake", "Ilion", "Lebanon", "Westerly", "Bristol", "Hemet",
}


def is_rural(rate_center: str) -> bool:
    base = rate_center.split(":")[0].strip()  # "Hemet: Hemet DA" -> "Hemet"
    return bool(rate_center) and (base in RURAL_RATE_CENTERS or rate_center in RURAL_RATE_CENTERS)


def hits(row) -> int:
    try:
        return int(row["hits"] or 0)
    except ValueError:
        return 0


def pct(a, b):
    return f"{(100 * a / b):.1f}%" if b else "n/a"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tsv", help="TSV from classify_dial_targets.py, or - for stdin")
    args = ap.parse_args(argv)

    f = sys.stdin if args.tsv == "-" else open(args.tsv)
    rows = list(csv.DictReader(f, delimiter="\t"))
    if f is not sys.stdin:
        f.close()
    if not rows:
        print("no rows", file=sys.stderr)
        return 1

    total_hits = sum(hits(r) for r in rows)
    geo = [r for r in rows if r["type"] in ("VoIP", "Wireline", "Wireless")]

    print(f"Numbers: {len(rows)}    total hits: {total_hits:,}")
    print(f"Resolved to a geographic line: {len(geo)}    "
          f"unresolved (toll-free / invalid / unallocated): {len(rows) - len(geo)}")
    print()

    print("=== LINE TYPE ===")
    by_type = collections.Counter(r["type"] or "(unresolved)" for r in rows)
    hits_by_type = collections.Counter()
    for r in rows:
        hits_by_type[r["type"] or "(unresolved)"] += hits(r)
    for t, c in by_type.most_common():
        print(f"  {t:14} {c:4} numbers ({pct(c, len(rows)):>6})   "
              f"{hits_by_type[t]:>8,} hits ({pct(hits_by_type[t], total_hits):>6})")
    voip = by_type.get("VoIP", 0)
    print(f"\n  VoIP share of resolved-geographic numbers: {voip}/{len(geo)} "
          f"= {pct(voip, len(geo))}")
    wh = [r for r in geo if r["type"] == "VoIP" and WHOLESALE_VOIP.search(r["carrier"])]
    print(f"  wholesale-CLEC VoIP: {len(wh)} numbers "
          f"({pct(len(wh), voip)} of VoIP, {pct(len(wh), len(geo))} of resolved)")
    print()

    print("=== CARRIER / TELCO ===")
    by_carrier = collections.Counter(r["carrier"] or "(none)" for r in rows)
    for ca, c in by_carrier.most_common():
        print(f"  {c:4}  {ca}")
    print()

    print("=== URBAN vs RURAL (by rate center, heuristic) ===")
    split = collections.Counter()
    split_hits = collections.Counter()
    for r in geo:
        k = "RURAL/small-town" if is_rural(r["rate_center"]) else "URBAN/suburban"
        split[k] += 1
        split_hits[k] += hits(r)
    for k in ("RURAL/small-town", "URBAN/suburban"):
        print(f"  {k:18} {split[k]:3} numbers   {split_hits[k]:>8,} hits")
    print()

    for label in ("Wireline", "Wireless"):
        sel = sorted((r for r in rows if r["type"] == label), key=hits, reverse=True)
        print(f"=== {label.upper()} NUMBERS ({len(sel)}) ===")
        for r in sel:
            tag = "rural" if is_rural(r["rate_center"]) else "urban"
            print(f"  {r['number']:14} {hits(r):>6}  [{tag}] "
                  f"{r['rate_center']}, {r['region']}  | {r['carrier']}")
        print()

    print("=== CONCENTRATION ===")
    hv = sorted((hits(r) for r in rows), reverse=True)
    top10 = sum(hv[:10])
    print(f"  top 10 numbers: {top10:,} hits = {pct(top10, total_hits)} of all volume")
    print(f"  >=1000 hits: {sum(1 for h in hv if h >= 1000)} numbers")
    print(f"  <=5 hits:    {sum(1 for h in hv if h <= 5)} numbers")
    print(f"  exactly 1:   {sum(1 for h in hv if h == 1)} numbers")
    print()

    print("=== SEQUENTIAL / BLOCK CLUSTERING (shared first 8 digits = same NXX) ===")
    blocks = collections.Counter(r["number"][:8] for r in rows if len(r["number"]) >= 8)
    for blk, c in blocks.most_common():
        if c > 1:
            members = sorted(r["number"] for r in rows if r["number"].startswith(blk))
            print(f"  {blk}xxxx  x{c}  {', '.join(m[-4:] for m in members)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

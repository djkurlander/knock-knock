#!/usr/bin/env python3
"""Phase 1-3 report for international dial targets classified by classify_intl_targets.py.

Per country and overall:
  - structure: counts, hit concentration, the one-off probing tail
  - number-type mix (fixed / mobile / premium / VoIP …), by count and by hits
  - outbound cost: per-minute rate distribution and a cost-weighted ranking
    (hits x rate = potential fraud value), plus the priciest legs
  - sequential-block clustering (owned-DID inventory signal)

Usage:
    python extras/sip-number-exploration/analyze_intl_targets.py /tmp/intl.tsv
"""
import argparse
import collections
import csv
import sys


def hits(r):
    try:
        return int(r["hits"] or 0)
    except ValueError:
        return 0


def rate(r):
    try:
        return float(r["rate"]) if r["rate"] else 0.0
    except ValueError:
        return 0.0


def pct(a, b):
    return f"{(100 * a / b):.1f}%" if b else "n/a"


def block_key(number):
    """Number minus its last 3 digits — groups consecutive DIDs in one range."""
    digits = "".join(ch for ch in number if ch.isdigit())
    return digits[:-3] if len(digits) > 3 else digits


def report(rows, label):
    n = len(rows)
    th = sum(hits(r) for r in rows)
    print(f"\n{'=' * 70}\n{label}: {n} numbers, {th:,} hits\n{'=' * 70}")

    # Type mix
    print("-- type mix --")
    by_t = collections.Counter(r["type"] or "?" for r in rows)
    h_t = collections.Counter()
    for r in rows:
        h_t[r["type"] or "?"] += hits(r)
    for t, c in by_t.most_common():
        print(f"   {t:22} {c:4} ({pct(c, n):>6})   {h_t[t]:>8,} hits ({pct(h_t[t], th):>6})")

    # Cost
    rated = [r for r in rows if rate(r) > 0]
    weight = sum(hits(r) * rate(r) for r in rows)
    print("-- outbound cost (Telnyx rate sheet, worst-case per-prefix) --")
    print(f"   numbers with a rate: {len(rated)}/{n}")
    if rated:
        rs = sorted(rate(r) for r in rated)
        print(f"   $/min  min={rs[0]:.4f}  median={rs[len(rs)//2]:.4f}  max={rs[-1]:.4f}")
    print(f"   cost-weight (sum hits x $/min) = {weight:,.0f}  "
          f"(≈ $ if every captured attempt completed 1 min)")
    print("   top legs by cost-weight (hits x rate):")
    for r in sorted(rows, key=lambda r: hits(r) * rate(r), reverse=True)[:12]:
        if hits(r) * rate(r) <= 0:
            break
        print(f"     {r['number']:16} {hits(r):>6}h x ${rate(r):.4f} = "
              f"{hits(r) * rate(r):>8,.0f}  {r['type']:14} {r['carrier'] or r['geo']:18} "
              f"| {r['rate_desc']}")

    # Concentration
    hv = sorted((hits(r) for r in rows), reverse=True)
    print("-- concentration --")
    print(f"   top 10 = {pct(sum(hv[:10]), th)} of volume   "
          f">=1000h: {sum(1 for h in hv if h >= 1000)}   "
          f"<=5h: {sum(1 for h in hv if h <= 5)}   =1h: {sum(1 for h in hv if h == 1)}")

    # Sequential blocks
    blocks = collections.defaultdict(list)
    for r in rows:
        blocks[block_key(r["number"])].append(r)
    multi = sorted(((k, v) for k, v in blocks.items() if len(v) > 1),
                   key=lambda kv: -sum(hits(x) for x in kv[1]))
    if multi:
        print(f"-- sequential blocks (shared all-but-last-3 digits): {len(multi)} --")
        for k, v in multi[:12]:
            tail = ",".join(sorted("".join(c for c in x["number"] if c.isdigit())[-3:]
                                   for x in v))
            print(f"   +{k}xxx  x{len(v):<2} {sum(hits(x) for x in v):>7,}h  [{tail}]")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tsv", help="TSV from classify_intl_targets.py, or - for stdin")
    ap.add_argument("--by-country", action="store_true",
                    help="also break the report down per country")
    args = ap.parse_args(argv)

    f = sys.stdin if args.tsv == "-" else open(args.tsv)
    rows = list(csv.DictReader(f, delimiter="\t"))
    if f is not sys.stdin:
        f.close()
    if not rows:
        print("no rows", file=sys.stderr)
        return 1

    report(rows, "ALL INTERNATIONAL CLUSTERS")
    if args.by_country:
        for cc in sorted({r["country"] for r in rows if r["country"]},
                         key=lambda c: -sum(hits(r) for r in rows if r["country"] == c)):
            report([r for r in rows if r["country"] == cc], f"COUNTRY {cc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

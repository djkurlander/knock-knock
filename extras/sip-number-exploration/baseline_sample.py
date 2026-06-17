#!/usr/bin/env python3
"""Establish the population base rate for NANP line types by random sampling.

Generates random valid-format US numbers (random area code from a spread of
real, populated NPAs + random NXX + random line), looks each up through
sipstack_whois, and reports the line-type mix and wholesale-VoIP share among
the numbers that resolve. This is the control for the dial-target analysis: it
answers "what fraction of *random* NANP numbers are VoIP?" so the honeypot's
enrichment can be quantified against it.

Emits the same TSV schema as classify_dial_targets.py (hits column blank), so
analyze_dial_targets.py can read it directly.

Usage:
    python extras/sip-number-exploration/baseline_sample.py --n 300 --out /tmp/baseline.tsv
    python extras/sip-number-exploration/baseline_sample.py --n 300 | \
        python extras/sip-number-exploration/analyze_dial_targets.py -

Note: these are random, non-personal numbers sent to a public number-intelligence
service (the same lookup a spam-call app performs). It is a statistical base-rate
measurement, not targeting. Keep --n modest and --sleep polite.
"""
import argparse
import csv
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_dial_targets import FIELDS  # noqa: E402
from sipstack_whois import lookup  # noqa: E402

# A spread of real, populated US area codes across regions and urban/rural mix.
AREA_CODES = [
    212, 718, 332, 646, 213, 310, 415, 510, 408, 312, 773, 847, 202, 301, 410,
    617, 305, 404, 470, 770, 214, 469, 713, 281, 832, 602, 480, 503, 971, 206,
    425, 702, 775, 505, 615, 901, 704, 919, 252, 207, 218, 319, 563, 660, 785,
    308, 406, 575, 580, 870, 802, 304, 859, 989, 231, 530, 760, 661, 559,
]


def random_did():
    npa = random.choice(AREA_CODES)
    nxx = random.randint(200, 999)        # exchange: first digit 2-9
    line = random.randint(0, 9999)
    return f"1{npa}{nxx}{line:04d}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=300, help="sample size (default: 300)")
    ap.add_argument("--out", default="-", help="output TSV path, or - for stdout")
    ap.add_argument("--sleep", type=float, default=0.2,
                    help="seconds between API calls (default: 0.2)")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    args = ap.parse_args(argv)
    if args.seed is not None:
        random.seed(args.seed)

    out = sys.stdout if args.out == "-" else open(args.out, "w", newline="")
    w = csv.DictWriter(out, fieldnames=FIELDS, delimiter="\t")
    w.writeheader()
    for i in range(args.n):
        if i:
            time.sleep(args.sleep)
        rec = lookup(random_did())
        w.writerow({
            "number": "+" + rec["did"], "hits": "", "type": rec["type"],
            "carrier": rec["carrier"], "rate_center": rec["rate_center"],
            "city": rec["city"], "region": rec["region"],
            "lata": rec["lata"] if rec["lata"] is not None else "",
            "cnam": rec["cnam"], "score": rec["score"], "error": rec["error"],
        })
        out.flush()
    if out is not sys.stdout:
        out.close()
    print(f"sampled {args.n} random NANP numbers -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

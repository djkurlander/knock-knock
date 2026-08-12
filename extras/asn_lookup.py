#!/usr/bin/env python3
"""List every ASN whose ISP name matches a search term, from saved knock tables.

Groups actual knock rows by ASN (authoritative), rather than isp_intel - whose
single per-name representative ASN is unreliable (it churns to whatever knocked
most recently). Matching is case-insensitive; substring is the default.

Usage:
    python3 extras/asn_lookup.py Microsoft
    python3 extras/asn_lookup.py "amazon" --since 2026-01-01
    python3 extras/asn_lookup.py Cisco --complete-word
    python3 extras/asn_lookup.py "Cisco Systems, Inc." --exact
"""
import argparse
import os
import re
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, os.environ.get('DB_DIR', 'data'), 'knock_knock.db')

ap = argparse.ArgumentParser()
ap.add_argument('match', help='ISP-name text to match (case-insensitive)')
ap.add_argument('--since', default='1970-01-01', help='only knocks on/after this date')
mode = ap.add_mutually_exclusive_group()
mode.add_argument('--substring', action='store_true',
                  help='match ISP names containing the text (default)')
mode.add_argument('--complete-word', action='store_true',
                  help='match the text as a complete word/phrase')
mode.add_argument('--exact', action='store_true',
                  help='match ISP names equal to the text')
args = ap.parse_args()

con = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
if args.complete_word:
    pattern = re.compile(r'(?<![A-Za-z0-9])' + re.escape(args.match) + r'(?![A-Za-z0-9])',
                         re.IGNORECASE)

    def regexp(_pattern, value):
        return bool(value and pattern.search(value))

    con.create_function('REGEXP', 2, regexp)
tbls = [r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'knocks_%' "
    "ORDER BY name")]
if not tbls:
    raise SystemExit('no knocks_* tables (need --save-knocks data)')

if args.exact:
    pred = 'isp = ? COLLATE NOCASE'
    term = args.match
elif args.complete_word:
    pred = 'isp REGEXP ?'
    term = args.match
else:
    pred = 'isp LIKE ? COLLATE NOCASE'
    term = f'%{args.match}%'
union = ' UNION ALL '.join(
    f'SELECT ip_address, asn, isp FROM {t} WHERE {pred} AND timestamp >= ?'
    for t in tbls)
params = []
for _ in tbls:
    params += [term, args.since]

rows = con.execute(f"""
    WITH m AS ({union})
    SELECT asn, MIN(isp) isp, COUNT(DISTINCT ip_address) ips, COUNT(*) knocks
    FROM m GROUP BY asn ORDER BY ips DESC""", params).fetchall()

print(f"{'ASN':>10} {'IPs':>8} {'knocks':>10}  ISP")
print('-' * 60)
tot_ips = tot_kn = 0
for asn, isp, ips, knocks in rows:
    print(f"{str(asn or '(null)'):>10} {ips:>8} {knocks:>10}  {isp}")
    tot_ips += ips
    tot_kn += knocks
print('-' * 60)
mode_name = ('exactly matching' if args.exact
             else 'containing complete word/phrase' if args.complete_word
             else 'containing')
print(f"{len(rows)} ASN(s), {tot_ips} IPs, {tot_kn} knocks with ISP {mode_name} "
      f"'{args.match}' since {args.since}")

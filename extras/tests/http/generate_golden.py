#!/usr/bin/env python3
"""
Regenerate extras/tests/http/http_classifier_golden.json from scratch.

Use this after sweeping classifier changes (priorities reshuffled, _RE_* heuristics
rewritten, large batches of entries added). For incremental updates after a normal
/check-http-knocks run, let the skill append cases instead — it's faster.

Sources (in priority order per case):
  1. Real DB traffic — most trustworthy; shows what the classifier actually sees
  2. Hand-crafted synthetics — for named entries that haven't appeared in captured data

Run from the repo root:
    python3 extras/tests/http/generate_golden.py [--db data/knock_knock.db] [--rows 150000]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'honeypots'))
from http_honeypot import _classify_purpose  # noqa: E402

import sqlite3

EXPLOITS_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'honeypots', 'http_exploits.json'
)
GOLDEN_PATH = os.path.join(os.path.dirname(__file__), 'http_classifier_golden.json')

# Hand-crafted synthetics for named entries that rarely appear in real traffic.
# Update this dict whenever a new entry is added that the DB scan doesn't cover.
SYNTHETICS = {
    'Anthropic API Probe':            ('GET',  '/anthropic/v1/models',  '', ''),
    'Atlassian Confluence RCE':       ('GET',  '/confluence/foo.action?rce=1', '', ''),
    'BinaryEdge':                     ('GET',  '/', 'BinaryEdge/1.0', ''),
    'Dahua IP Camera SDK':            ('GET',  '/sdk/index.php', '', ''),
    'Embedded Web UI Discovery':      ('GET',  '/currentsetting.htm', '', ''),
    'Expanse':                        ('GET',  '/', 'ExpanseBot/1.0', ''),
    'FreePBX Config Disclosure Probe':
        ('GET', '/admin/modules/framework/amp_conf/htdocs/admin/config.php', '', ''),
    'Hikvision ZhingPing Discovery':  ('GET',  '/zhnping.html', '', ''),
    'IPP Printer Probe':              ('POST', '/ipp', '', ''),
    'IPify Reconnaissance Probe':     ('GET',  '/api.ipify.org/check', '', ''),
    'Netcraft':                       ('GET',  '/', 'Mozilla/5.0 (netcraft.com survey)', ''),
    'OwnCloud GraphAPI Info Disclosure':
        ('GET', '/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php', '', ''),
    'RWTH Aachen University':         ('GET',  '/', 'RWTH Aachen University scanner', ''),
    'Rapid7 Project Sonar':           ('GET',  '/', 'Rapid7/1.0 Project Sonar', ''),
    'RoboMongo Config Exposure':      ('GET',  '/config/robomongo.json', '', ''),
    'SQLiteManager Discovery':        ('GET',  '/SQLiteManager/', '', ''),
    'SecurityTrails':                 ('GET',  '/', 'SecurityTrails/1.0', ''),
    'Vite Dev Server Probe':          ('GET',  '/__vite_ping', '', ''),
    'VMware vCenter / ESXi Discovery':('POST', '/sdk', 'VMware-client/6.0', '<RetrieveServiceContent/>'),
    'WordPress Asset Discovery':      ('GET',  '/wp-includes/css/buttons.css', '', ''),
    'XMRig cryptocurrency miner':
        ('POST', '/stratum', 'XMRIG/6.18.0', '{"method": "login", "params": {"login": "wallet"}}'),
    'ZoomEye':                        ('GET',  '/', 'ZoomEye-Spider/1.0', ''),
}

# Synthetic triggers for heuristic purposes (_RE_* in http_honeypot.py).
# These fire when no named entry matches. One case per purpose category.
HEURISTIC_SYNTHETICS = {
    'rce':               ('POST', '/upload.php',       '',             'eval(base64_decode("dGVzdA=="))'),
    'credential_theft':  ('GET',  '/wp-admin/',        '',             ''),
    'device_infiltration':('GET', '/goform/setSysAdm', '',             ''),
    'config_exposure':   ('GET',  '/.env.backup',      '',             ''),
    'path_traversal':    ('GET',  '/img/../../etc/passwd', '',         ''),
    'proxy_abuse':       ('CONNECT', 'example.com:443','',             ''),
    'research_scanner':  ('GET',  '/robots.txt',       '',             ''),
    'mass_scanner':      ('GET',  '/random-path',      '',             ''),
    'malware_comm':      ('POST', '/gate.php',         '',             "x=|'|'|cmd"),
    'crypto_mining':     ('POST', '/pool',             'genericminer', '{"method": "login"}'),
    'basic_probe':       ('GET',  '/',                 'Mozilla/5.0',  ''),
    'app_discovery':     ('GET',  '/admin/',           'Mozilla/5.0',  ''),
    'resource_discovery':('GET',  '/readme.txt',       'Mozilla/5.0',  ''),
    'protocol_probe':    ('\x16\x03\x01', '/',         '',             ''),
}


def scan_db(db_path, max_rows):
    con = sqlite3.connect(db_path)
    rows = con.execute(
        "SELECT http_method, http_path, http_user_agent, http_body "
        "FROM knocks_http ORDER BY id DESC LIMIT ?", (max_rows,)
    ).fetchall()
    con.close()

    db_named    = {}   # name    -> (m, p, u, b)
    db_heuristic = {}  # purpose -> (m, p, u, b)

    for method, path, ua, body in rows:
        m, p, u, b = method or '', path or '', ua or '', body or ''
        purpose, name, _ = _classify_purpose(m, p, u, b)
        if name and name not in db_named:
            db_named[name] = (m, p, u, b)
        if name is None and purpose and purpose not in db_heuristic:
            db_heuristic[purpose] = (m, p, u, b)

    return db_named, db_heuristic


def make_case(entry_type, source, m, p, u, b, expected_purpose, expected_name):
    return {
        'type': entry_type,
        'source': source,
        'method': m,
        'path': p,
        'ua': u,
        'body': b[:200],
        'expected_purpose': expected_purpose,
        'expected_name': expected_name,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default='data/knock_knock.db')
    parser.add_argument('--rows', type=int, default=150000)
    args = parser.parse_args()

    with open(EXPLOITS_PATH) as f:
        exploits = json.load(f)

    print(f"Scanning {args.rows:,} rows from {args.db} …", flush=True)
    db_named, db_heuristic = scan_db(args.db, args.rows)
    print(f"DB named examples found: {len(db_named)}/{len(exploits)}")

    golden = []
    failures = []

    # ── Named entries ─────────────────────────────────────────────────────
    for entry in exploits:
        name, purpose = entry['name'], entry['purpose']

        if name in db_named and name not in SYNTHETICS:
            m, p, u, b = db_named[name]
            src = 'db'
        elif name in SYNTHETICS:
            m, p, u, b = SYNTHETICS[name]
            src = 'synthetic'
        elif name in db_named:
            m, p, u, b = db_named[name]
            src = 'db'
        else:
            failures.append(f"NO TRIGGER: {name!r} — add to SYNTHETICS dict")
            continue

        b_trunc = (b or '')[:200]
        gp, gn, _ = _classify_purpose(m, p, u, b_trunc)
        if gn != name:
            failures.append(
                f"VERIFY FAIL [{src}] {name!r} → got {gn!r} | {m} {p!r} ua={u!r}"
            )
            continue

        golden.append(make_case('named', src, m, p, u, b_trunc, purpose, name))

    # ── Heuristic cases ───────────────────────────────────────────────────
    all_purposes = set(list(db_heuristic) + list(HEURISTIC_SYNTHETICS))
    for purpose in sorted(all_purposes):
        if purpose in db_heuristic:
            m, p, u, b = db_heuristic[purpose]
            src = 'db'
        else:
            m, p, u, b = HEURISTIC_SYNTHETICS[purpose]
            src = 'synthetic'

        b_trunc = (b or '')[:200]
        gp, gn, _ = _classify_purpose(m, p, u, b_trunc)

        if gn is not None or gp != purpose:
            # DB example now matches a named entry or wrong purpose — try synthetic
            if purpose in HEURISTIC_SYNTHETICS:
                m, p, u, b = HEURISTIC_SYNTHETICS[purpose]
                b_trunc = b[:200]
                gp, gn, _ = _classify_purpose(m, p, u, b_trunc)
                src = 'synthetic'

        if gn is not None or gp != purpose:
            failures.append(f"HEURISTIC FAIL {purpose!r}: got name={gn!r} purpose={gp!r}")
            continue

        golden.append(make_case('heuristic', src, m, p, u, b_trunc, purpose, None))

    # ── Report ────────────────────────────────────────────────────────────
    if failures:
        print(f"\n{len(failures)} FAILURE(S) — golden set NOT written:")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)

    named_n     = sum(1 for g in golden if g['type'] == 'named')
    heuristic_n = sum(1 for g in golden if g['type'] == 'heuristic')
    print(f"\nTotal: {len(golden)} cases  (named={named_n}, heuristic={heuristic_n})")

    with open(GOLDEN_PATH, 'w') as f:
        json.dump(golden, f, indent=2)
    print(f"Written: {GOLDEN_PATH}")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

import geoip2.database


DEFAULT_DB = 'data/knock_knock.db'
DEFAULT_GEOIP = '/usr/share/GeoIP/GeoLite2-City.mmdb'
DEFAULT_CACHE = 'extras/places_seen/geoip_country_set.json'


def _load_cache(cache_path, geoip_path):
    if not os.path.isfile(cache_path):
        return None
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            cached = json.load(f)
        countries = cached.get('countries') or []
        by_iso = {}
        for item in countries:
            iso = str(item.get('iso') or '').strip().upper()
            if not iso:
                continue
            name = str(item.get('name') or '').strip()
            by_iso[iso] = name
        if by_iso:
            return by_iso
    except Exception:
        return None
    return None


def _save_cache(cache_path, geoip_path, countries_by_iso):
    os.makedirs(os.path.dirname(cache_path) or '.', exist_ok=True)
    st = os.stat(geoip_path)
    payload = {
        'geoip_path': os.path.abspath(geoip_path),
        'geoip_mtime': int(st.st_mtime),
        'geoip_size': int(st.st_size),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'countries': [
            {'iso': iso, 'name': countries_by_iso.get(iso, '')}
            for iso in sorted(countries_by_iso)
        ],
    }
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _build_geoip_country_set(geoip_path):
    countries = {}
    reader = geoip2.database.Reader(geoip_path)
    try:
        for _net, rec in reader._db_reader:
            if not isinstance(rec, dict):
                continue
            country = rec.get('country') or {}
            iso = str(country.get('iso_code') or '').strip().upper()
            if not iso:
                continue
            name = ''
            names = country.get('names') or {}
            if isinstance(names, dict):
                name = str(names.get('en') or '').strip()
            if not name:
                name = str(rec.get('registered_country', {}).get('names', {}).get('en') or '').strip()
            if iso not in countries or (name and not countries[iso]):
                countries[iso] = name
    finally:
        reader.close()
    return countries


def load_geoip_countries(geoip_path, cache_path, refresh=False):
    if not refresh:
        cached = _load_cache(cache_path, geoip_path)
        if cached is not None:
            return cached, True
    countries = _build_geoip_country_set(geoip_path)
    _save_cache(cache_path, geoip_path, countries)
    return countries, False


def load_seen_countries(db_path):
    seen = {}
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT iso_code, country FROM country_intel WHERE iso_code IS NOT NULL AND TRIM(iso_code) != ''"
        )
        for iso, country in cur.fetchall():
            code = str(iso or '').strip().upper()
            if not code:
                continue
            name = str(country or '').strip()
            seen[code] = name
    finally:
        conn.close()
    return seen


def _fmt_line(iso, name):
    return f"{iso:>3}  {name}" if name else iso


def main():
    p = argparse.ArgumentParser(
        description='Compare countries/territories seen in country_intel vs possible GeoIP country set.'
    )
    p.add_argument('--db', default=DEFAULT_DB, help=f'SQLite DB path (default: {DEFAULT_DB})')
    p.add_argument('--geoip', default=DEFAULT_GEOIP, help=f'GeoLite2-City mmdb path (default: {DEFAULT_GEOIP})')
    p.add_argument('--cache', default=DEFAULT_CACHE, help=f'GeoIP country cache JSON (default: {DEFAULT_CACHE})')
    p.add_argument('--refresh-cache', action='store_true', help='Ignore cache and rebuild GeoIP country set')
    p.add_argument('--summary-only', action='store_true', help='Print only counts, not full lists')
    args = p.parse_args()

    if not os.path.isfile(args.db):
        print(f'error: DB not found: {args.db}', file=sys.stderr)
        return 2
    if not os.path.isfile(args.geoip):
        print(f'error: GeoIP DB not found: {args.geoip}', file=sys.stderr)
        return 2

    geoip_countries, from_cache = load_geoip_countries(args.geoip, args.cache, refresh=args.refresh_cache)
    seen_in_db = load_seen_countries(args.db)

    geoip_set = set(geoip_countries.keys())
    seen_set = set(seen_in_db.keys())

    seen_known = sorted(seen_set & geoip_set)
    not_seen = sorted(geoip_set - seen_set)
    seen_unknown_to_geoip = sorted(seen_set - geoip_set)

    print(f"GeoIP source: {args.geoip}")
    print(f"GeoIP country cache: {args.cache} ({'cache hit' if from_cache else 'rebuilt'})")
    print(f"GeoIP possible countries/territories: {len(geoip_set)}")
    print(f"Seen in country_intel (matching GeoIP set): {len(seen_known)}")
    print(f"Not yet seen (GeoIP set - seen): {len(not_seen)}")
    if seen_unknown_to_geoip:
        print(f"Seen in DB but not in current GeoIP set: {len(seen_unknown_to_geoip)}")

    if args.summary_only:
        return 0

    print('\n=== Seen ===')
    for iso in seen_known:
        name = seen_in_db.get(iso) or geoip_countries.get(iso, '')
        print(_fmt_line(iso, name))

    print('\n=== Not Seen Yet ===')
    for iso in not_seen:
        print(_fmt_line(iso, geoip_countries.get(iso, '')))

    if seen_unknown_to_geoip:
        print('\n=== Seen But Not In Current GeoIP Set ===')
        for iso in seen_unknown_to_geoip:
            print(_fmt_line(iso, seen_in_db.get(iso, '')))

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

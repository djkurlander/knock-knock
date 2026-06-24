#!/usr/bin/env python3
"""Cache Telnyx carrier number-lookup results for SIP dial targets.

Reads E.164 targets from the `dial_intel` table and queries Telnyx's
`/v2/number_lookup/{number}?type=carrier` API for any number not already present
in the local JSON cache. The cache is a dict keyed by normalized E.164 number
with a leading plus.

Usage:
    python extras/sip-number-exploration/telnyx_number_lookup_cache.py --limit 10
    python extras/sip-number-exploration/telnyx_number_lookup_cache.py --dry-run

Reminder: dial targets are attacker-controlled evidence. This tool only looks
them up through Telnyx; it never dials them.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import telnyx_rates  # sibling module: local rate-sheet lookup (rates.csv -> rates.sqlite)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DEFAULT_CACHE = HERE / "telnyx_number_lookup_cache.json"
API_BASE = "https://api.telnyx.com/v2/number_lookup"


def load_env():
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    with env_path.open() as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), value)


def normalize_e164(value):
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if not digits:
        return ""
    return "+" + digits


def load_cache(path):
    if not path.exists():
        return {}
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def save_cache(path, cache):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp.replace(path)


def dial_intel_numbers(db_path, min_hits):
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT number FROM dial_intel WHERE hits >= ? ORDER BY hits DESC, number",
            (min_hits,),
        ).fetchall()
    finally:
        con.close()
    seen = set()
    for (number,) in rows:
        e164 = normalize_e164(number)
        if e164 and e164 not in seen:
            seen.add(e164)
            yield e164


def telnyx_lookup(api_key, number, timeout):
    quoted_number = urllib.parse.quote(number, safe="")
    url = f"{API_BASE}/{quoted_number}?type=carrier"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "knock-knock-telnyx-number-lookup-cache/1.0",
        },
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            parsed = json.loads(body) if body else None
            return {
                "ok": True,
                "status": resp.status,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.time() - started, 3),
                "response": parsed,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body
        return {
            "ok": False,
            "status": e.code,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(time.time() - started, 3),
            "error": str(e),
            "response": parsed,
        }
    except (urllib.error.URLError, TimeoutError) as e:
        return {
            "ok": False,
            "status": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(time.time() - started, 3),
            "error": str(e),
        }


def cache_country_code(entry):
    """The carrier-lookup country_code for an entry, or None."""
    data = (entry.get("response") or {}).get("data") or {}
    return data.get("country_code")


def build_rate(number, rates_con, country_code=None):
    """Snapshot the rate-deck entry for a number into the trimmed ``rate`` dict.

    The presence of the returned object marks the entry as rate-enriched; an
    unmatched number yields ``{"rate_per_minute": None}``. ``iso`` is checked
    against the carrier-lookup ``country_code`` and warned on — never stored.
    ``match_type`` and ``origination_prefixes`` are intentionally dropped.
    """
    rec = telnyx_rates.lookup(number, con=rates_con)
    if not rec.get("matched"):
        return {"rate_per_minute": None}
    iso = rec.get("iso")
    if iso and country_code and iso != country_code:
        print(f"  ! iso mismatch {number}: rate.iso={iso} country_code={country_code}",
              file=sys.stderr)
    return {
        "rate_per_minute": rec.get("rate_per_minute"),
        "call_setup_fee": rec.get("price_per_call"),
        "matched_prefix": rec.get("matched_prefix"),
        "rate_description": rec.get("description"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(PROJECT_ROOT / os.environ.get("DB_DIR", "data") / "knock_knock.db"),
                    help="path to knock_knock.db (default: data/knock_knock.db)")
    ap.add_argument("--cache", default=str(DEFAULT_CACHE),
                    help="JSON cache path (default: telnyx_number_lookup_cache.json beside this script)")
    ap.add_argument("--min-hits", type=int, default=1,
                    help="only query dial_intel rows with at least this many hits")
    ap.add_argument("--limit", type=int, default=0,
                    help="query at most N cache misses this run (0 = all)")
    ap.add_argument("--sleep", type=float, default=0.25,
                    help="seconds to sleep between API calls")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="HTTP timeout in seconds")
    ap.add_argument("--retry-failures", action="store_true",
                    help="retry cached entries whose previous lookup had ok=false")
    ap.add_argument("--dry-run", action="store_true",
                    help="print cache misses without calling Telnyx")
    args = ap.parse_args(argv)

    load_env()
    api_key = os.environ.get("TELNYX_API_KEY", "").strip()
    if not api_key and not args.dry_run:
        ap.error("TELNYX_API_KEY is not set in the environment or .env")
    if not os.path.exists(args.db):
        ap.error(f"database not found: {args.db}")

    cache_path = Path(args.cache)
    cache = load_cache(cache_path)
    numbers = list(dial_intel_numbers(args.db, args.min_hits))
    misses = [
        n for n in numbers
        if n not in cache or (args.retry_failures and not cache.get(n, {}).get("ok"))
    ]
    if args.limit:
        misses = misses[:args.limit]

    print(f"dial_intel numbers: {len(numbers)}", file=sys.stderr)
    print(f"cache entries: {len(cache)}", file=sys.stderr)
    print(f"to query: {len(misses)}", file=sys.stderr)

    if args.dry_run:
        for number in misses:
            print(number)
        return 0

    ok = failed = 0
    for i, number in enumerate(misses, start=1):
        if i > 1 and args.sleep > 0:
            time.sleep(args.sleep)
        rec = telnyx_lookup(api_key, number, args.timeout)
        cache[number] = rec
        save_cache(cache_path, cache)
        if rec.get("ok"):
            ok += 1
        else:
            failed += 1
        print(f"{i}/{len(misses)} {number} status={rec.get('status')} ok={rec.get('ok')}",
              file=sys.stderr)

    print(f"done: {ok} ok, {failed} failed, cache={cache_path}", file=sys.stderr)

    # Rate-deck enrichment: snapshot a `rate` object into every entry lacking one
    # (the new lookups above + a backfill of existing entries). The deck is stable,
    # so one pass prices all entries correctly; presence of `rate` = enriched.
    try:
        rates_con = telnyx_rates.connect()
    except FileNotFoundError as e:
        print(f"rate enrichment skipped (no rate sheet): {e}", file=sys.stderr)
        rates_con = None
    if rates_con is not None:
        enriched = 0
        try:
            for number, entry in cache.items():
                if not isinstance(entry, dict) or "rate" in entry:
                    continue
                entry["rate"] = build_rate(number, rates_con, cache_country_code(entry))
                enriched += 1
        finally:
            rates_con.close()
        if enriched:
            save_cache(cache_path, cache)
        print(f"rate enrichment: {enriched} entries updated", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())

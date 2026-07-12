#!/usr/bin/env python3
"""
Retrospectively re-resolve SIP dial strings against full dialing history and
repair E.164 misattributions in knocks_sip and dial_intel.

The live parser (honeypots/sip_honeypot.py parse_dial_country) must guess from
a single dial string, sometimes with a cold suffix cache. With the whole
history available, most of those guesses become decidable:

  * explicit evidence — a literal '+<digits>' dial that validates is proof the
    number is real ('+16508601846' proves 6508601846 / 9916508601846 were
    California, not Saint Pierre & Miquelon)
  * weight of history — '0093545395213' reads as 00 + Afghanistan or
    009 + Iceland; six thousand prior Iceland dials settle it
  * national aliases — '988123746728' is 9 (PBX) + 8 (RU trunk) + the
    St Petersburg number dialed 16 seconds earlier, not an Iranian number

For every distinct (sip_dial_string, sip_dial_number) pair the script picks a
target number: an explicit valid '+'E.164 wins outright; otherwise the
strongest canonical whose digits (or >=9-digit national part) form a suffix of
the dialed digits behind at most --max-prefix junk digits, guarded by
--min-ratio / --min-weight so a weak reading never captures a strong one.
Corrected pairs get their knocks_sip rows rewritten and their dial_intel hits
moved to the canonical row (created if missing, using the live parser's own
labeling/geocoding); emptied artifact rows are deleted.

Dry-run is the default and prints the full plan. Use --apply to write.
Consider `python dbtool.py --backup` first, and restart knock-monitor after
applying so the honeypot reseeds its dial cache from the cleaned table.

Meant to be run periodically, e.g. nightly:
    17 4 * * * cd /root/knock-knock && .venv/bin/python extras/sip_dial_reconcile.py --apply >> data/sip_dial_reconcile.log 2>&1

Usage:
    python extras/sip_dial_reconcile.py                  # dry-run report
    python extras/sip_dial_reconcile.py --apply
    python extras/sip_dial_reconcile.py --prune-invalid  # also drop dial_intel rows whose number can't exist
"""

import argparse
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import phonenumbers

_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = _ROOT / "data" / "knock_knock.db"

# The live parser is reused for labeling/geocoding newly created dial_intel rows
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "honeypots"))


def _sanitize(dial):
    """Mirror parse_dial_country()'s cleanup of a raw dial string."""
    s = re.sub(r"^sips?:", "", dial or "")
    s = s.split("@")[0].lstrip("*#").replace(".", "").replace("-", "")
    s = re.sub(r"\D+$", "", s)
    if s.startswith("++"):
        s = s[1:]
    return s


def _forms(dial):
    """Return (explicit_plus_form_or_None, trailing_digits_or_None) for a dial string."""
    s = _sanitize(dial)
    explicit = s if re.fullmatch(r"\+\d{7,}", s) else None
    m = re.search(r"(\d{7,})$", s)
    return explicit, (m.group(1) if m else None)


@lru_cache(maxsize=None)
def _valid_e164(candidate):
    """'+<digits>' -> canonical E.164 string when libphonenumber says it's a real number."""
    try:
        pn = phonenumbers.parse(candidate, None)
        if phonenumbers.is_valid_number(pn):
            return phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        pass
    return None


@lru_cache(maxsize=None)
def _national_digits(e164):
    """>=9-digit national part of an E.164 ('+12022234942' -> '2022234942'), else None."""
    try:
        pn = phonenumbers.parse(e164, None)
    except Exception:
        return None
    national = str(pn.national_number)
    return national if len(national) >= 9 else None


def _high_confidence(explicit, digits):
    """Resolutions trustworthy enough to build the canonical set from.
    Returns (e164, kind) or (None, None)."""
    if explicit:
        e164 = _valid_e164(explicit)
        if e164:
            return e164, "explicit"
    if digits:
        if re.fullmatch(r"1\d{10}", digits):
            e164 = _valid_e164("+" + digits)
            if e164:
                return e164, "nanp11"
        for prefix in ("011", "00"):
            if digits.startswith(prefix) and len(digits) - len(prefix) >= 7:
                e164 = _valid_e164("+" + digits[len(prefix):])
                if e164:
                    return e164, "intl"
    return None, None


def load_pairs(conn):
    """Distinct (dial_string, current_number) pairs with knock counts and time range."""
    return conn.execute(
        """SELECT sip_dial_string AS ds, sip_dial_number AS cur, COUNT(*) AS knocks,
                  MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
           FROM knocks_sip
           WHERE sip_dial_string IS NOT NULL AND sip_dial_string != ''
           GROUP BY sip_dial_string, sip_dial_number"""
    ).fetchall()


def build_canonicals(pairs, dial_intel):
    """Weight every plausible target number by the evidence behind it."""
    weight = defaultdict(float)
    explicit_knocks = defaultdict(int)
    for row in pairs:
        explicit, digits = _forms(row["ds"])
        e164, kind = _high_confidence(explicit, digits)
        if e164:
            weight[e164] += row["knocks"]
            if kind == "explicit":
                explicit_knocks[e164] += row["knocks"]
    for number, info in dial_intel.items():
        if _valid_e164(number):
            weight[number] += info["hits"]
    return weight, explicit_knocks


def build_suffix_index(weight):
    """digit-suffix -> [e164]: full E.164 digits plus >=9-digit national aliases."""
    index = defaultdict(list)
    for e164 in weight:
        digits = e164.lstrip("+")
        index[digits].append(e164)
        national = _national_digits(e164)
        if national and national != digits:
            index[national].append(e164)
    return index


def best_candidate(digits, suffix_index, weight, explicit_knocks, min_explicit, max_prefix):
    """Strongest canonical matching a suffix of `digits` behind <= max_prefix junk
    digits. Explicitly-observed numbers outrank weight (proof beats popularity).
    Returns (e164, exact) where exact=True when the match consumed the canonical's
    full E.164 digits rather than just its national part."""
    best = None
    best_score = None
    best_exact = False
    best_strip = 0
    for strip in range(0, max_prefix + 1):
        if len(digits) - strip < 7:
            break
        suffix = digits[strip:]
        for e164 in suffix_index.get(suffix, ()):
            score = (explicit_knocks.get(e164, 0) >= min_explicit, weight[e164])
            if best_score is None or score > best_score:
                best, best_score = e164, score
                best_exact, best_strip = e164.lstrip("+") == suffix, strip
    return best, best_exact, best_strip


def load_ip_maps(conn):
    """Per-IP dialed-number maps for the same-IP prefix-twin check.
    number_ips: E.164 -> set of source IPs that dialed it.
    ip_digits:  source IP -> {digit-string: E.164} for every number that IP dialed."""
    number_ips = defaultdict(set)
    ip_digits = defaultdict(dict)
    for ip, num in conn.execute(
        "SELECT DISTINCT ip_address, sip_dial_number FROM knocks_sip"
        " WHERE sip_dial_number IS NOT NULL AND sip_dial_number != ''"
        "   AND ip_address IS NOT NULL AND ip_address != ''"
    ):
        number_ips[num].add(ip)
        ip_digits[ip][num.lstrip("+")] = num
    return number_ips, ip_digits


def same_ip_subset(e164, number_ips, ip_digits):
    """Prefix-enumeration collapse: if some IP that dialed `e164` ALSO dialed a
    shorter valid E.164 `M` whose digits are a full (>=9-digit) suffix of `e164`'s
    digits, return the closest such `M` (longest suffix). One IP dialing both a
    number and (prefix + that number) is dial-out-prefix enumeration, so the longer
    form is an artifact (e.g. `+15154890969` and `9`+it => `+915154890969`). Same-IP
    + suffix is conclusive (a chance suffix collision within one IP's dial set is ~0),
    so no trunk-prefix guard is needed. Returns `M` or None."""
    digits = e164.lstrip("+")
    best, best_cut = None, None
    for ip in number_ips.get(e164, ()):
        dmap = ip_digits.get(ip)
        if not dmap:
            continue
        for cut in range(1, len(digits) - 8):       # keep the matched suffix >= 9 digits
            m = dmap.get(digits[cut:])
            if m and m != e164 and _valid_e164(m):
                if best_cut is None or cut < best_cut:
                    best, best_cut = m, cut
                break                               # longest suffix for this IP
    return best


def subsumes_current(e164, cur):
    """True when `cur` is a valid E.164 whose digits are a proper >=9-digit suffix of
    `e164`'s digits — i.e. the explicit `e164` is a dial-out-prefix extension of the
    shorter real number the live parser already resolved (`9`+`+1 919...` => `+91 9197...`).
    Same idea as the honeypot's _e164_subsumes_cached, but the evidence is the current
    reading itself: proof only counts if the explicit form isn't a prefixed artifact of a
    valid shorter number. (>=9-digit suffix => a chance collision is ~0 at our scale.)"""
    if not cur or not _valid_e164(cur):
        return False
    ed, cd = e164.lstrip("+"), cur.lstrip("+")
    return len(cd) >= 9 and len(cd) < len(ed) and ed.endswith(cd)


def plan(conn, args):
    dial_intel = {
        row["number"]: dict(row)
        for row in conn.execute(
            "SELECT number, hits, first_seen, last_seen, country, country_name, lat, lng"
            " FROM dial_intel WHERE number IS NOT NULL"
        )
    }
    pairs = load_pairs(conn)
    weight, explicit_knocks = build_canonicals(pairs, dial_intel)
    suffix_index = build_suffix_index(weight)
    number_ips, ip_digits = load_ip_maps(conn)

    moves = []  # (pair_row, target_e164, reason)
    for row in pairs:
        explicit, digits = _forms(row["ds"])
        cur = row["cur"]

        # 1. A literal valid '+'E.164 is unconditional — UNLESS the same source IP
        #    also probed a shorter valid number that is a full suffix of this one.
        #    That's dial-out-prefix enumeration (one IP dials both +15154890969 and
        #    9+it => +915154890969); the longer +91 form is an artifact, not a real
        #    India number, so collapse it to the subset.
        if explicit:
            e164 = _valid_e164(explicit)
            if e164:
                twin = same_ip_subset(e164, number_ips, ip_digits)
                # An explicit dial-out-prefix form must not override a shorter valid reading
                # the live parser already resolved: if cur is a valid >=9-digit suffix of the
                # explicit e164, the explicit form is the artifact — keep cur, don't mint a
                # bogus +91/+81 row. (same_ip_subset covers the case where the same IP also
                # dialed the bare number; this covers the bots that only ever dial the prefixed
                # form, which the global suffix cache still resolved correctly at ingest.)
                target = twin or (cur if subsumes_current(e164, cur) else e164)
                if target != cur:
                    moves.append((row, target, "prefix-twin" if twin else "explicit"))
                continue
        if not digits:
            continue

        # 2. Strongest canonical suffix/national-alias match, guarded so a weak
        #    reading can't capture a strong one
        best, best_exact, best_strip = best_candidate(
            digits, suffix_index, weight, explicit_knocks,
            args.min_explicit, args.max_prefix)
        if best == cur:
            continue  # history agrees with the live assignment — done
        if best:
            cur_digits = cur.lstrip("+") if cur else None
            cur_strip = next(
                (i for i in range(args.max_prefix + 1) if digits[i:] == cur_digits),
                None,
            ) if cur_digits and _valid_e164(cur) else None  # impossible number is no reading
            cur_weight = weight.get(cur, 0.0)
            cur_explicit = explicit_knocks.get(cur, 0) >= args.min_explicit
            best_explicit = explicit_knocks.get(best, 0) >= args.min_explicit
            # A national-alias reading doesn't override a coherent exact reading
            # that explains at least as much of the dialed string (keeps
            # +970/+972 dual-CC dials on their dialed CC, while still letting
            # '6508601846' — fully consumed by +16508601846's national part —
            # escape a bad exact reading of its last 9 digits) unless the alias
            # target's evidence is overwhelming ('97787603331' is a possible
            # Nepal number, but 1 knock vs 2199 for 9 + the +1 778 number).
            alias_blocked = (
                not best_exact and cur_strip is not None
                and cur_strip <= best_strip
                and weight[best] < args.alias_override_ratio * max(cur_weight, 1.0)
            )
            if not alias_blocked and (
                (best_explicit and not cur_explicit)
                or (weight[best] >= args.min_weight
                    and weight[best] >= args.min_ratio * max(cur_weight, 1.0))
            ):
                moves.append((row, best, "suffix" if best_exact else "national-alias"))
                continue

        # 3. Remaining high-confidence digit forms (1+10 NANP, 011/00+valid) —
        #    only to backfill unresolved knocks or replace an impossible number,
        #    never to second-guess a valid assignment without canonical weight
        if cur is not None and _valid_e164(cur):
            continue
        e164, kind = _high_confidence(None, digits)
        if e164 and e164 != cur:
            moves.append((row, e164, kind))

    invalid_rows = [n for n in dial_intel if not _valid_e164(n)] if args.prune_invalid else []
    return dial_intel, moves, invalid_rows


def _target_geo(number, dial_intel):
    """(iso, name, lat, lng) for a target number: reuse its dial_intel row, else
    run the live parser (identical labels, geocode-cache backed)."""
    info = dial_intel.get(number)
    if info:
        return info["country"], info["country_name"], info["lat"], info["lng"]
    try:
        import sip_honeypot
        iso, name, _, lat, lng = sip_honeypot.parse_dial_country(number)
        if iso:
            return iso, name, lat, lng
    except Exception as e:
        print(f"WARN: live-parser labeling failed for {number}: {e}", file=sys.stderr)
    try:
        pn = phonenumbers.parse(number, None)
        iso = phonenumbers.region_code_for_number(pn) or "XX"
        from phonenumbers import geocoder as pn_geocoder
        name = pn_geocoder.country_name_for_number(pn, "en") or iso
        return iso, name, None, None
    except Exception:
        return "XX", "International Network", None, None


def apply_moves(conn, moves, dial_intel):
    """Rewrite knocks_sip pairs and shift dial_intel hits accordingly."""
    delta = defaultdict(int)          # number -> +/- knock rows moved
    seen_range = {}                   # number -> [first_seen, last_seen] of arriving knocks
    for row, target, _reason in moves:
        iso, name, lat, lng = _target_geo(target, dial_intel)
        if row["cur"] is None:
            conn.execute(
                """UPDATE knocks_sip SET sip_dial_number=?, sip_dial_country=?,
                       sip_dial_country_name=?, sip_dial_lat=?, sip_dial_lng=?
                   WHERE sip_dial_string=? AND sip_dial_number IS NULL""",
                (target, iso, name, lat, lng, row["ds"]),
            )
        else:
            conn.execute(
                """UPDATE knocks_sip SET sip_dial_number=?, sip_dial_country=?,
                       sip_dial_country_name=?, sip_dial_lat=?, sip_dial_lng=?
                   WHERE sip_dial_string=? AND sip_dial_number=?""",
                (target, iso, name, lat, lng, row["ds"], row["cur"]),
            )
            delta[row["cur"]] -= row["knocks"]
        delta[target] += row["knocks"]
        rng = seen_range.setdefault(target, [row["first_seen"], row["last_seen"]])
        rng[0] = min(rng[0], row["first_seen"])
        rng[1] = max(rng[1], row["last_seen"])

    created, deleted, updated = 0, 0, 0
    for number, moved in sorted(delta.items()):
        if moved > 0:
            first_seen, last_seen = seen_range[number]
            if number in dial_intel:
                conn.execute(
                    """UPDATE dial_intel SET hits = hits + ?,
                           first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
                       WHERE number = ?""",
                    (moved, first_seen, last_seen, number),
                )
                updated += 1
            else:
                iso, name, lat, lng = _target_geo(number, dial_intel)
                conn.execute(
                    "INSERT INTO dial_intel VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (number, moved, first_seen, last_seen, iso, name, lat, lng),
                )
                created += 1
        elif moved < 0 and number in dial_intel:
            remaining = conn.execute(
                "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM knocks_sip"
                " WHERE sip_dial_number = ?", (number,)
            ).fetchone()
            if remaining[0] == 0:
                conn.execute("DELETE FROM dial_intel WHERE number = ?", (number,))
                deleted += 1
            else:
                conn.execute(
                    """UPDATE dial_intel SET hits = MAX(?, hits + ?),
                           first_seen = ?, last_seen = ? WHERE number = ?""",
                    (remaining[0], moved, remaining[1], remaining[2], number),
                )
                updated += 1
    return created, updated, deleted


def print_plan(moves, invalid_rows, dial_intel, limit):
    if not moves and not invalid_rows:
        print("Nothing to reconcile — dial_intel and knocks_sip agree with history.")
        return

    # Roll pair-level moves up to (from -> to) for the report
    rollup = defaultdict(lambda: {"knocks": 0, "forms": [], "reasons": set()})
    for row, target, reason in moves:
        key = (row["cur"], target)
        rollup[key]["knocks"] += row["knocks"]
        rollup[key]["forms"].append(f"{row['knocks']}x {row['ds']}")
        rollup[key]["reasons"].add(reason)

    print(f"Corrections: {len(rollup)} (covering {sum(r['knocks'] for r in rollup.values())} knock rows)")
    print()
    for (cur, target), agg in sorted(
        rollup.items(), key=lambda kv: -kv[1]["knocks"]
    )[:limit]:
        cur_label = cur or "<unresolved>"
        cur_geo = dial_intel.get(cur, {}).get("country_name") if cur else None
        tgt_geo = dial_intel.get(target, {}).get("country_name")
        print(f"  {cur_label}{f' ({cur_geo})' if cur_geo else ''}"
              f"  ->  {target}{f' ({tgt_geo})' if tgt_geo else ' (new row)'}"
              f"  [{'+'.join(sorted(agg['reasons']))}, {agg['knocks']} knocks]")
        for form in agg["forms"][:4]:
            print(f"      {form}")
        if len(agg["forms"]) > 4:
            print(f"      ... {len(agg['forms']) - 4} more dial forms")
    if len(rollup) > limit:
        print(f"  ... {len(rollup) - limit} more corrections not shown")

    if invalid_rows:
        print()
        print(f"Invalid-number dial_intel rows to prune ({len(invalid_rows)}):")
        for number in invalid_rows[:limit]:
            info = dial_intel[number]
            print(f"  {number}  {info['hits']} hits  {info['country']}  {info['country_name']}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--db", default=str(DEFAULT_DB), help="path to knock_knock.db")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--min-ratio", type=float, default=10.0,
                    help="canonical must outweigh the current reading by this factor (default 10)")
    ap.add_argument("--min-weight", type=float, default=50.0,
                    help="minimum canonical evidence weight for non-explicit redirects (default 50)")
    ap.add_argument("--min-explicit", type=int, default=2,
                    help="explicit '+'E.164 knocks needed to count as proof (default 2)")
    ap.add_argument("--max-prefix", type=int, default=6,
                    help="max junk PBX/trunk digits allowed before a suffix match (default 6)")
    ap.add_argument("--alias-override-ratio", type=float, default=100.0,
                    help="evidence factor letting a national-alias reading override a"
                         " coherent exact reading of the dialed digits (default 100)")
    ap.add_argument("--prune-invalid", action="store_true",
                    help="also delete dial_intel rows whose number libphonenumber rejects")
    ap.add_argument("--limit", type=int, default=40, help="max report lines (default 40)")
    args = ap.parse_args()

    if not os.path.isfile(args.db):
        print(f"ERROR: database not found: {args.db}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(args.db, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        has_knocks = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='knocks_sip'"
        ).fetchone()
        if not has_knocks:
            print("ERROR: knocks_sip table not found — reconciliation needs saved SIP knocks"
                  " (SAVE_KNOCKS=SIP).", file=sys.stderr)
            return 1

        print(f"sip_dial_reconcile @ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}"
              f"  db={args.db}  {'APPLY' if args.apply else 'DRY-RUN'}")
        dial_intel, moves, invalid_rows = plan(conn, args)
        print_plan(moves, invalid_rows, dial_intel, args.limit)

        if not args.apply:
            if moves or invalid_rows:
                print("\nDry-run only. Re-run with --apply to write"
                      " (consider `python dbtool.py --backup` first).")
            return 0

        created, updated, deleted = apply_moves(conn, moves, dial_intel)
        for number in invalid_rows:
            conn.execute("DELETE FROM dial_intel WHERE number = ?", (number,))
        conn.commit()
        print(f"\nApplied: {len(moves)} knock pair(s) rewritten;"
              f" dial_intel rows: +{created} created, {updated} adjusted,"
              f" -{deleted + len(invalid_rows)} deleted.")
        print("Restart knock-monitor (or wait for its next start) so the SIP honeypot"
              " reseeds its dial cache from the cleaned dial_intel.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())

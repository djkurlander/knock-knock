#!/usr/bin/env python3
"""
Prune likely parser artifacts from dial_intel.

SIP fraud bots often try the same target with many PBX/access prefixes. Some
prefixed strings can parse as plausible but wrong E.164 numbers. This script
removes low-hit dial_intel rows when a much stronger shorter suffix target
exists.

Dry-run is the default. Use --apply to delete from dial_intel.

Usage:
    python extras/db-migrations/prune_dial_intel_suffix_artifacts.py
    python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --max-suspect-hits 50 --with-knock-samples
    python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --mode nanp-alias --with-knock-samples
    python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --db data/knock_knock.db --apply
"""

import argparse
import sqlite3
from pathlib import Path


DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / "data" / "knock_knock.db"


def fetch_candidates(conn, max_suspect_hits, min_hit_ratio):
    sql = """
        WITH d AS (
            SELECT
                number,
                replace(number, '+', '') AS digits,
                hits,
                first_seen,
                last_seen,
                country,
                country_name
            FROM dial_intel
            WHERE number IS NOT NULL
        ),
        matches AS (
            SELECT
                a.number AS suspect_number,
                a.digits AS suspect_digits,
                a.hits AS suspect_hits,
                a.first_seen AS suspect_first_seen,
                a.last_seen AS suspect_last_seen,
                a.country AS suspect_country,
                a.country_name AS suspect_country_name,
                b.number AS canonical_number,
                b.digits AS canonical_digits,
                b.hits AS canonical_hits,
                b.first_seen AS canonical_first_seen,
                b.last_seen AS canonical_last_seen,
                b.country AS canonical_country,
                b.country_name AS canonical_country_name,
                row_number() OVER (
                    PARTITION BY a.number
                    ORDER BY b.hits DESC, b.last_seen DESC, length(b.digits) DESC
                ) AS rn
            FROM d a
            JOIN d b
              ON length(a.digits) > length(b.digits)
             AND substr(a.digits, -length(b.digits)) = b.digits
            WHERE a.hits <= ?
              AND b.hits >= a.hits * ?
              AND b.country IS NOT NULL
              AND b.country != 'XX'
        )
        SELECT
            suspect_number,
            suspect_hits,
            suspect_country,
            suspect_country_name,
            suspect_first_seen,
            suspect_last_seen,
            canonical_number,
            canonical_hits,
            canonical_country,
            canonical_country_name,
            canonical_first_seen,
            canonical_last_seen,
            printf('%.1f', CAST(canonical_hits AS REAL) / NULLIF(suspect_hits, 0)) AS hit_ratio
        FROM matches
        WHERE rn = 1
        ORDER BY suspect_hits DESC, canonical_hits DESC, suspect_last_seen DESC
    """
    return conn.execute(sql, (max_suspect_hits, min_hit_ratio)).fetchall()


def fetch_nanp_alias_candidates(conn, max_suspect_hits, min_hit_ratio):
    sql = """
        WITH d AS (
            SELECT
                number,
                replace(number, '+', '') AS digits,
                hits,
                first_seen,
                last_seen,
                country,
                country_name
            FROM dial_intel
            WHERE number IS NOT NULL
        )
        SELECT
            a.number AS suspect_number,
            a.hits AS suspect_hits,
            a.country AS suspect_country,
            a.country_name AS suspect_country_name,
            a.first_seen AS suspect_first_seen,
            a.last_seen AS suspect_last_seen,
            b.number AS canonical_number,
            b.hits AS canonical_hits,
            b.country AS canonical_country,
            b.country_name AS canonical_country_name,
            b.first_seen AS canonical_first_seen,
            b.last_seen AS canonical_last_seen,
            printf('%.1f', CAST(b.hits AS REAL) / NULLIF(a.hits, 0)) AS hit_ratio
        FROM d a
        JOIN d b
          ON length(a.digits) = 10
         AND b.digits = '1' || a.digits
        WHERE a.hits <= ?
          AND b.hits >= a.hits * ?
          AND b.country IS NOT NULL
          AND b.country != 'XX'
        ORDER BY a.hits DESC, b.hits DESC, a.last_seen DESC
    """
    return conn.execute(sql, (max_suspect_hits, min_hit_ratio)).fetchall()


def print_candidates(candidates, limit):
    if not candidates:
        print("No dial_intel suffix artifact candidates found.")
        return

    print(f"Candidates: {len(candidates)}")
    print()
    print(
        "suspect_number".ljust(18),
        "hits".rjust(5),
        "country".ljust(4),
        "canonical_number".ljust(18),
        "canon_hits".rjust(10),
        "canon_country".ljust(4),
        "ratio".rjust(8),
        "suspect_last_seen",
    )
    print("-" * 96)
    for row in candidates[:limit]:
        print(
            str(row["suspect_number"]).ljust(18),
            str(row["suspect_hits"]).rjust(5),
            str(row["suspect_country"] or "").ljust(4),
            str(row["canonical_number"]).ljust(18),
            str(row["canonical_hits"]).rjust(10),
            str(row["canonical_country"] or "").ljust(4),
            str(row["hit_ratio"]).rjust(8),
            row["suspect_last_seen"],
        )
    if len(candidates) > limit:
        print(f"... {len(candidates) - limit} more not shown")


def fetch_knock_samples(conn, dial_number, limit):
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='knocks_sip'"
    ).fetchone()
    if not table_exists:
        return 0, []

    total = conn.execute(
        "SELECT COUNT(*) FROM knocks_sip WHERE sip_dial_number = ?",
        (dial_number,),
    ).fetchone()[0]
    rows = conn.execute(
        """SELECT
               sip_dial_string,
               COUNT(*) AS hits,
               MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen
           FROM knocks_sip
           WHERE sip_dial_number = ?
           GROUP BY sip_dial_string
           ORDER BY hits DESC, last_seen DESC
           LIMIT ?""",
        (dial_number, limit),
    ).fetchall()
    return total, rows


def print_knock_samples(conn, candidates, preview_limit, sample_limit):
    shown = candidates[:preview_limit]
    if not shown:
        return
    print()
    print("knocks_sip samples:")
    for row in shown:
        print()
        for label, dial_number in (
            ("suspect", row["suspect_number"]),
            ("canonical", row["canonical_number"]),
        ):
            total, samples = fetch_knock_samples(conn, dial_number, sample_limit)
            print(f"  {label} {dial_number} ({total} knock row(s))")
            if not samples:
                print("    <none>")
                continue
            for sample in samples:
                print(
                    "    "
                    f"{sample['hits']}x "
                    f"{sample['sip_dial_string']} "
                    f"[{sample['first_seen']} -> {sample['last_seen']}]"
                )


def prune(db_path, mode, apply, max_suspect_hits, min_hit_ratio, preview_limit, with_knock_samples, sample_limit):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) FROM dial_intel").fetchone()[0]
    if mode == "suffix":
        candidates = fetch_candidates(conn, max_suspect_hits, min_hit_ratio)
        rule = f"suspect.hits <= {max_suspect_hits}, canonical.hits >= suspect.hits * {min_hit_ratio:g}"
    elif mode == "nanp-alias":
        candidates = fetch_nanp_alias_candidates(conn, max_suspect_hits, min_hit_ratio)
        rule = f"10-digit suspect.hits <= {max_suspect_hits}, 1+suspect canonical.hits >= suspect.hits * {min_hit_ratio:g}"
    else:
        raise ValueError(f"unknown mode: {mode}")

    print(f"Database: {db_path}")
    print(f"dial_intel rows: {total}")
    print(f"Mode: {mode}")
    print(f"Rule: {rule}")
    print()
    print_candidates(candidates, preview_limit)
    if with_knock_samples:
        print_knock_samples(conn, candidates, preview_limit, sample_limit)

    if not apply:
        print()
        print("Dry run - no changes made. Re-run with --apply to delete these dial_intel rows.")
        conn.close()
        return

    suspect_numbers = [row["suspect_number"] for row in candidates]
    if not suspect_numbers:
        conn.close()
        return

    conn.executemany("DELETE FROM dial_intel WHERE number = ?", [(number,) for number in suspect_numbers])
    deleted = conn.total_changes
    conn.commit()
    remaining = conn.execute("SELECT COUNT(*) FROM dial_intel").fetchone()[0]
    conn.close()

    print()
    print(f"Deleted {deleted} dial_intel row(s).")
    print(f"dial_intel rows now: {remaining}")
    print("knocks_sip was not modified.")


def main():
    parser = argparse.ArgumentParser(description="Prune likely low-hit dial_intel suffix artifacts")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Path to knock_knock.db")
    parser.add_argument("--mode", choices=("suffix", "nanp-alias"), default="suffix", help="Prune rule to use")
    parser.add_argument("--apply", action="store_true", help="Delete candidates. Default is dry-run.")
    parser.add_argument("--max-suspect-hits", type=int, default=5, help="Only delete suspects at or below this hit count")
    parser.add_argument("--min-hit-ratio", type=float, default=5.0, help="Canonical row must have at least this many times the suspect hits")
    parser.add_argument("--preview-limit", type=int, default=80, help="Maximum candidate rows to print")
    parser.add_argument("--with-knock-samples", action="store_true", help="Show grouped raw knocks_sip dial strings for each previewed suspect/canonical pair")
    parser.add_argument("--sample-limit", type=int, default=5, help="Raw knocks_sip dial-string groups to show per suspect/canonical number")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")
    if args.max_suspect_hits < 1:
        raise SystemExit("--max-suspect-hits must be >= 1")
    if args.min_hit_ratio <= 1:
        raise SystemExit("--min-hit-ratio must be > 1")
    if args.sample_limit < 1:
        raise SystemExit("--sample-limit must be >= 1")

    prune(
        db_path,
        args.mode,
        args.apply,
        args.max_suspect_hits,
        args.min_hit_ratio,
        args.preview_limit,
        args.with_knock_samples,
        args.sample_limit,
    )


if __name__ == "__main__":
    main()

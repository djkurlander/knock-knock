#!/usr/bin/env python3
"""
Repair per-protocol SMTP intel rows after migrate_mail_to_smtp.py dropped columns.

The original MAIL -> SMTP migration merged rows into *_proto tables using only the
minimal shared columns. That left SMTP rows missing:
  - country_intel_proto.country
  - isp_intel_proto.asn
  - ip_intel_proto.lat / ip_intel_proto.lng

These values can be reconstructed from the corresponding global intel tables.

Usage:
    python fix_mail_migration.py data/knock_knock.db

Safe to run multiple times.
"""

import sqlite3
import sys

SMTP_PROTO = 2


def count_missing(cur, table, where_sql):
    cur.execute(f"SELECT COUNT(*) FROM {table} WHERE proto = ? AND ({where_sql})", (SMTP_PROTO,))
    return cur.fetchone()[0]


def repair(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    cur = conn.cursor()

    before = {
        "country": count_missing(cur, "country_intel_proto", "country IS NULL OR country = ''"),
        "asn": count_missing(cur, "isp_intel_proto", "asn IS NULL"),
        "latlng": count_missing(cur, "ip_intel_proto", "lat IS NULL OR lng IS NULL"),
    }

    cur.execute(
        """
        UPDATE country_intel_proto
        SET country = (
            SELECT country_intel.country
            FROM country_intel
            WHERE country_intel.iso_code = country_intel_proto.iso_code
        )
        WHERE proto = ?
          AND (country IS NULL OR country = '')
          AND EXISTS (
              SELECT 1
              FROM country_intel
              WHERE country_intel.iso_code = country_intel_proto.iso_code
                AND country_intel.country IS NOT NULL
                AND country_intel.country != ''
          )
        """,
        (SMTP_PROTO,),
    )
    country_fixed = cur.rowcount

    cur.execute(
        """
        UPDATE isp_intel_proto
        SET asn = (
            SELECT isp_intel.asn
            FROM isp_intel
            WHERE isp_intel.isp = isp_intel_proto.isp
        )
        WHERE proto = ?
          AND asn IS NULL
          AND EXISTS (
              SELECT 1
              FROM isp_intel
              WHERE isp_intel.isp = isp_intel_proto.isp
                AND isp_intel.asn IS NOT NULL
          )
        """,
        (SMTP_PROTO,),
    )
    asn_fixed = cur.rowcount

    cur.execute(
        """
        UPDATE ip_intel_proto
        SET lat = COALESCE(
                lat,
                (SELECT ip_intel.lat FROM ip_intel WHERE ip_intel.ip = ip_intel_proto.ip)
            ),
            lng = COALESCE(
                lng,
                (SELECT ip_intel.lng FROM ip_intel WHERE ip_intel.ip = ip_intel_proto.ip)
            )
        WHERE proto = ?
          AND (lat IS NULL OR lng IS NULL)
          AND EXISTS (
              SELECT 1
              FROM ip_intel
              WHERE ip_intel.ip = ip_intel_proto.ip
                AND (ip_intel.lat IS NOT NULL OR ip_intel.lng IS NOT NULL)
          )
        """,
        (SMTP_PROTO,),
    )
    latlng_fixed = cur.rowcount

    conn.commit()

    after = {
        "country": count_missing(cur, "country_intel_proto", "country IS NULL OR country = ''"),
        "asn": count_missing(cur, "isp_intel_proto", "asn IS NULL"),
        "latlng": count_missing(cur, "ip_intel_proto", "lat IS NULL OR lng IS NULL"),
    }
    conn.close()

    print("SMTP migration repair complete")
    print(f"  country_intel_proto: fixed {country_fixed}, remaining missing {after['country']} (was {before['country']})")
    print(f"  isp_intel_proto.asn: fixed {asn_fixed}, remaining missing {after['asn']} (was {before['asn']})")
    print(f"  ip_intel_proto lat/lng: fixed {latlng_fixed}, remaining missing {after['latlng']} (was {before['latlng']})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path/to/knock_knock.db>")
        sys.exit(1)
    repair(sys.argv[1])

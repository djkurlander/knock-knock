#!/usr/bin/env bash
set -euo pipefail

# Report SQLite space overhead for multi-protocol support vs SSH-only scenarios.
# Usage:
#   extras/db-overhead-report.sh [--json] [path/to/knock_knock.db]

JSON=0
DB_PATH="data/knock_knock.db"

for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    *) DB_PATH="$arg" ;;
  esac
done

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 not found" >&2
  exit 1
fi

if [ ! -f "$DB_PATH" ]; then
  echo "DB not found: $DB_PATH" >&2
  exit 1
fi

SQLITE=(sqlite3 -cmd ".timeout 5000")

db_bytes="$(stat -c%s "$DB_PATH")"
IFS='|' read -r page_size page_count freelist_count <<EOF
$("${SQLITE[@]}" "$DB_PATH" "SELECT (SELECT page_size FROM pragma_page_size), (SELECT page_count FROM pragma_page_count), (SELECT freelist_count FROM pragma_freelist_count);")
EOF
page_size="${page_size:-0}"
page_count="${page_count:-0}"
freelist_count="${freelist_count:-0}"

proto_tables_bytes="$("${SQLITE[@]}" "$DB_PATH" "
WITH s AS (SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name)
SELECT COALESCE(SUM(bytes),0) FROM s
WHERE name IN ('user_intel_proto','pass_intel_proto','country_intel_proto','isp_intel_proto','ip_intel_proto');
")"

proto_idx_manual_bytes="$("${SQLITE[@]}" "$DB_PATH" "
WITH s AS (SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name)
SELECT COALESCE(SUM(bytes),0) FROM s
WHERE name IN ('idx_user_intel_proto_hits','idx_pass_intel_proto_hits','idx_country_intel_proto_hits','idx_isp_intel_proto_hits','idx_ip_intel_proto_hits');
")"

proto_idx_auto_bytes="$("${SQLITE[@]}" "$DB_PATH" "
WITH s AS (SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name)
SELECT COALESCE(SUM(bytes),0) FROM s
WHERE name IN ('sqlite_autoindex_user_intel_proto_1','sqlite_autoindex_pass_intel_proto_1','sqlite_autoindex_country_intel_proto_1','sqlite_autoindex_isp_intel_proto_1','sqlite_autoindex_ip_intel_proto_1');
")"
proto_tables_bytes="${proto_tables_bytes:-0}"
proto_idx_manual_bytes="${proto_idx_manual_bytes:-0}"
proto_idx_auto_bytes="${proto_idx_auto_bytes:-0}"

proto_struct_bytes="$((proto_tables_bytes + proto_idx_manual_bytes + proto_idx_auto_bytes))"

IFS='|' read -r ssh_knocks non_ssh_knocks <<EOF
$("${SQLITE[@]}" "$DB_PATH" "SELECT COALESCE(SUM(CASE WHEN proto=0 THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN proto!=0 THEN 1 ELSE 0 END),0) FROM knocks;")
EOF
ssh_knocks="${ssh_knocks:-0}"
non_ssh_knocks="${non_ssh_knocks:-0}"
total_knocks="$((ssh_knocks + non_ssh_knocks))"

proto_struct_pct="0.00"
non_ssh_pct="0.00"
if [ "$db_bytes" -gt 0 ]; then
  proto_struct_pct="$(awk "BEGIN { printf \"%.2f\", (100.0 * $proto_struct_bytes / $db_bytes) }")"
fi
if [ "$total_knocks" -gt 0 ]; then
  non_ssh_pct="$(awk "BEGIN { printf \"%.2f\", (100.0 * $non_ssh_knocks / $total_knocks) }")"
fi

tmp_drop_proto="$(mktemp /tmp/knock_drop_proto.XXXXXX.db)"
tmp_ssh_only="$(mktemp /tmp/knock_ssh_only.XXXXXX.db)"
trap 'rm -f "$tmp_drop_proto" "$tmp_ssh_only"' EXIT

cp "$DB_PATH" "$tmp_drop_proto"
"${SQLITE[@]}" "$tmp_drop_proto" "
DROP TABLE IF EXISTS user_intel_proto;
DROP TABLE IF EXISTS pass_intel_proto;
DROP TABLE IF EXISTS country_intel_proto;
DROP TABLE IF EXISTS isp_intel_proto;
DROP TABLE IF EXISTS ip_intel_proto;
DROP INDEX IF EXISTS idx_user_intel_proto_hits;
DROP INDEX IF EXISTS idx_pass_intel_proto_hits;
DROP INDEX IF EXISTS idx_country_intel_proto_hits;
DROP INDEX IF EXISTS idx_isp_intel_proto_hits;
DROP INDEX IF EXISTS idx_ip_intel_proto_hits;
VACUUM;
"
sim_drop_proto_bytes="$(stat -c%s "$tmp_drop_proto")"

cp "$DB_PATH" "$tmp_ssh_only"
"${SQLITE[@]}" "$tmp_ssh_only" "
DELETE FROM knocks WHERE proto!=0;
DROP TABLE IF EXISTS user_intel_proto;
DROP TABLE IF EXISTS pass_intel_proto;
DROP TABLE IF EXISTS country_intel_proto;
DROP TABLE IF EXISTS isp_intel_proto;
DROP TABLE IF EXISTS ip_intel_proto;
DROP INDEX IF EXISTS idx_user_intel_proto_hits;
DROP INDEX IF EXISTS idx_pass_intel_proto_hits;
DROP INDEX IF EXISTS idx_country_intel_proto_hits;
DROP INDEX IF EXISTS idx_isp_intel_proto_hits;
DROP INDEX IF EXISTS idx_ip_intel_proto_hits;
VACUUM;
"
sim_ssh_only_bytes="$(stat -c%s "$tmp_ssh_only")"

drop_proto_delta="$((db_bytes - sim_drop_proto_bytes))"
ssh_only_delta="$((db_bytes - sim_ssh_only_bytes))"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$JSON" -eq 1 ]; then
  cat <<EOF
{
  "timestamp_utc": "$timestamp",
  "db_path": "$DB_PATH",
  "db_bytes": $db_bytes,
  "page_size": $page_size,
  "page_count": $page_count,
  "freelist_count": $freelist_count,
  "proto_tables_bytes": $proto_tables_bytes,
  "proto_indexes_manual_bytes": $proto_idx_manual_bytes,
  "proto_indexes_auto_bytes": $proto_idx_auto_bytes,
  "proto_struct_bytes": $proto_struct_bytes,
  "proto_struct_pct": $proto_struct_pct,
  "ssh_knocks": $ssh_knocks,
  "non_ssh_knocks": $non_ssh_knocks,
  "non_ssh_pct": $non_ssh_pct,
  "sim_drop_proto_bytes": $sim_drop_proto_bytes,
  "sim_drop_proto_delta": $drop_proto_delta,
  "sim_ssh_only_bytes": $sim_ssh_only_bytes,
  "sim_ssh_only_delta": $ssh_only_delta
}
EOF
else
  cat <<EOF
timestamp_utc=$timestamp
db_path=$DB_PATH
db_bytes=$db_bytes page_size=$page_size page_count=$page_count freelist_count=$freelist_count
proto_tables_bytes=$proto_tables_bytes proto_indexes_manual_bytes=$proto_idx_manual_bytes proto_indexes_auto_bytes=$proto_idx_auto_bytes
proto_struct_bytes=$proto_struct_bytes proto_struct_pct=${proto_struct_pct}%
ssh_knocks=$ssh_knocks non_ssh_knocks=$non_ssh_knocks non_ssh_pct=${non_ssh_pct}%
sim_drop_proto_bytes=$sim_drop_proto_bytes sim_drop_proto_delta=$drop_proto_delta
sim_ssh_only_bytes=$sim_ssh_only_bytes sim_ssh_only_delta=$ssh_only_delta
EOF
fi

#!/usr/bin/env bash
#
# sip_daily_scan.sh — read-only evidence scan for /sip-daily-review (Steps 0–7).
#
# Runs the whole analysis batch in one auditable, read-only command so the review
# can be auto-approved with a single allowlist rule (Bash(*/sip_daily_scan.sh *))
# instead of allowlisting a pile of shell helpers. It NEVER writes to the repo; the
# only side effects are (a) refreshing the gitignored Telnyx number-lookup cache
# (idempotent, fractions of a cent for genuinely-new targets) and (b) a /tmp slice.
#
# The diary/notes WRITE step stays in the skill (Step 9) behind the user's approval —
# this script only gathers evidence and prints it.
#
# Usage:
#   extras/sip-number-exploration/sip_daily_scan.sh ["YYYY-MM-DD HH:MM:SS"]  # cutoff
#   extras/sip-number-exploration/sip_daily_scan.sh --no-cache-refresh ["CUT"]
#
# Cutoff defaults to the diary file's mtime (the skill's documented fallback).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DB="data/knock_knock.db"
TRACE="data/b2bua_trace.log"
DIARY="extras/notes/sip_daily_observations.md"
CACHE="extras/sip-number-exploration/telnyx_number_lookup_cache.json"
RTP_DIR="data/rtp_dumps"
EMBASSIES="'+12022234942','+12029446000','+12023423800','+12025886500'"

REFRESH=1
if [[ "${1:-}" == "--no-cache-refresh" ]]; then REFRESH=0; shift; fi

CUT="${1:-}"
if [[ -z "$CUT" ]]; then
  CUT="$(date -u -r "$DIARY" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
fi
if [[ -z "$CUT" ]]; then
  echo "ERROR: no cutoff given and could not derive one from $DIARY mtime" >&2
  exit 2
fi
CUT_ISO="${CUT/ /T}"
SLICE="$(mktemp /tmp/sip_scan.XXXXXX.log)"
trap 'rm -f "$SLICE"' EXIT

sec() { printf '\n========== %s ==========\n' "$*"; }

echo "window: since $CUT UTC  →  $(date -u '+%Y-%m-%d %H:%M:%S') UTC   (LA1, source=0)"

# ---------------------------------------------------------------- Step 0
sec "Step 0 — carrier/rate cache refresh"
MISS=$(python3 extras/sip-number-exploration/telnyx_number_lookup_cache.py --dry-run 2>/dev/null | grep -c '^+')
echo "new dial_intel targets not yet cached: $MISS"
if [[ "$REFRESH" == "1" ]]; then
  python3 extras/sip-number-exploration/telnyx_number_lookup_cache.py 2>&1 | tail -3
else
  echo "(--no-cache-refresh: skipped the live lookup)"
fi

# ---------------------------------------------------------------- Step 2
sec "Step 2 — B2BUA outcome breakdown"
awk -v c="$CUT_ISO" '$1>c' "$TRACE" > "$SLICE"
echo "trace lines in window: $(wc -l < "$SLICE")"
echo "stages:";        grep -oE 'stage=[a-z_]+' "$SLICE" | sort | uniq -c | sort -rn
echo "closed reasons:"; grep 'stage=closed' "$SLICE" | grep -oE "reason='[^']+'" | sort | uniq -c | sort -rn
echo "setup_failed:";   grep 'stage=setup_failed' "$SLICE" | grep -oE "ip='[^']+'" | sort | uniq -c | sort -rn
echo "--- analyzer summary ---"
python3 extras/sip-b2bua-trace/b2bua_trace.py "$SLICE"
echo "--- completions / holds ---"
python3 extras/sip-b2bua-trace/b2bua_trace.py "$SLICE" --completions --top 25

# ---------------------------------------------------------------- Step 3
sec "Step 3 — knocks_sip aggregates (LA1)"
echo "top source IPs:"
sqlite3 -separator ' | ' "$DB" "
  SELECT ip_address, isp, asn, COUNT(*) c, COUNT(DISTINCT sip_dial_number) dests
  FROM knocks_sip WHERE source=0 AND timestamp>'$CUT'
  GROUP BY ip_address ORDER BY c DESC LIMIT 15;"
echo "top dialed numbers:"
sqlite3 -separator ' | ' "$DB" "
  SELECT sip_dial_number, sip_dial_country, COUNT(*) c, COUNT(DISTINCT ip_address) ips
  FROM knocks_sip WHERE source=0 AND timestamp>'$CUT'
    AND sip_dial_number IS NOT NULL AND sip_dial_number!=''
  GROUP BY sip_dial_number ORDER BY c DESC LIMIT 20;"

# ---------------------------------------------------------------- Step 4
sec "Step 4 — held/ACKed destinations: carrier + line-type + rate (from cache)"
# Pull held/ACKed destination numbers straight out of the completions output.
HELD_NUMS=$(python3 extras/sip-b2bua-trace/b2bua_trace.py "$SLICE" --completions --top 100 2>/dev/null \
            | grep -oE 'num=\+[0-9]+' | sed 's/num=//' | sort -u)
if [[ -n "$HELD_NUMS" ]]; then
  python3 - "$CACHE" $HELD_NUMS <<'PY'
import json, sys
cache_path, nums = sys.argv[1], sys.argv[2:]
c = json.load(open(cache_path))
for num in nums:
    e = c.get(num, {}); da = (e.get("response") or {}).get("data") or {}
    car = da.get("carrier") or {}; port = da.get("portability") or {}; rate = e.get("rate") or {}
    name = port.get("spid_carrier_name") or car.get("name") or "?"
    print(f"{num:16} {str(da.get('country_code')):3} {str(car.get('type')):11.11} "
          f"{name:30.30} rate/min={rate.get('rate_per_minute')} "
          f"setup={rate.get('call_setup_fee')}  {rate.get('rate_description') or ''}")
PY
else
  echo "(no held/ACKed destinations in window)"
fi

# ---------------------------------------------------------------- Step 5
sec "Step 5 — two-axis media analysis (recv × sent)"
python3 extras/sip-b2bua-trace/b2bua_trace.py "$SLICE" --listeners --top 20

# ---------------------------------------------------------------- Step 6
sec "Step 6 — RTP media-probe triage"
echo "non-empty in-window dumps by source IP:"
find "$RTP_DIR" -newermt "$CUT" -name 'LA1-*.rtp' -size +0c -printf '%f\n' 2>/dev/null \
  | awk -F- '{print $2}' | sort | uniq -c | sort -rn | head
echo "--- cross-IP frame fingerprints (whole corpus) ---"
python3 extras/sip_rtp_triage.py "$RTP_DIR/" --fingerprint 2>&1 | tail -18

# ---------------------------------------------------------------- Step 7
sec "Step 7 — embassy beacons & silence check"
echo "in-window vs prior-7d embassy call counts:"
sqlite3 -separator ' | ' "$DB" "
  SELECT 'in-window', COUNT(*) FROM knocks_sip WHERE source=0 AND timestamp>'$CUT'
    AND sip_dial_number IN ($EMBASSIES)
  UNION ALL SELECT 'prior-7d', COUNT(*) FROM knocks_sip WHERE source=0
    AND timestamp>datetime('$CUT','-7 days') AND timestamp<='$CUT'
    AND sip_dial_number IN ($EMBASSIES);"
echo "last call per embassy DID:"
sqlite3 -separator ' | ' "$DB" "
  SELECT sip_dial_number, MAX(timestamp) FROM knocks_sip WHERE source=0
    AND sip_dial_number IN ($EMBASSIES) GROUP BY sip_dial_number;"

sec "scan complete — proceed to Step 8 (compose candidates)"

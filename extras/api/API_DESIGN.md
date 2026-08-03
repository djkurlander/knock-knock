# IP Blocklist API — Design

Allows organizations to check their own IP ranges against the knock-knock blocklist to detect
compromised devices. A company that finds one of their IPs listed knows something on their network
is participating in attack traffic — useful for internal incident response.

---

## API Entry Point — Decision: Standalone service `knock-api` on port 8081

**Public URL base:** `https://api.knock-knock.net/` (root paths — the subdomain already says "api")

`extras/api/knock_api.py` is a self-contained FastAPI app with its own uvicorn instance on
port 8081 and its own systemd unit (`knock-api.service`). The service is named **knock-api**
(not blocklist-specific) so it can later grow non-blocklist endpoints. The in-memory sorted
list, ASN map, bisect logic, and DB queries all live in this one process — no Redis
intermediary for computation. Redis is used only for rate limiting state and health metrics
(lightweight keys, shared across restarts).

**main.py is untouched.**

**Cloudflare:**
- `api.knock-knock.net` DNS already configured (same origin IP as base domain)
- Existing Origin Rule rewrites all `knock-knock.net` → port 8080; add a
  **higher-priority rule**: hostname = `api.knock-knock.net` → port 8081
- Port 8081 confirmed free on the server

**Systemd:**
```
knock-api.service      # new optional unit (extras/api/knock-api.service)
knock-web.service      # unchanged
knock-monitor.service  # unchanged
```

---

## Endpoints

### `GET /check-ranges`

```
?ranges=198.51.100.0/24,203.0.113.0/22   # comma-separated CIDRs
&list=year                                 # year (default) | month
```

Response:
```json
{
  "list": "year",
  "generated_at": "2026-08-02T14:00:00Z",
  "ranges_checked": ["198.51.100.0/24"],
  "total_ips_checked": 256,
  "hits": [
    {
      "ip": "198.51.100.45",
      "hits": 312,
      "first_seen": "2026-01-14",
      "last_seen": "2026-08-01",
      "protocols": [
        { "proto": "SSH",  "hits": 280, "last_seen": "2026-08-01" },
        { "proto": "SIP",  "hits": 28,  "last_seen": "2026-07-30" },
        { "proto": "SMTP", "hits": 4,   "last_seen": "2026-06-15" }
      ]
    }
  ],
  "hit_count": 1,
  "total_matched": 1,
  "truncated": false
}
```

### `GET /check-asn`

```
?asn=12345        # ASN number
&list=year        # year (default) | month
```

Simpler than range-checking — a dict lookup on the in-memory per-ASN index. ASN is a stored
`ip_intel` column (observation-time ground truth), with a GeoLite2 fallback at snapshot-build
time for rows not yet re-observed. Useful for organizations that know their ASN but not their
full IP range inventory.

Response: same shape as `check-ranges`.

```json
{
  "list": "year",
  "generated_at": "2026-08-02T14:00:00Z",
  "asn": 12345,
  "isp": "Build-A-Bear Workshop",
  "hits": [
    {
      "ip": "198.51.100.45",
      "hits": 312,
      "first_seen": "2026-01-14",
      "last_seen": "2026-08-01",
      "protocols": [
        { "proto": "SSH",  "hits": 280, "last_seen": "2026-08-01" },
        { "proto": "SIP",  "hits": 28,  "last_seen": "2026-07-30" }
      ]
    }
  ],
  "hit_count": 1,
  "total_matched": 1,
  "truncated": false
}
```

Rate limit: same as `check-ranges` (20/hour per client IP). No query size limit needed —
ASN membership is already indexed. `total_matched` is always the exact count
(free from the in-memory index); the 25,000-row detail cap is a safety ceiling only.

---

### `GET /ip/{ip}`

Single IP detail. Metered by the global 300/min budget (waits briefly when exhausted).

```json
{
  "ip": "198.51.100.45",
  "listed": true,
  "hits": 312,
  "first_seen": "2026-01-14 03:22:10",
  "last_seen": "2026-08-01 07:12:44",
  "country": "United States",
  "isp": "Build-A-Bear Workshop",
  "asn": 12345,
  "banned": true,
  "ban_until": "2026-09-01T00:00:00Z",
  "protocols": [
    { "proto": "SSH",  "hits": 280, "last_seen": "2026-08-01 07:12:44" },
    { "proto": "SIP",  "hits": 28,  "last_seen": "2026-07-30 22:01:13" }
  ]
}
```

An IP with no recorded attacks returns `{"ip": "...", "listed": false}` (HTTP 200).
`first_seen` is `null` for IPs whose history predates the column (2026-08). Country/ISP come
from GeoLite2 at request time; ASN prefers the stored observation-time value.

---

## Architecture

```
Client curl → api.knock-knock.net (Cloudflare) → port 8081
                                                       │
                                              knock_api.py
                                              (standalone FastAPI/uvicorn)
                                                       │
                                    ┌──────────────────┼──────────────────┐
                                    │                  │                  │
                              check-ranges        check-asn          /ip/{ip}
                                    │                  │                  │
                          bisect_left + walk    asn_map lookup     SELECT ip_intel
                          on sorted_ips         on asn_map         (300/min global
                          then IN(...) DB       then IN(...) DB      budget, waits
                          for metadata          for metadata        then 429)
```

**In-memory cache (refreshed hourly, single DB pass):**
- `sorted_ips` — all IPs as a single sorted integer list (for `check-ranges` bisect)
- `asn_map` — `{asn: [sorted integer list of IPs for that ASN]}` (for `check-asn` lookup)

No data sharing between the two structures — `asn_map` values are independent sorted lists,
not indices into `sorted_ips`. Clean lookups, trivial memory cost: main list ~400KB,
`asn_map` sublists sum to another ~400KB total across all ASNs. ~800KB combined.

Both built from one `SELECT ip, asn FROM ip_intel` pass — no extra query cost.
`ip_intel` has no index on `asn`; the cache makes that irrelevant.

**main.py is untouched.** Redis is used only for rate limiting state (lightweight keys),
not for routing computation or payloads.

---

## Query Limits

| Limit | Value | Reason |
|-------|-------|--------|
| Max prefix length | /16 (65,536 IPs) | Largest realistic org range |
| Max ranges per request | 10 | Covers orgs with multiple allocations |
| Max detail rows returned | 25,000 | Safety ceiling only; `total_matched` is always exact, `truncated: true` if the cap is hit |

---

## Rate Limits

**Per-client (by requesting IP):**

| Endpoint | Limit |
|----------|-------|
| All endpoints combined | 500 requests/day |
| `check-ranges` | 20 requests/hour |
| `check-asn` | 20 requests/hour |
| `/ip/{ip}` | 30 requests/minute |

**Global:**

| Resource | Limit | Reason |
|----------|-------|--------|
| `/ip` lookups | 300/minute shared budget | Safety valve against distributed scraping, not a bottleneck |

When the global `/ip` budget is exhausted the request **waits** (up to 25 s) rather than
rejecting immediately; only if no token frees up does it return 429. All other limits return
429 immediately with a `Retry-After` header. Rejections do not consume quota.

---

## Processing Time Estimates

Measured on the production server (2026-08-03):

| Request | Time |
|---------|------|
| `check-ranges` /24, 2 hits (incl. metadata query) | ~2-4ms |
| `check-ranges` /16 | ~26ms wall incl. curl overhead |
| `check-asn`, 60+ member ASN | ~3ms |
| `/ip` single lookup | ~7-12ms |
| 20 parallel `/ip` requests | 374ms total |

Rate-limit checks add 2-3 Redis round-trips (~1ms) per request. The `/ip` global budget
(300/min) makes waits essentially theoretical at expected traffic levels.

---

## Redis Keys

| Key | Type | Purpose |
|-----|------|---------|
| `knock:api:{endpoint}:count` | string | Requests served per endpoint (all time) |
| `knock:api:{endpoint}:ms_last` | string | Last request processing time (ms) |
| `knock:api:{endpoint}:ms_max` | string | Slowest request ever (ms) |
| `knock:api:rate_limited:count` | string | Total requests rejected by rate limiter |
| `knock:api:rl:day:{ip}` | counter (TTL 24h) | Per-IP daily quota window |
| `knock:api:rl:check-ranges:{ip}` | counter (TTL 1h) | Per-IP hourly window |
| `knock:api:rl:check-asn:{ip}` | counter (TTL 1h) | Per-IP hourly window |
| `knock:api:rl:ip:{ip}` | counter (TTL 60s) | Per-IP minute window |
| `knock:api:rl:global_min` | counter (TTL 60s) | Global /ip budget window |

`rate_limited:count` and `ms_max` are the key diagnostic signals: rising rejections mean
the endpoint is being hammered; a growing ms_max means a slow query path worth a look.
Rejected requests never consume quota (the limiter decrements on rejection).

---

## Differentiation from AbuseIPDB CHECK-BLOCK

AbuseIPDB does offer a CIDR range endpoint (`CHECK-BLOCK`), but it is a paid subscriber feature
and returns generic abuse category codes. This API differs in ways that matter for incident response:

| | Knock-Knock | AbuseIPDB |
|--|-------------|-----------|
| Cost | Free, no API key | Subscriber feature |
| Data source | Single-source honeypot — observed attack traffic only | Crowdsourced reputation scores |
| Protocol detail | Exact protocols (SSH/SIP/SMTP etc.) with hit counts + dates | Generic category codes (e.g. "Port Scan") |
| Framing | "Is my network compromised?" | "Should I block this network?" |
| First/last seen | Yes, per IP and per protocol | Aggregated score only |

The protocol breakdown (sourced from `ip_intel_proto`) is the key differentiator — "this device
has been hitting SSH honeypots 280 times and SIP honeypots 28 times since January" tells an
investigator exactly what kind of compromise they're dealing with. Worth highlighting in the
blog post alongside the curl example.

---

## Relationship to Static Blocklist Files

The existing `generate.py` / cron pipeline (`ip-blocklist-year.txt`, `ip-blocklist-month.txt`)
is unchanged. The static files and the API are independent — different audiences, different use cases:

- **Static files** — pre-generated flat lists for firewall consumption (CSF, ipset, pfSense etc.)
- **API** — interactive range-checking with hit counts and first/last seen metadata

The checker worker queries `ip_intel` directly on its hourly refresh rather than reading the
static files. This keeps the two pipelines fully decoupled — a missed cron run does not silently
serve stale API data.

---

## New Components

| Component | Description |
|-----------|-------------|
| `extras/api/knock_api.py` | Standalone FastAPI app: in-memory snapshots, bisect logic, DB queries, rate limiting, visitor logging, all three endpoints |
| `extras/api/knock-api.service` | Systemd unit (copy to /etc/systemd/system/) |
| `extras/api/README.md` | Endpoint reference, curl examples, deploy steps |

---

## Companion Script

`extras/ip-blocklist/check_ip_ranges.py` — offline equivalent for organizations that prefer
to run the check locally. Fetches the public blocklist URL (or accepts a local file path),
loads into a sorted integer list, does the same bisect + forward walk, outputs a report.
Optionally emails results via the existing visitor-report SMTP config.

```bash
python3 extras/ip-blocklist/check_ip_ranges.py \
  --ranges 198.51.100.0/24,203.0.113.0/22 \
  --list year \
  --email security@example.com
```

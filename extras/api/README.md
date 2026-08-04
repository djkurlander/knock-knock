# knock-api — Public Query API

Standalone FastAPI service that lets any organization check its own address space against
the knock-knock attack database. A listed IP means a device in that network has been caught
attacking this honeypot — a free compromise-detection signal for the network's owner.

Runs independently of the dashboard (`main.py` is untouched). Default port 8081, fronted by
`api.knock-knock.net` via a Cloudflare Origin Rule. See [DESIGN.md](DESIGN.md) for the
design rationale.

## Endpoints

### `GET /check-ranges?ranges=<cidr>[,<cidr>...]&list=year|month`

Check up to 10 CIDR ranges (each /16 or smaller) against the blocklist.

```bash
curl 'https://api.knock-knock.net/check-ranges?ranges=198.51.100.0/24,203.0.113.0/22'
```

```json
{
  "list": "year",
  "generated_at": "2026-08-03T14:00:00Z",
  "ranges_checked": ["198.51.100.0/24", "203.0.113.0/22"],
  "total_ips_checked": 1280,
  "hits": [
    {
      "ip": "198.51.100.45",
      "hits": 312,
      "first_seen": "2026-01-14 03:22:10",
      "last_seen": "2026-08-01 07:12:44",
      "protocols": [
        {"proto": "SSH", "hits": 280, "last_seen": "2026-08-01 07:12:44"},
        {"proto": "SIP", "hits": 32, "last_seen": "2026-07-30 22:01:13"}
      ]
    }
  ],
  "hit_count": 1,
  "total_matched": 1,
  "truncated": false
}
```

### `GET /check-asn?asn=<number>&list=year|month`

Check every blocklisted IP announced by an ASN — no need to know your CIDR inventory.

```bash
curl 'https://api.knock-knock.net/check-asn?asn=12345'
```

Same response shape as `check-ranges`, plus top-level `asn` and `isp` (organization name).

### `GET /ip/<address>`

Full detail for a single IP.

```bash
curl 'https://api.knock-knock.net/ip/198.51.100.45'
```

```json
{
  "ip": "198.51.100.45",
  "listed": true,
  "hits": 312,
  "first_seen": "2026-01-14 03:22:10",
  "last_seen": "2026-08-01 07:12:44",
  "country": "United States",
  "isp": "Example Networks Inc",
  "asn": 12345,
  "banned": true,
  "ban_until": "2026-09-01T00:00:00Z",
  "protocols": [
    {"proto": "SSH", "hits": 280, "last_seen": "2026-08-01 07:12:44"}
  ]
}
```

An IP with no recorded attacks returns `{"ip": "...", "listed": false}` (HTTP 200).

## Rate limits

| Scope | Limit |
|-------|-------|
| All endpoints, per IP | 500 requests/day |
| `check-ranges` / `check-asn`, per IP | 20 requests/hour each |
| `/ip`, per IP | 30 requests/minute |
| `/ip`, global | 300/minute (over-budget requests wait up to 25 s, then 429) |

Rejected requests get HTTP 429 with a `Retry-After` header and
`{"error": "rate_limited", "retry_after_seconds": N}`.

## How it works

- An in-memory snapshot (sorted IP-integer list + per-ASN index, for both the 365-day and
  30-day windows) is rebuilt hourly from `ip_intel` in a single DB pass. Range checks are
  two binary searches; ASN checks are a dict lookup. No DB hit unless there are matches.
- Confirmed hits get one batched `IN(...)` query for hit counts, last-seen dates, and the
  per-protocol breakdown (`ip_intel_proto`).
- ASN is stored at observation time in `ip_intel` (ground truth survives IP reallocation),
  with a GeoLite2 fallback for rows not yet re-observed; country and ISP names come from
  GeoLite2. `first_seen` is `null` for IPs whose history predates the column (2026-08).
- Redis holds rate-limit windows and health metrics (`knock:api:*` keys); restarting the
  service does not reset client quotas.
- API requests are logged to `visitors.db` (same table the dashboard uses) when
  `LOG_VISITORS=true`.

## Maintaining the docs page (`api.html`) examples

The interactive docs page (served at `knock-knock.net/api` and the API root) shows a sample
JSON response under each endpoint. **Those samples are real API responses, kept identical to
what "Run" returns** — so pressing Run refreshes values in place instead of reshaping the
block. That creates one maintenance point:

`ip_intel` is a rolling **365-day window**, so an example IP/ASN can age *off* the list after
365 days with no new hits. When that happens, Run returns `{"listed": false}` / empty and
contradicts the static sample.

- The **check-asn** and **/ip** examples use Build-A-Bear (`104.238.197.106`, AS21811) — a
  currently-active but institutional one-off, so it's the example most likely to expire.
- The **check-ranges** example (`2.57.121.0/24`) is a persistent heavy attacker, far more
  durable.

**~Yearly, or whenever an example goes stale, swap it** (a two-minute job):

1. Pick a fresh, striking target — the appeal is an organization you'd never expect to be
   attacking. Bench, all from the `sip-compromised-pbx-canary` campaign: Guardia Civil (Spanish
   police), Royal Thai Army, State of Idaho / Nebraska, LA County Office of Education, Lockheed
   Martin, Citigroup, Etat du Valais. Find one currently listed:
   ```bash
   sqlite3 data/knock_knock.db "SELECT ip, isp, asn, hits, last_seen FROM ip_intel
     WHERE last_seen > datetime('now','-60 days')
     AND (isp LIKE '%Univ%' OR isp LIKE '%Gov%' OR isp LIKE '%Army%' OR isp LIKE '%Police%'
          OR isp LIKE '%County%' OR isp LIKE '%State of%' OR isp LIKE '%Bank%')
     ORDER BY last_seen DESC LIMIT 20;"
   ```
2. Update the `<input value="…">` for that example in `api.html`.
3. `curl` the endpoint once and paste its JSON into the sample `<pre>` (it's read fresh per
   request — no service restart needed for `api.html` edits).

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `KNOCK_API_PORT` | `8081` | Listening port |
| `KNOCK_API_LISTEN` | `0.0.0.0` | Bind interface |
| `REDIS_HOST` / `REDIS_DB` | `localhost` / `0` | Rate-limit + metrics store |
| `DB_DIR` | `data` | Location of `knock_knock.db` / `visitors.db` |
| `LOG_VISITORS` | unset | `true` = log API requests to `visitors.db` |
| `TRUST_PROXY_HEADERS` | `true` | Honor `CF-Connecting-IP` / `X-Forwarded-For` |

## Deploy

```bash
# systemd
cp extras/api/knock-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now knock-api
```

**TLS:** the service serves HTTPS when `ENABLE_SSL=true` (reusing `KNOCK_KEYFILE` /
`KNOCK_CERTFILE` — the same Origin CA cert as the web server). A Cloudflare **Full
(strict)** zone requires this; the cert's `*.<domain>` wildcard must cover the API
subdomain.

**Cloudflare:** add a DNS record for `api.<domain>` (same origin IP, **proxied**), then two
mutually-exclusive **Origin Rules** so precedence is irrelevant:
- `api.<domain>` → Destination Port **8081**
- everything else (`Hostname does not equal api.<domain>`) → Destination Port **8080**

**Firewall (the easy-to-miss step):** the honeypot restricts the web port to Cloudflare
IPs via `extras/cloudflare-ufw/update-cloudflare-ufw.sh`. Port 8081 needs the same
allowlist, or Cloudflare gets a **522** (connection timeout) to the origin. Add 8081 to the
`PORTS` list and to the refresh cron so the allowlist stays current as Cloudflare's ranges
change:

```bash
PORTS="8080 8081" bash extras/cloudflare-ufw/update-cloudflare-ufw.sh   # one-time
# and in the daily crontab entry:
0 4 * * * PORTS="8080 8081" /bin/bash /root/knock-knock/extras/cloudflare-ufw/update-cloudflare-ufw.sh >> /var/log/cloudflare-ufw.log 2>&1
```

## Health metrics (Redis)

```bash
redis-cli get knock:api:check-ranges:count     # requests served
redis-cli get knock:api:check-ranges:ms_last   # last request duration
redis-cli get knock:api:check-ranges:ms_max    # slowest ever
redis-cli get knock:api:rate_limited:count     # total 429s
```

# knock-api — Design & Rationale

Why the public query API (`knock_api.py`) is built the way it is. For endpoints, request/
response shapes, rate-limit values, config, and deploy steps see [README.md](README.md);
this doc is the "why," not the "how."

## What it is

A standalone FastAPI service that lets any organization check its own address space against
the honeypot's observed-attacker data. A listed IP means a device in that network was caught
attacking the honeypot — a free compromise-detection signal for its owner. Three GET
endpoints: `/check-ranges` (CIDRs), `/check-asn` (whole ASN), `/ip/<addr>` (single IP).

## Why a standalone service, not part of `main.py`

The dashboard server (`main.py`) already runs WebSockets, Redis pub/sub, the stats cache,
and visitor logging. Folding a public, potentially-hammered query API into that same event
loop couples an external attack surface to the live dashboard. Instead `knock_api.py` is its
own process on its own port (8081) with its own systemd unit — `main.py` is untouched. The
service is named **knock-api** (not blocklist-specific) so it can grow non-blocklist
endpoints later.

Redis is used only for rate-limit windows and health counters — never as a payload/routing
intermediary (an earlier design shuttled results through Redis; that was dropped once the
service became in-process, and the 1,000-hit response cap that existed to bound those Redis
blobs went with it).

## Architecture

```
Client → api.knock-knock.net (Cloudflare, 443) → origin :8081
                                                     │
                                              knock_api.py (uvicorn, HTTPS)
                                                     │
                        ┌────────────────────────────┼────────────────────────────┐
                   /check-ranges                 /check-asn                      /ip/<addr>
                        │                            │                              │
                bisect + walk over            dict lookup on               2 indexed point
                sorted_ips (in-mem)           asn_map (in-mem)             queries on ip_intel
                        │                            │                              │
                  IN(...) metadata query on ip_intel + ip_intel_proto      (300/min global
                  for confirmed hits only                                   budget; waits→429)
```

### In-memory snapshot (the core idea)

A background thread rebuilds a snapshot hourly from one `SELECT ip, asn, last_seen FROM
ip_intel` pass, for both the 365-day and 30-day windows:

- `sorted_ips` — every listed IP as a sorted `int`. A range check is two binary searches
  (`bisect_left` for the start, forward walk to the range end) — see below on why not a trie.
- `asn_map` — `{asn: [sorted ints]}`. An ASN check is a dict lookup + slice.

Membership never touches the database. Only *confirmed hits* trigger a single batched
`IN(...)` query for hit counts, first/last-seen, and the per-protocol breakdown. So a query
that matches nothing does zero disk I/O, and a query that matches a lot does exactly one
metadata round-trip.

### Why bisect-on-sorted-ints, not a trie

A trie shines when matching an IP against a set of *prefixes*. Here the data is individual
IPs and the query is a range — the inverse. Sorted ints + `bisect` is the natural fit:
~800 KB–23 MB resident, microsecond lookups, and the sort is a once-an-hour background cost.

## Data-model decisions

### ASN stored at observation time (not looked up at query time)

`ip_intel.asn` is written on every knock (the value is already in the knock payload, so it
costs no extra lookup) and reflects the ASN **as of the last observation**. GeoLite2 maps
reflect *today's* allocations, so resolving ASN at query time would misattribute any IP that
was reallocated since it attacked. Storing observation-time ground truth avoids that. The
snapshot build falls back to a GeoLite2 lookup only for the handful of rows with no stored
ASN (feeder-ingested or not-yet-re-observed). Measured effect: DigitalOcean returns 4,282
via the stored column vs. ~4,286 via current GeoLite2 — the gap is exactly the reallocated
IPs the stored value correctly keeps.

### first_seen

Set on insert going forward; historical rows are backfilled once (in `updatedb.py`) from
`MIN(timestamp)` across the `knocks_*` tables, which recorded it at knock time. Servers with
no saved knocks leave it `null` ("predates tracking"), which the API reports honestly.

Neither backfill can invent data it never had — that's why both prefer real captured history
(`knocks_*`) over a current-GeoLite2 guess.

## Limits and their rationale

Exact numbers live in the README; the reasoning:

- **`/16` max prefix.** The largest range a real org checks in one shot (~65k addresses).
  It doubles as a walk-cost bound — without it a `/1` query would walk ~78k entries (~20 ms);
  with it the walk is always cheap.
- **25,000-row detail ceiling + exact `total_matched`.** `total_matched` is computed for
  free from the in-memory structures (ASN member-list length; full bisect-walk count), so
  every response reports the true match size even in the (never-hit-in-practice) capped case.
  25k is a pure safety ceiling far above any real ASN — the largest cloud ASNs are a few
  thousand.
- **Rate limits** are per-IP fixed windows in Redis that *decrement on rejection* (a 429
  never consumes quota). The `/ip` endpoint additionally shares a 300/min global budget that
  **waits** up to 25 s for a slot before returning 429 — a scrape backstop, not a bottleneck
  at expected traffic.

## Measured performance (LA1, 2026-08-03, ~132k IPs)

In-process, isolating this machine's CPU/disk from the network:

| Phase | Cost |
|-------|------|
| Hourly snapshot rebuild | ~1.3–1.7 s, ~23 MB resident (background thread, off the request path) |
| `/check-ranges` /24 (in-mem) | ~11 µs |
| `/check-ranges` /8, 837 hits (in-mem) | ~134 µs |
| `/check-asn` 4,282 members (in-mem) | ~28 µs |
| `/ip` single lookup (DB) | ~0.6 ms |
| Metadata fetch, 100 hits (DB) | ~2.6 ms |
| Metadata fetch, 1,000 hits (DB) | ~19 ms |
| Metadata fetch, 4,282 hits — all of DigitalOcean (DB) | ~78 ms |

Membership is microseconds; the only per-request disk cost is the metadata fetch, ~18 µs/hit,
dominated by the `ip_intel_proto` breakdown. `fetch_meta` runs via `asyncio.to_thread`, so
even the worst case doesn't block the event loop. Nothing here stresses the box.

## Relationship to the static blocklist files

The `extras/ip-blocklist/generate.py` cron pipeline (`ip-blocklist-year.txt` /
`-month.txt`) is unchanged and independent: flat lists for firewall consumption (CSF, ipset,
pfSense) vs. the API's interactive lookups with metadata. The API reads `ip_intel` directly
on its hourly rebuild rather than the static files, so a missed cron run can't make it serve
stale data.

## Why the per-protocol breakdown matters

The response's value beyond a yes/no listing is the `ip_intel_proto` breakdown: "this device
hit SSH 280× and SIP 28× since January" tells an investigator what *kind* of compromise
they're chasing (credential brute-forcing vs. toll-fraud probing vs. web-exploit scanning),
not just that the IP is bad. That, plus the observation-time framing ("a device on your
network was caught attacking"), is what the endpoint is designed to surface.

## Scale-out path

The service already sits behind its own subdomain, so it can be split off its shared origin
port without any client-visible change: run a second instance on a new port, repoint the
`api.knock-knock.net` Cloudflare Origin Rule (and the UFW allowlist + refresh cron) to it,
done. Moving the port is config-only — `KNOCK_API_PORT` in `.env`, the Cloudflare rule, the
`update-cloudflare-ufw.sh` `PORTS` list (one-time run + the daily cron), and a service
restart. No code changes; nothing hardcodes the port.

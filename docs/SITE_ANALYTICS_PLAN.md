# Plan: Site Traffic Visualizer — ASN Typing, Bot Detection, nginx Log Adapter

## Context

Knock-knock is currently a pure honeypot — all traffic it sees is hostile. The goal here is to extend it so a site owner can point their nginx/Apache access logs at it and get the same real-time geo, classification, and leaderboard view, enriched with two new signals that are only meaningful with real-site traffic:

1. **ASN type** (datacenter vs consumer) — flips the suspicion signal; datacenter IPs are expected in the honeypot but suspicious on a real site
2. **Bot/crawler identification** — separates legitimate search crawlers (Googlebot, Bingbot) from attack tools and unknown automated traffic

This is a pure enrichment feature. It reuses the existing ingest pipeline unchanged; knocks from the nginx adapter flow through INGEST_PORT exactly like feeder-server knocks.

---

## Open Decisions

- **Bot/ASN persistence in knock table**: Bot name, bot type, and ASN type can flow through the broadcast package (via `after_save`) without being stored per-knock. For a traffic visualizer the live view is primary. If persistence is desired, the `HTTP+` protocol's own table (see below) is the right home — not `knocks_http`. Decision deferred.

- **`HTTP+` protocol name**: Placeholder name. Could be `HTTP_SITE`, `WEB`, `HTTP_ANALYTICS`, etc.

---

## Long-Term Architecture: `HTTP+` Protocol + `HTTP_ANALYTICS_ONLY` Preset

### `HTTP+` as an Extension Protocol (proto_id 1000+)

Analytics-specific schema belongs in a separate extension protocol rather than in the built-in `HTTP` definition. This avoids adding bot/ASN columns to `knocks_http` for all classic honeypot deployments. The `HTTP+` protocol would have:
- Its own `knocks_http_site` table with `http_bot_name`, `http_bot_type`, `asn_type` columns — only created when the protocol is active
- Its own display formats emphasizing visitor type and bot name over exploit/attack details
- Its own "honeypot script" entry pointing to the nginx/Apache log adapter
- Zero impact on classic `HTTP` honeypot deployments

### `HTTP_ANALYTICS_ONLY=1` — A Meta-Config Preset

A single env var acting as a profile switch, setting:
- `ENABLED_PROTOCOLS=HTTP+` (only the analytics protocol active)
- Appropriate defaults for site traffic (dedup windows, throttle rates tuned for real visitors)
- A mode flag broadcast to the frontend that triggers UI suppression

**UI changes in analytics mode** (building on existing Classic Mode logic, which already adapts when one protocol is active):
- Hide trivia and knock-knock joke panels
- Hide user/pass leaderboard panels (not applicable to HTTP traffic)
- Suppress Classic Mode's own protocol-switcher hiding (since we want `HTTP+` branding visible)
- Possibly retitle "Total Knocks" → "Total Visits"

---

## Components (Phase 1 — Foundation)

### 1. ASN Type Database (`extras/update-asn-types.py` + `data/asn_types.json`)

**What:** A downloaded ASN-number → type mapping, stored as a flat JSON dict `{asn_int: "hosting"|"isp"|"edu"|"gov"|"mil"|"ixp"}`. The ipapi.is ASN database is the recommended source (ASN-keyed, so lookup is O(1) integer key — no IP CIDR matching needed, since we already extract the ASN from GeoLite2).

**Refresh script** `extras/update-asn-types.py`:
- Downloads the ipapi.is ASN CSV (or equivalent)
- Writes `data/asn_types.json`
- Can be run manually or via cron (`0 3 1 * *` monthly is sufficient)
- Should be idempotent and safe to interrupt

**Loading in `monitor.py`:**
- New `_load_asn_types(path) -> dict[int, str]` function, called at startup alongside GeoIP reader init
- Stored in module-level `_ASN_TYPES: dict`
- `get_geo_enriched()` (line 870) extended to do `asn_type = _ASN_TYPES.get(asn_int, 'unknown')` and include it in the returned dict
- Graceful: if file missing, `_ASN_TYPES` is empty dict, `asn_type` defaults to `'unknown'`

**DB storage:**
- Add `asn_type TEXT DEFAULT 'unknown'` column to `isp_intel` (and `isp_intel_proto`)
- DB migration guard in `_init_db()`: `ALTER TABLE isp_intel ADD COLUMN asn_type TEXT DEFAULT 'unknown'` wrapped in try/except for idempotency
- `log_to_enriched_db()` upsert (line ~713) updated to write `asn_type`

**Propagation:**
- `get_geo_enriched()` returns `asn_type` in its dict
- `package` dict in main loop includes `asn_type`
- Published to Redis and broadcast via WebSocket as part of every knock

---

### 2. Bot/Crawler Detection (`protocols/http.py` — new `process_knock` hook)

**Dependency:** `device-detector` (PyPI). Soft import with graceful fallback:
```python
try:
    from device_detector import DeviceDetector
    _DD_AVAILABLE = True
except ImportError:
    _DD_AVAILABLE = False
```
Add `device-detector` to `requirements.txt`.

**New `_detect_bot(ua: str) -> dict | None`** in `protocols/http.py`:
- LRU cache keyed on UA string (`@functools.lru_cache(maxsize=2048)`)
- Returns `{'name': str, 'type': str}` if device-detector identifies it as a bot/crawler, else `None`
- Types to surface: `'crawler'`, `'bot'`, `'feed_reader'` (map device-detector's categories)

**New `process_knock(knock, _ctx)` hook** in `protocols/http.py`:

Two responsibilities:

*a) HTTP classification for adapter-originated knocks:*
- If `knock.get('http_purpose')` is absent (nginx adapter sent an unclassified knock):
  - Lazy-import `_classify_purpose` from `honeypots/http_honeypot.py`
  - Run it on `(http_method, http_path, http_user_agent, http_body)`
  - Set `knock['http_purpose']` and `knock['http_exploit']` from result
- If already classified (local honeypot knocks), skip — no-op

*b) Bot detection:*
- If `http_user_agent` present, call `_detect_bot(ua)`
- If a bot is identified: set `knock['http_bot_name']` and `knock['http_bot_type']`

Add to `DEFINITION` in `protocols/http.py`:
- `process_knock = "protocols.http:process_knock"` field
- Two new `Column` entries: `Column("http_bot_name", "TEXT")` and `Column("http_bot_type", "TEXT")`
- `http_bot_name` and `http_bot_type` are already covered by `passthrough_prefixes=["http_"]`

**New display format `"bot"`** in `protocols/http.py` `display_formats`:
```python
"bot": [
    [{"label": "bot",    "value_key": "http_bot_name"}],
    [{"label": "type",   "value_key": "http_bot_type"}],
    [{"label": "method", "value_key": "http_method"},
     {"label": "path",   "value_key": "http_path", "format": "truncate"}],
]
```
`after_save` hook: if `http_bot_name` is set, override `display_format` to `"bot"`.

---

### 3. nginx/Apache Log Adapter (`extras/nginx-adapter/`)

**Files:**
- `extras/nginx-adapter/knock_adapter.py` — the adapter script
- `extras/nginx-adapter/nginx-log-format.conf` — drop-in nginx config snippet

**nginx log format** (use `escape=json` to handle special chars):
```nginx
log_format knock_json escape=json
  '{"ip":"$remote_addr","method":"$request_method","path":"$request_uri",'
  '"ua":"$http_user_agent","host":"$host","port":$server_port}';
access_log /var/log/nginx/knock_json.log knock_json;
```

**Apache equivalent** (documented in README within the adapter dir):
```apache
LogFormat '{"ip":"%a","method":"%m","path":"%U%q","ua":"%{User-Agent}i","host":"%V","port":"%p"}' knock_json
CustomLog /var/log/apache2/knock_json.log knock_json
```

**`knock_adapter.py` behaviour:**
- CLI args: `--log-file`, `--host` (default `localhost`), `--port` (INGEST_PORT), `--source` (source ID for dashboard label), `--from-beginning` (replay existing log on startup, default: tail only new lines)
- Opens a persistent TCP connection to host:port; reconnects with backoff on failure
- Tails the log file with inotify or polling fallback
- Maps each nginx JSON line → knock JSON:
  ```json
  {"type":"KNOCK","proto":"HTTP","ip":"...","http_method":"...","http_path":"...",
   "http_user_agent":"...","http_host":"...","http_port":80,"source":"my-site"}
  ```
- Note: `http_purpose`/`http_exploit` intentionally absent — the `process_knock` hook in monitor.py fills them in

---

### 4. Dashboard Enrichment (`index.html`, `main.py`)

**ISP leaderboard (`top_providers`):**
- `GlobalStatsCache` query in `main.py` (line ~280) updated to `SELECT isp, hits, asn_type FROM isp_intel ORDER BY hits DESC LIMIT N`
- Each provider entry in the broadcast now includes `asn_type`
- `index.html` ISP leaderboard row: small badge `[DC]` / `[ISP]` appended to label when `asn_type` is `'hosting'` or `'isp'`

**Knock feed:**
- No change needed — the new `"bot"` display format in `protocols/http.py` is already wired into the existing `display_format` rendering path in `index.html` (lines 2986-3005). The bot name will appear automatically once the format key exists.

---

## Hook Placement Rationale

Understanding where each piece of logic runs matters because the monitor processes each knock in a fixed order:

```
parse → sanitize → process_knock hook → get_geo_enriched() → build package
  → _db_write_queue.put(package.copy())   ← DB snapshot taken here
  → after_save hook                        ← can still mutate package for broadcast
  → r.lpush("knock:recent", ...)           ← Redis/WebSocket broadcast
```

### `process_knock` hook — bot detection + HTTP classification

**Runs:** Before geo enrichment, before DB write is queued.

**Handles:**
- **HTTP classification** for adapter-originated knocks: nginx adapter sends no `http_purpose`. The hook checks `knock.get('http_purpose')` and, if absent, calls `_classify_purpose(method, path, ua, body)` to set `knock['http_purpose']` and `knock['http_exploit']`. Local honeypot knocks already have these fields — no-op for them.
- **Bot detection**: Calls `_detect_bot(ua)` and sets `knock['http_bot_name']` / `knock['http_bot_type']` when a bot is identified.

**Why here:** Both pieces of logic operate on raw knock fields (`http_user_agent`, `http_path`, `http_method`, `http_body`) that are available before geo enrichment. More importantly, setting them here means they're present in the knock dict when `_db_write_queue.put(package.copy())` fires — so `http_bot_name` and `http_bot_type` land in the per-knock table (`knocks_http`, or `knocks_http_site` for `HTTP+`).

### `get_geo_enriched()` — ASN type lookup

**Runs:** After `process_knock`, as part of the main monitor loop's geo enrichment step.

**Handles:** `asn_type = _ASN_TYPES.get(asn_int, 'unknown')` — the ASN integer is already returned by GeoLite2-ASN, so this is a natural extension of the existing enrichment function. The result flows into the `package` dict automatically and is included in the DB write and broadcast with no further hook needed.

**Why here (not in `process_knock` or `after_save`):** ASN type is derived from a GeoLite2 lookup, so it belongs in the same geo enrichment step rather than a protocol hook. Placing it in `get_geo_enriched()` means all protocols (not just HTTP) get `asn_type` for free, and the `isp_intel.asn_type` column write in `log_to_enriched_db()` is a simple extension of the existing upsert.

### `after_save` hook — `display_format` override for bot knocks

**Runs:** After the DB snapshot is queued, before Redis/WebSocket broadcast.

**Handles:** If `http_bot_name` is set in the package, overrides `display_format` to `"bot"` so the live feed renders the bot-specific row layout instead of the default exploit layout.

**Why here (not `process_knock`):** `display_format` is a broadcast-only field — it doesn't belong in the knock table. The existing `after_save` hook already sets `display_format` from `http_purpose`; the bot override is a natural addition to that same hook. The hook can safely read `package['http_bot_name']` since `process_knock` already set it.

### `db_update` hook — `isp_intel.asn_type` write (alternative approach)

If `asn_type` is added to `get_geo_enriched()` (preferred), the `log_to_enriched_db()` upsert in `monitor.py` is updated directly — no hook needed. The `db_update` hook (runs inside `log_to_enriched_db()` with an open cursor mid-transaction) is an alternative if the write needs to be protocol-specific or deferred to a protocol extension. For Phase 1, direct modification of `log_to_enriched_db()` is simpler.

---

## File Change Summary

| File | Change |
|------|--------|
| `extras/update-asn-types.py` | New: ASN type database download/refresh script |
| `extras/nginx-adapter/knock_adapter.py` | New: log tail → INGEST_PORT adapter |
| `extras/nginx-adapter/nginx-log-format.conf` | New: example nginx config snippet |
| `monitor.py` | `_load_asn_types()`, extend `get_geo_enriched()`, DB migration for `isp_intel.asn_type`, include `asn_type` in package |
| `protocols/http.py` | Add `process_knock` hook (classification + bot detection), `_detect_bot()`, `"bot"` display format, two new Columns |
| `main.py` | Include `asn_type` in `top_providers` query and broadcast |
| `index.html` | `[DC]`/`[ISP]` badge on ISP leaderboard rows |
| `requirements.txt` | Add `device-detector` |

---

## Verification

1. **ASN type lookup**: Run `extras/update-asn-types.py`, confirm `data/asn_types.json` written. Start monitor, confirm `asn_type` field appears in Redis knock JSON (`redis-cli lrange knock:recent 0 0`).
2. **Bot detection**: Send a test HTTP knock with UA `"Googlebot/2.1"` via netcat to INGEST_PORT; confirm knock arrives in Redis with `http_bot_name: "Googlebot"` and `display_format: "bot"`.
3. **HTTP classification via hook**: Send a test knock with no `http_purpose` and `http_path: "/wp-login.php"` to INGEST_PORT; confirm `http_purpose: "credential_theft"` is set in the published package.
4. **nginx adapter**: Configure nginx with `knock_json` log format, start `knock_adapter.py`, make a test request; confirm it appears in the dashboard feed with correct geo and classification.
5. **ISP leaderboard badge**: Confirm `[DC]` badge renders for a known hosting ASN in the top providers list.
6. **Regression**: Run `python3 extras/tests/http/test_http_classifier.py` — must still pass 236/236.

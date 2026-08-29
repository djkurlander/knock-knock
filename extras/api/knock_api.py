#!/usr/bin/env python3
"""knock-api — public query API for the knock-knock attack database.

Standalone FastAPI service (default port 8081, fronted by api.knock-knock.net).
Lets an organization check its own address space against the honeypot's
observed-attacker data — a listed IP means a device in their network has been
caught attacking this honeypot:

  GET /check-ranges?ranges=198.51.100.0/24,203.0.113.0/22&list=year
  GET /check-asn?asn=12345&list=year
  GET /ip/198.51.100.45

Membership checks run against an in-memory snapshot rebuilt hourly from
ip_intel in one DB pass; only confirmed hits touch the database again (one
IN(...) query for metadata). Redis holds rate-limit state and health metrics.
See API_DESIGN.md for the full design.
"""
import asyncio
import bisect
import ipaddress
import os
import sqlite3
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import geoip2.database
import geoip2.errors
import redis.asyncio as aioredis
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from constants import PROTO_NAME  # noqa: E402

KNOCK_DB = ROOT / os.environ.get('DB_DIR', 'data') / 'knock_knock.db'
VISITORS_DB = ROOT / os.environ.get('DB_DIR', 'data') / 'visitors.db'
GEOIP_CITY = '/usr/share/GeoIP/GeoLite2-City.mmdb'
GEOIP_ASN = '/usr/share/GeoIP/GeoLite2-ASN.mmdb'

API_PORT = int(os.environ.get('KNOCK_API_PORT', '8081'))
API_LISTEN = os.environ.get('KNOCK_API_LISTEN', '0.0.0.0')
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_DB = int(os.environ.get('REDIS_DB', '0'))
LOG_VISITORS = os.environ.get('LOG_VISITORS', '').lower() == 'true'
TRUST_PROXY_HEADERS = os.environ.get('TRUST_PROXY_HEADERS', 'true').lower() not in ('0', 'false', 'no')

WINDOWS = {'year': 365, 'month': 30}
MAX_RANGES = 10          # CIDRs per check-ranges request
MIN_PREFIXLEN = 16       # largest range accepted (a /16)
MAX_HITS = 25000         # detail rows returned before truncation (safety ceiling only;
                         # far above any real ASN/range — total_matched is always exact)
# --- Rate limits -----------------------------------------------------------
# TWO currencies, checked together in one Redis round trip (see guard()):
#   calls  — every request weighs 1, covering the fixed per-request work
#   ips    — a request weighs the number of IPs it returns, which is what
#            actually drives database work (measured: ~1.4 ms fixed + ~0.065 ms
#            per IP returned; the median ASN returns 2 IPs, the largest 8,478).
# A flat per-request limit cannot work here: the heaviest call is ~200x the
# median, so any single number either strangles ordinary use or licenses an
# absurd worst case. The old per-endpoint caps did the former — a legitimate
# ISP audit returning ZERO hits was capped at 20/hour and took a week.
API_CALLS_PER_MIN = int(os.environ.get('API_CALLS_PER_MIN', '60'))
API_CALLS_PER_HOUR = int(os.environ.get('API_CALLS_PER_HOUR', '1000'))
API_CALLS_PER_DAY = int(os.environ.get('API_CALLS_PER_DAY', '5000'))
API_IPS_PER_HOUR = int(os.environ.get('API_IPS_PER_HOUR', '20000'))
API_IPS_PER_DAY = int(os.environ.get('API_IPS_PER_DAY', '100000'))
# Global ceiling across ALL clients, in the same IP currency. Queues rather than
# rejecting: aggregate contention is transient, so waiting usually succeeds.
API_GLOBAL_IPS_PER_MIN = int(os.environ.get('API_GLOBAL_IPS_PER_MIN', '50000'))
API_GLOBAL_WAIT_MAX = int(os.environ.get('API_GLOBAL_WAIT_MAX', '25'))

app = FastAPI(title='knock-api', docs_url=None, redoc_url=None)
# Let the docs page's "Run" widget call the API from the main site (cross-origin).
# Public read-only data, simple GETs — no credentials, no preflight needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=['https://knock-knock.net', 'https://api.knock-knock.net'],
    allow_methods=['GET'],
    allow_headers=['*'],
)
R: aioredis.Redis = None
city_reader = asn_reader = None


# --- In-memory snapshot (rebuilt hourly, one DB pass) -----------------------

class Snapshot:
    """Sorted-int IP membership for one time window, plus a per-ASN index."""
    __slots__ = ('ips', 'ip_strs', 'asn_map', 'generated_at')

    def __init__(self):
        self.ips = []            # sorted list[int]
        self.ip_strs = {}        # int -> original string (avoids re-formatting)
        self.asn_map = {}        # asn -> sorted list[int]
        self.generated_at = None


snapshots: dict[str, Snapshot] = {}


def ro_conn(path):
    return sqlite3.connect(f'file:{path}?mode=ro', uri=True)


def build_snapshots():
    """One pass over ip_intel builds both windows; ASN comes from GeoLite2."""
    cutoffs = {w: (datetime.now() - timedelta(days=d)).strftime('%Y-%m-%d %H:%M:%S')
               for w, d in WINDOWS.items()}
    fresh = {w: Snapshot() for w in WINDOWS}
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with ro_conn(KNOCK_DB) as conn:
        rows = conn.execute(
            'SELECT ip, last_seen, asn FROM ip_intel WHERE last_seen >= ?',
            (cutoffs['year'],)).fetchall()
    for ip, last_seen, asn in rows:
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError):
            continue
        if asn is None and asn_reader:
            # rows not re-observed since the asn column was added
            try:
                asn = asn_reader.asn(ip).autonomous_system_number
            except geoip2.errors.AddressNotFoundError:
                pass
        for w, snap in fresh.items():
            if last_seen >= cutoffs[w]:
                snap.ips.append(ip_int)
                snap.ip_strs[ip_int] = ip
                if asn is not None:
                    snap.asn_map.setdefault(asn, []).append(ip_int)
    for snap in fresh.values():
        snap.ips.sort()
        for lst in snap.asn_map.values():
            lst.sort()
        snap.generated_at = now
    return fresh


async def refresher():
    global snapshots
    while True:
        await asyncio.sleep(3600)
        try:
            snapshots = await asyncio.to_thread(build_snapshots)
        except Exception as e:
            print(f'snapshot refresh failed: {e}', file=sys.stderr)


# --- Rate limiting (Redis fixed windows; count only admitted requests) ------
# All windows are checked and committed in ONE Lua call, atomically. Two reasons:
#   1. Correctness. Taking them sequentially means a request refused by the LAST
#      window has already consumed the earlier ones — which is what the old
#      guard() did, silently burning daily allowance on requests it rejected and
#      contradicting the published "a rejected request never counts" promise.
#   2. Speed. Five windows sequentially is ~2.8 ms of round trips to protect a
#      ~1.4 ms request; one EVALSHA is ~0.6 ms.
# Weight is exact and known BEFORE any database work: both check-ranges and
# check-asn compute their hit count from the in-memory snapshot first, so a
# rejected request costs nothing at all.
_LIMITER_LUA = """
-- KEYS = window keys;  ARGV = flattened triples of (cap, ttl, weight)
local n = #KEYS
for i = 1, n do
  local cap    = tonumber(ARGV[(i-1)*3 + 1])
  local weight = tonumber(ARGV[(i-1)*3 + 3])
  if weight > cap then
    return {i, -1}                      -- can never succeed; do not tell them to retry
  end
  local cur = tonumber(redis.call('GET', KEYS[i])) or 0
  if cur + weight > cap then
    local ttl = redis.call('TTL', KEYS[i])
    return {i, ttl < 0 and tonumber(ARGV[(i-1)*3 + 2]) or ttl}
  end
end
for i = 1, n do                         -- every window passed: commit
  local ttl    = tonumber(ARGV[(i-1)*3 + 2])
  local weight = tonumber(ARGV[(i-1)*3 + 3])
  if redis.call('INCRBY', KEYS[i], weight) == weight then
    redis.call('EXPIRE', KEYS[i], ttl)
  end
end
return {0, 0}
"""
_limiter_sha = None

# (name, ttl, cap, currency) — order fixes the index the Lua script reports back.
def _windows(ip):
    return (('calls_per_min',  f'knock:api:rl:cmin:{ip}',   60, API_CALLS_PER_MIN,  'calls'),
            ('calls_per_hour', f'knock:api:rl:chour:{ip}', 3600, API_CALLS_PER_HOUR, 'calls'),
            ('calls_per_day',  f'knock:api:rl:cday:{ip}', 86400, API_CALLS_PER_DAY,  'calls'),
            ('ips_per_hour',   f'knock:api:rl:ihour:{ip}', 3600, API_IPS_PER_HOUR,   'ips'),
            ('ips_per_day',    f'knock:api:rl:iday:{ip}', 86400, API_IPS_PER_DAY,    'ips'))


async def _eval_limiter(keys, argv):
    """EVALSHA with a NOSCRIPT fallback (Redis restarts drop the script cache)."""
    global _limiter_sha
    try:
        if _limiter_sha is None:
            _limiter_sha = await R.script_load(_LIMITER_LUA)
        return await R.evalsha(_limiter_sha, len(keys), *keys, *argv)
    except aioredis.ResponseError as e:
        if 'NOSCRIPT' not in str(e).upper():
            raise
        _limiter_sha = await R.script_load(_LIMITER_LUA)
        return await R.evalsha(_limiter_sha, len(keys), *keys, *argv)


def _429(limit_name, retry_after, endpoint=None):
    detail = {'error': 'rate_limited', 'limit': limit_name,
              'retry_after_seconds': max(int(retry_after), 1)}
    if endpoint == 'check-ranges':
        detail['hint'] = 'batch up to %d CIDRs per check-ranges request' % MAX_RANGES
    return HTTPException(429, detail=detail,
                         headers={'Retry-After': str(max(int(retry_after), 1))})


def _413(limit_name, weight, cap, endpoint):
    """A single request bigger than the whole window. Retrying can never help, so
    say so instead of handing back a Retry-After that invites an infinite loop."""
    detail = {'error': 'request_too_large', 'limit': limit_name,
              'ips_requested': weight, 'limit_value': cap,
              'message': 'this single request returns more IPs than the %s limit allows; '
                         'split it into smaller queries' % limit_name}
    if endpoint == 'check-ranges':
        detail['hint'] = 'use fewer or smaller CIDRs per request'
    return HTTPException(413, detail=detail)


async def guard(ip, endpoint, ips=0):
    """Admit or reject in one atomic Redis call. `ips` is the number of IPs the
    response will return — known from the in-memory snapshot before any DB work."""
    wins = _windows(ip)
    keys, argv = [], []
    for _name, key, ttl, cap, currency in wins:
        keys.append(key)
        argv += [cap, ttl, 1 if currency == 'calls' else ips]
    idx, retry = await _eval_limiter(keys, argv)
    if idx:
        name, _key, _ttl, cap, currency = wins[int(idx) - 1]
        await R.incr('knock:api:rate_limited:count')
        if int(retry) < 0:
            raise _413(name, ips, cap, endpoint)
        raise _429(name, retry, endpoint)


async def take_global_token(ips):
    """Global budget across all clients; waits (rather than rejecting) up to
    API_GLOBAL_WAIT_MAX seconds. Aggregate contention is transient — unlike a
    client's own exhausted window, which no amount of waiting will clear."""
    if ips <= 0:
        return
    deadline = time.monotonic() + API_GLOBAL_WAIT_MAX
    while True:
        idx, retry = await _eval_limiter(
            ['knock:api:rl:global_min'], [API_GLOBAL_IPS_PER_MIN, 60, ips])
        if not idx:
            return
        if int(retry) < 0 or time.monotonic() + 1 >= deadline:
            await R.incr('knock:api:rate_limited:count')
            raise _429('global_ips_per_min', max(int(retry), 1))
        await asyncio.sleep(1)


# --- Request helpers --------------------------------------------------------

def client_ip(request: Request):
    if TRUST_PROXY_HEADERS:
        ip = request.headers.get('cf-connecting-ip')
        if ip:
            return ip.strip()
        xff = request.headers.get('x-forwarded-for')
        if xff:
            return xff.split(',')[0].strip()
    return request.client.host if request.client else '?'


# --- Access log (real client IP, not the Cloudflare edge) -------------------
# uvicorn's built-in access log prints request.client.host, which behind Cloudflare
# is the CF *edge* IP — useless for per-client attribution. We disable it
# (access_log=False in uvicorn.run) and log here with the same CF-Connecting-IP-aware
# client_ip() the visitor logging uses, so the journal and visitors.db agree on the
# real client. Includes the query string (which the built-in log also drops from view).
ACCESS_LOG = os.environ.get('API_ACCESS_LOG', 'true').lower() not in ('0', 'false', 'no')


@app.middleware('http')
async def access_log_middleware(request: Request, call_next):
    response = await call_next(request)
    if ACCESS_LOG:
        try:
            q = request.url.query
            path = request.url.path + (f'?{q}' if q else '')
            print(f'{client_ip(request)} - "{request.method} {path} '
                  f'HTTP/{request.scope.get("http_version", "1.1")}" {response.status_code}',
                  flush=True)
        except Exception as e:  # never let logging break a request
            print(f'access-log failed: {e}', file=sys.stderr)
    return response


def init_visitors_db():
    """Same append-only visitor_events DDL as main.py — a no-op when the dashboard
    has already created it. The legacy daily-rollup `visitors` table is left untouched."""
    with sqlite3.connect(VISITORS_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS visitor_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            ip TEXT NOT NULL, page TEXT NOT NULL DEFAULT '/', query_string TEXT,
            method TEXT, status_code INTEGER,
            city TEXT, region TEXT, country TEXT, iso_code TEXT, isp TEXT, asn INTEGER,
            referrer TEXT, user_agent TEXT)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ve_ip_ts ON visitor_events(ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ve_page_ts ON visitor_events(page, timestamp)")
        conn.execute('PRAGMA journal_mode=WAL')


def log_visitor(ip, user_agent, page, query_string, referrer=None,
                method=None, status_code=None):
    """Append one raw request event to visitor_events (same table main.py writes; no dedup)."""
    geo = {'city': None, 'region': None, 'country': None, 'iso': None,
           'isp': None, 'asn': None}
    try:
        if city_reader:
            c = city_reader.city(ip)
            geo.update(city=c.city.name, country=c.country.name, iso=c.country.iso_code,
                       region=c.subdivisions[0].name if c.subdivisions else None)
        if asn_reader:
            a = asn_reader.asn(ip)
            geo.update(isp=a.autonomous_system_organization, asn=a.autonomous_system_number)
    except Exception:
        pass
    try:
        with sqlite3.connect(VISITORS_DB) as conn:
            conn.execute("""
                INSERT INTO visitor_events (timestamp, ip, page, query_string, method, status_code,
                                            city, region, country, iso_code, isp, asn, referrer, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (int(time.time()), ip, page, query_string, method, status_code,
                  geo['city'], geo['region'], geo['country'], geo['iso'],
                  geo['isp'], geo['asn'], referrer, user_agent))
    except sqlite3.Error as e:
        print(f'visitor log failed: {e}', file=sys.stderr)


async def _record(user_agent, ip, endpoint, query, ms, referer=None, method=None):
    try:
        async with R.pipeline(transaction=False) as pipe:
            pipe.incr(f'knock:api:{endpoint}:count')
            pipe.set(f'knock:api:{endpoint}:ms_last', f'{ms:.1f}')
            await pipe.execute()
        prev = await R.get(f'knock:api:{endpoint}:ms_max')
        if prev is None or ms > float(prev):
            await R.set(f'knock:api:{endpoint}:ms_max', f'{ms:.1f}')
        if LOG_VISITORS:
            # record() only runs after a successful endpoint (errors raise first) → status 200.
            await asyncio.to_thread(log_visitor, ip, user_agent, f'/{endpoint}', query, referer, method, 200)
    except Exception as e:
        print(f'record failed: {e}', file=sys.stderr)


def record(request, ip, endpoint, started, query=None):
    """Metrics + visitor logging — fire-and-forget, off the response path."""
    ms = (time.monotonic() - started) * 1000
    asyncio.get_running_loop().create_task(
        _record(request.headers.get('user-agent'), ip, endpoint,
                query or request.url.query or None, ms,
                request.headers.get('referer'), request.method))


# --- Hit metadata (the only per-request DB work) ----------------------------

def fetch_meta(ips: list[str]):
    """hits + last_seen + per-protocol breakdown for confirmed hits, in one pass."""
    meta = {ip: {'ip': ip, 'hits': 0, 'first_seen': None, 'last_seen': None,
                 'protocols': []} for ip in ips}
    with ro_conn(KNOCK_DB) as conn:
        for chunk in (ips[i:i + 900] for i in range(0, len(ips), 900)):
            marks = ','.join('?' * len(chunk))
            for ip, hits, first, last in conn.execute(
                    f'SELECT ip, hits, first_seen, last_seen FROM ip_intel WHERE ip IN ({marks})', chunk):
                meta[ip].update(hits=hits, first_seen=first, last_seen=last)
            for ip, proto, hits, last in conn.execute(
                    f'SELECT ip, proto, hits, last_seen FROM ip_intel_proto '
                    f'WHERE ip IN ({marks}) ORDER BY hits DESC', chunk):
                meta[ip]['protocols'].append(
                    {'proto': PROTO_NAME.get(proto, str(proto)), 'hits': hits, 'last_seen': last})
    return [meta[ip] for ip in ips]


def get_snapshot(window):
    if window not in WINDOWS:
        raise HTTPException(400, detail={'error': f"list must be one of {list(WINDOWS)}"})
    return snapshots[window]


# --- Endpoints --------------------------------------------------------------

@app.get('/', include_in_schema=False)
@app.head('/', include_in_schema=False)
async def index(request: Request):
    """Human-facing docs at the API root — the same page served at
    knock-knock.net/api, so browsing the bare API domain isn't a dead end.
    Logged as '/api' (not '/') so landing hits register distinctly from the
    main dashboard homepage and roll up with knock-knock.net/api."""
    if LOG_VISITORS:
        # Fire-and-forget, off the response path (matches record()/_record()). Always a 200 here.
        asyncio.get_running_loop().create_task(asyncio.to_thread(
            log_visitor, client_ip(request), request.headers.get('user-agent'),
            '/api', request.url.query or None, request.headers.get('referer'),
            request.method, 200))
    from fastapi.responses import HTMLResponse
    try:
        return HTMLResponse((ROOT / 'api.html').read_text())
    except OSError:
        return HTMLResponse('<h1>knock-api</h1><p>See '
                            '<a href="https://knock-knock.net/api">knock-knock.net/api</a></p>')


@app.get('/check-ranges')
async def check_ranges(request: Request, ranges: str,
                       window: str = Query('year', alias='list')):
    ip, started = client_ip(request), time.monotonic()
    # Validation runs before the limiter so the weight can be exact, but a malformed
    # request must still weigh one call — otherwise garbage is the one unmetered path.
    try:
        snap = get_snapshot(window)
        nets = []
        for part in ranges.split(','):
            try:
                net = ipaddress.ip_network(part.strip(), strict=False)
            except ValueError:
                raise HTTPException(400, detail={'error': f'invalid CIDR: {part.strip()!r}'})
            if net.version != 4:
                raise HTTPException(400, detail={'error': 'IPv4 ranges only'})
            if net.prefixlen < MIN_PREFIXLEN:
                raise HTTPException(400, detail={'error':
                    f'{net} too large — /{MIN_PREFIXLEN} maximum ({2**(32-MIN_PREFIXLEN):,} IPs)'})
            nets.append(net)
        if not 1 <= len(nets) <= MAX_RANGES:
            raise HTTPException(400, detail={'error': f'1-{MAX_RANGES} ranges per request'})
    except HTTPException:
        await guard(ip, 'check-ranges', 0)
        raise

    # Walk the full match set for an exact count (cheap — bounded by blocklist size),
    # but only materialize the first MAX_HITS for the metadata fetch / response body.
    hit_ints, total_matched = [], 0
    for net in nets:
        lo, hi = int(net[0]), int(net[-1])
        i = bisect.bisect_left(snap.ips, lo)
        while i < len(snap.ips) and snap.ips[i] <= hi:
            total_matched += 1
            if len(hit_ints) < MAX_HITS:
                hit_ints.append(snap.ips[i])
            i += 1
    hit_ips = [snap.ip_strs[n] for n in hit_ints]

    # Weight is exact here and no DB work has happened yet, so a rejection is free.
    await guard(ip, 'check-ranges', len(hit_ips))
    await take_global_token(len(hit_ips))
    hits = await asyncio.to_thread(fetch_meta, hit_ips) if hit_ips else []
    record(request, ip, 'check-ranges', started)
    return {'list': window, 'generated_at': snap.generated_at,
            'ranges_checked': [str(n) for n in nets],
            'total_ips_checked': sum(n.num_addresses for n in nets),
            'hit_count': len(hits), 'total_matched': total_matched,
            'truncated': total_matched > len(hits),
            'hits': hits}   # long array last, so the summary reads first


@app.get('/check-asn')
async def check_asn(request: Request, asn: int,
                    window: str = Query('year', alias='list')):
    ip, started = client_ip(request), time.monotonic()
    try:
        snap = get_snapshot(window)
    except HTTPException:
        await guard(ip, 'check-asn', 0)
        raise

    members = snap.asn_map.get(asn, [])
    total_matched = len(members)          # exact and free from the in-memory index
    hit_ips = [snap.ip_strs[n] for n in members[:MAX_HITS]]
    await guard(ip, 'check-asn', len(hit_ips))
    await take_global_token(len(hit_ips))
    org = None
    if hit_ips and asn_reader:
        try:
            org = asn_reader.asn(hit_ips[0]).autonomous_system_organization
        except Exception:
            pass

    hits = await asyncio.to_thread(fetch_meta, hit_ips) if hit_ips else []
    record(request, ip, 'check-asn', started)
    return {'list': window, 'generated_at': snap.generated_at, 'asn': asn, 'isp': org,
            'hit_count': len(hits), 'total_matched': total_matched,
            'truncated': total_matched > len(hits),
            'hits': hits}   # long array last, so the summary reads first


@app.get('/ip/{target}')
async def ip_detail(request: Request, target: str):
    ip, started = client_ip(request), time.monotonic()
    try:
        target = str(ipaddress.IPv4Address(target.strip()))
    except (ipaddress.AddressValueError, ValueError):
        await guard(ip, 'ip', 0)
        raise HTTPException(400, detail={'error': f'invalid IPv4 address: {target!r}'})
    await guard(ip, 'ip', 1)              # one address in, one record out
    await take_global_token(1)

    def lookup():
        with ro_conn(KNOCK_DB) as conn:
            row = conn.execute(
                'SELECT hits, first_seen, last_seen, ban_until, asn FROM ip_intel WHERE ip=?',
                (target,)).fetchone()
            if row is None:
                return None
            protos = [{'proto': PROTO_NAME.get(p, str(p)), 'hits': h, 'last_seen': ls}
                      for p, h, ls in conn.execute(
                          'SELECT proto, hits, last_seen FROM ip_intel_proto '
                          'WHERE ip=? ORDER BY hits DESC', (target,))]
        return row, protos

    result = await asyncio.to_thread(lookup)
    record(request, ip, 'ip', started, query=target)
    if result is None:
        return {'ip': target, 'listed': False}

    (hits, first_seen, last_seen, ban_until, asn), protocols = result
    country = isp = None
    try:
        if city_reader:
            country = city_reader.city(target).country.name
        if asn_reader:
            a = asn_reader.asn(target)
            isp = a.autonomous_system_organization
            asn = asn or a.autonomous_system_number   # stored (observed) ASN wins
    except Exception:
        pass
    banned = ban_until is not None and (ban_until == 0 or ban_until > time.time())
    return {'ip': target, 'listed': True, 'hits': hits,
            'first_seen': first_seen, 'last_seen': last_seen,
            'country': country, 'isp': isp, 'asn': asn, 'banned': banned,
            'ban_until': ('permanent' if ban_until == 0 else
                          datetime.fromtimestamp(ban_until, timezone.utc)
                          .strftime('%Y-%m-%dT%H:%M:%SZ')) if banned else None,
            'protocols': protocols}


@app.exception_handler(HTTPException)
async def http_exc(request, exc):
    body = exc.detail if isinstance(exc.detail, dict) else {'error': exc.detail}
    return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)


# --- Lifecycle --------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    global R, city_reader, asn_reader, snapshots
    R = aioredis.Redis(host=REDIS_HOST, db=REDIS_DB, decode_responses=True)
    city_reader = geoip2.database.Reader(GEOIP_CITY) if os.path.exists(GEOIP_CITY) else None
    asn_reader = geoip2.database.Reader(GEOIP_ASN) if os.path.exists(GEOIP_ASN) else None
    if LOG_VISITORS:
        init_visitors_db()
    snapshots = await asyncio.to_thread(build_snapshots)
    print(f'knock-api ready: {len(snapshots["year"].ips)} IPs (year), '
          f'{len(snapshots["month"].ips)} (month), '
          f'{len(snapshots["year"].asn_map)} ASNs', file=sys.stderr)
    task = asyncio.create_task(refresher())
    yield
    task.cancel()
    await R.aclose()

app.router.lifespan_context = lifespan


if __name__ == '__main__':
    # Serve HTTPS with the same Origin CA cert main.py uses, so a Full (strict)
    # Cloudflare zone reaches this origin exactly like the web server on 8080.
    ssl_args = {}
    if os.environ.get('ENABLE_SSL', '').lower() == 'true':
        ssl_args = {'ssl_keyfile': os.environ.get('KNOCK_KEYFILE', 'certs/key.pem'),
                    'ssl_certfile': os.environ.get('KNOCK_CERTFILE', 'certs/cert.pem')}
    # access_log=False: our access_log_middleware logs the real CF-Connecting-IP client
    # (uvicorn's built-in would log the Cloudflare edge IP). proxy_headers stays off since
    # client_ip() handles CF-Connecting-IP/XFF itself.
    uvicorn.run(app, host=API_LISTEN, port=API_PORT, proxy_headers=False, access_log=False, **ssl_args)

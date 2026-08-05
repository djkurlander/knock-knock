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
DAY_CAP = 500            # per-IP requests/day, all endpoints (backstop against abuse)
CHECK_CAP = 20           # per-IP check-ranges / check-asn requests/hour
IP_MIN_CAP = 30          # per-IP /ip lookups/minute
GLOBAL_MIN_CAP = 300     # global /ip lookups/minute (token bucket)
WAIT_MAX = 25            # seconds a /ip request will wait for a global token

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

def _429(retry_after):
    return HTTPException(429, detail={'error': 'rate_limited',
                                      'retry_after_seconds': max(int(retry_after), 1)},
                         headers={'Retry-After': str(max(int(retry_after), 1))})


async def _take(key, ttl, cap):
    """Consume one slot; return None if admitted, else seconds until reset."""
    n = await R.incr(key)
    if n == 1:
        await R.expire(key, ttl)
    if n > cap:
        await R.decr(key)
        return await R.ttl(key)
    return None


async def guard(ip, endpoint):
    """Daily cap + per-endpoint per-IP limit. Raises 429 when over."""
    checks = [(f'knock:api:rl:day:{ip}', 86400, DAY_CAP)]
    if endpoint == 'ip':
        checks.append((f'knock:api:rl:ip:{ip}', 60, IP_MIN_CAP))
    else:
        checks.append((f'knock:api:rl:{endpoint}:{ip}', 3600, CHECK_CAP))
    for key, ttl, cap in checks:
        retry = await _take(key, ttl, cap)
        if retry is not None:
            await R.incr('knock:api:rate_limited:count')
            raise _429(retry)


async def take_global_token():
    """Global /ip budget; waits (rather than rejecting) up to WAIT_MAX seconds."""
    deadline = time.monotonic() + WAIT_MAX
    while True:
        retry = await _take('knock:api:rl:global_min', 60, GLOBAL_MIN_CAP)
        if retry is None:
            return
        if time.monotonic() + 1 >= deadline:
            await R.incr('knock:api:rate_limited:count')
            raise _429(retry)
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


def init_visitors_db():
    """Same DDL as main.py — a no-op when the dashboard has already created it."""
    with sqlite3.connect(VISITORS_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS visitors (
            ip TEXT NOT NULL, date TEXT NOT NULL, page TEXT NOT NULL DEFAULT '/',
            city TEXT, region TEXT, country TEXT, iso_code TEXT, isp TEXT, asn INTEGER,
            referrer TEXT, query_string TEXT, user_agent TEXT,
            visit_count INTEGER NOT NULL DEFAULT 1,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ip, date, page))""")
        conn.execute('PRAGMA journal_mode=WAL')


def log_visitor(ip, user_agent, page, query_string, referrer=None):
    """Same visitors table main.py writes — one row per IP per day per page."""
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
                INSERT INTO visitors (ip, date, page, city, region, country, iso_code,
                                      isp, asn, referrer, query_string, user_agent)
                VALUES (?, date('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, date, page) DO UPDATE SET
                    visit_count = visit_count + 1,
                    last_seen = CURRENT_TIMESTAMP,
                    referrer = COALESCE(NULLIF(visitors.referrer, ''), excluded.referrer),
                    query_string = COALESCE(NULLIF(visitors.query_string, ''), excluded.query_string),
                    user_agent = COALESCE(NULLIF(visitors.user_agent, ''), excluded.user_agent)
            """, (ip, page, geo['city'], geo['region'], geo['country'], geo['iso'],
                  geo['isp'], geo['asn'], referrer, query_string, user_agent))
    except sqlite3.Error as e:
        print(f'visitor log failed: {e}', file=sys.stderr)


async def _record(user_agent, ip, endpoint, query, ms, referer=None):
    try:
        async with R.pipeline(transaction=False) as pipe:
            pipe.incr(f'knock:api:{endpoint}:count')
            pipe.set(f'knock:api:{endpoint}:ms_last', f'{ms:.1f}')
            await pipe.execute()
        prev = await R.get(f'knock:api:{endpoint}:ms_max')
        if prev is None or ms > float(prev):
            await R.set(f'knock:api:{endpoint}:ms_max', f'{ms:.1f}')
        if LOG_VISITORS:
            await asyncio.to_thread(log_visitor, ip, user_agent, f'/{endpoint}', query, referer)
    except Exception as e:
        print(f'record failed: {e}', file=sys.stderr)


def record(request, ip, endpoint, started, query=None):
    """Metrics + visitor logging — fire-and-forget, off the response path."""
    ms = (time.monotonic() - started) * 1000
    asyncio.get_running_loop().create_task(
        _record(request.headers.get('user-agent'), ip, endpoint,
                query or request.url.query or None, ms,
                request.headers.get('referer')))


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
async def index():
    """Human-facing docs at the API root — the same page served at
    knock-knock.net/api, so browsing the bare API domain isn't a dead end."""
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
    await guard(ip, 'check-ranges')
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
    await guard(ip, 'check-asn')
    snap = get_snapshot(window)

    members = snap.asn_map.get(asn, [])
    total_matched = len(members)          # exact and free from the in-memory index
    hit_ips = [snap.ip_strs[n] for n in members[:MAX_HITS]]
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
    await guard(ip, 'ip')
    try:
        target = str(ipaddress.IPv4Address(target.strip()))
    except (ipaddress.AddressValueError, ValueError):
        raise HTTPException(400, detail={'error': f'invalid IPv4 address: {target!r}'})
    await take_global_token()

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
    uvicorn.run(app, host=API_LISTEN, port=API_PORT, proxy_headers=False, **ssl_args)

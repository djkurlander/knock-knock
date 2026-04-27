import asyncio, json, logging, sqlite3, os, time, uvicorn
from contextlib import asynccontextmanager
import redis.asyncio as redis
import geoip2.database
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from datetime import datetime
from fastapi.staticfiles import StaticFiles
from constants import PROTO, PROTO_NAME, PROTOCOL_META, DEFAULT_ENABLED_PROTOCOLS, sort_protocols_for_ui

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Knock-Knock Web Active...", flush=True)
    asyncio.create_task(redis_listener())
    asyncio.create_task(stats_cache.update_and_broadcast())
    yield

app = FastAPI(lifespan=lifespan)
logger = logging.getLogger("uvicorn.error")
LOG_UNHANDLED_HTTP = os.environ.get('LOG_UNHANDLED_HTTP', '').lower() == 'true'

def get_request_client_ip(request: Request) -> str:
    """Extract real client IP: CF-Connecting-IP > X-Forwarded-For > direct."""
    cf_ip = request.headers.get('cf-connecting-ip')
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get('x-forwarded-for')
    if xff:
        return xff.split(',')[0].strip()
    return request.client.host if request.client else None

def get_client_ip(websocket: WebSocket) -> str:
    """Extract real client IP: CF-Connecting-IP > X-Forwarded-For > direct."""
    cf_ip = websocket.headers.get('cf-connecting-ip')
    if cf_ip:
        return cf_ip.strip()
    xff = websocket.headers.get('x-forwarded-for')
    if xff:
        return xff.split(',')[0].strip()
    return websocket.client.host if websocket.client else None

@app.middleware("http")
async def log_unhandled_http_requests(request: Request, call_next):
    response = await call_next(request)
    if LOG_UNHANDLED_HTTP and response.status_code == 404:
        logger.warning(
            "Unhandled HTTP request: ip=%s method=%s url=%s host=%s user_agent=%s",
            get_request_client_ip(request),
            request.method,
            str(request.url),
            request.headers.get('host', ''),
            request.headers.get('user-agent', ''),
        )
    return response

# --- Visitor Logging (opt-in via LOG_VISITORS=true) ---
LOG_VISITORS = os.environ.get('LOG_VISITORS', '').lower() == 'true'

if LOG_VISITORS:
    VISITORS_DB_PATH = os.environ.get('DB_DIR', 'data') + '/visitors.db'
    GEOIP_CITY_PATH = '/usr/share/GeoIP/GeoLite2-City.mmdb'
    GEOIP_ASN_PATH = '/usr/share/GeoIP/GeoLite2-ASN.mmdb'

    visitor_city_reader = geoip2.database.Reader(GEOIP_CITY_PATH) if os.path.exists(GEOIP_CITY_PATH) else None
    visitor_asn_reader = geoip2.database.Reader(GEOIP_ASN_PATH) if os.path.exists(GEOIP_ASN_PATH) else None

    def init_visitors_db():
        conn = sqlite3.connect(VISITORS_DB_PATH, timeout=10)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            city TEXT,
            region TEXT,
            country TEXT,
            iso_code TEXT,
            isp TEXT,
            asn INTEGER,
            referrer TEXT,
            user_agent TEXT
        )""")
        conn.commit()
        conn.close()

    def get_visitor_geo(ip):
        geo = {"city": None, "region": None, "country": None, "iso": None, "isp": None, "asn": None}
        try:
            if visitor_city_reader:
                c_res = visitor_city_reader.city(ip)
                geo["iso"] = c_res.country.iso_code
                geo["country"] = c_res.country.name
                geo["city"] = c_res.city.name
                if c_res.subdivisions.most_specific.name:
                    geo["region"] = c_res.subdivisions.most_specific.name
            if visitor_asn_reader:
                a_res = visitor_asn_reader.asn(ip)
                geo["isp"] = a_res.autonomous_system_organization
                geo["asn"] = a_res.autonomous_system_number
        except:
            pass
        return geo

    def log_visitor(ip, referrer=None, user_agent=None):
        """Log a visitor to the separate visitors database."""
        try:
            geo = get_visitor_geo(ip)
            conn = sqlite3.connect(VISITORS_DB_PATH, timeout=10)
            cur = conn.cursor()
            cur.execute("""INSERT INTO visitors (ip, city, region, country, iso_code, isp, asn, referrer, user_agent)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (ip, geo['city'], geo['region'], geo['country'], geo['iso'], geo['isp'], geo['asn'], referrer, user_agent))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Visitor log error: {e}")

    init_visitors_db()
    print("👥 Visitor tracking enabled")

# This ensures /static/robot1.png is available immediately
app.mount("/static", StaticFiles(directory="static"), name="static")

r = redis.from_url(f"redis://{os.environ.get('REDIS_HOST', 'localhost')}/{os.environ.get('REDIS_DB', '0')}", decode_responses=True)
DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'

def _build_source_counts(raw):
    """Merge Redis source_counts hash with display names from sources table.
    Returns list of {source_id, display_name, hits} sorted by hits desc."""
    if not raw:
        return []
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        rows = conn.execute("SELECT source_id, display_name, first_seen, last_seen FROM sources WHERE active=1").fetchall()
        conn.close()
        meta = {row[0]: {"display_name": row[1] or row[0], "first_seen": row[2], "last_seen": row[3]} for row in rows}
    except Exception:
        meta = {}
    result = []
    for src_id, count in raw.items():
        m = meta.get(src_id, {})
        result.append({
            "source_id": src_id,
            "display_name": m.get("display_name", src_id),
            "hits": int(count or 0),
            "first_seen": m.get("first_seen"),
            "last_seen": m.get("last_seen"),
        })
    result.sort(key=lambda x: x["hits"], reverse=True)
    return result

async def load_protocol_runtime_config():
    enabled_protocols_raw = await r.get("knock:config:enabled_protocols")
    protocol_meta_raw = await r.get("knock:config:protocol_meta")
    try:
        enabled_protocols = json.loads(enabled_protocols_raw) if enabled_protocols_raw else list(DEFAULT_ENABLED_PROTOCOLS)
    except Exception:
        enabled_protocols = list(DEFAULT_ENABLED_PROTOCOLS)
    enabled_protocols = sort_protocols_for_ui([p for p in enabled_protocols if p in PROTO])
    if not enabled_protocols:
        enabled_protocols = list(DEFAULT_ENABLED_PROTOCOLS)

    default_protocol_meta = {
        name: {
            "proto_int": PROTO.get(name),
            "enabled": name in enabled_protocols,
            "supports_user_panel": bool(PROTOCOL_META.get(name, {}).get("supports_user_panel", False)),
            "supports_pass_panel": bool(PROTOCOL_META.get(name, {}).get("supports_pass_panel", False)),
            "color": PROTOCOL_META.get(name, {}).get("color", "#ffcc00"),
        }
        for name in PROTO.keys()
    }
    try:
        protocol_meta = json.loads(protocol_meta_raw) if protocol_meta_raw else default_protocol_meta
    except Exception:
        protocol_meta = default_protocol_meta
    return enabled_protocols, protocol_meta

class GlobalStatsCache:
    def __init__(self):
        self.top_locations = []
        self.top_passwords = []
        self.top_providers = []
        self.top_users = []
        self.top_ips = []
        self.proto_stats = {}  # keyed by proto int: {0: {top_locations, ...}, ...}
        self.last_updated = None

    async def _refresh_cache(self):
        loop = asyncio.get_event_loop()
        # ALL leaderboards (existing tables, index-driven)
        self.top_locations = await loop.run_in_executor(None, self._get_top_stats, "location", None)
        self.top_passwords = await loop.run_in_executor(None, self._get_top_stats, "password", None)
        self.top_providers = await loop.run_in_executor(None, self._get_top_stats, "isp", None)
        self.top_users = await loop.run_in_executor(None, self._get_top_stats, "username", None)
        self.top_ips = await loop.run_in_executor(None, self._get_top_stats, "ip", None)
        # Per-protocol leaderboards — only query enabled protocols
        enabled_protocols, _ = await load_protocol_runtime_config()
        self.proto_stats = {}
        for name in enabled_protocols:
            proto_int = PROTO[name]
            self.proto_stats[proto_int] = {
                "top_locations": await loop.run_in_executor(None, self._get_top_stats, "location", proto_int),
                "top_passwords": await loop.run_in_executor(None, self._get_top_stats, "password", proto_int),
                "top_providers": await loop.run_in_executor(None, self._get_top_stats, "isp", proto_int),
                "top_users":     await loop.run_in_executor(None, self._get_top_stats, "username", proto_int),
                "top_ips":       await loop.run_in_executor(None, self._get_top_stats, "ip", proto_int),
            }
        self.last_updated = datetime.now().strftime("%H:%M:%S")

    async def update_and_broadcast(self):
        # Prime the cache immediately so first visitors get full data
        try:
            await self._refresh_cache()
            print(f"📊 Stats Cache Primed: {self.last_updated}")
        except Exception as e:
            print(f"❌ Cache Prime Error: {e}")

        while True:
            await asyncio.sleep(60)
            try:
                await self._refresh_cache()
                print(f"📊 Stats Cache Updated: {self.last_updated}")

                payload = await manager.get_initial_data(include_protocol_config=False, include_history=False)
                await manager.broadcast(json.dumps({"type": "init_stats", "data": payload}))
            except Exception as e:
                print(f"❌ Cache Update Error: {e}")

    def _get_top_stats(self, stat_type, proto=None):
        """Synchronous helper for the executor - uses indexed intel tables."""
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if proto is None:
            queries = {
                "location": "SELECT iso_code as iso, country, hits as count FROM country_intel ORDER BY hits DESC",
                "password": "SELECT password as label, hits as count FROM pass_intel ORDER BY hits DESC LIMIT 100",
                "username": "SELECT username as label, hits as count FROM user_intel ORDER BY hits DESC LIMIT 100",
                "isp":      "SELECT isp as label, hits as count FROM isp_intel ORDER BY hits DESC LIMIT 100",
                "ip":       "SELECT ip as label, hits as count, ban_until FROM ip_intel ORDER BY hits DESC LIMIT 100",
            }
            cur.execute(queries[stat_type])
        else:
            queries = {
                "location": "SELECT iso_code as iso, country, hits as count FROM country_intel_proto WHERE proto=? ORDER BY hits DESC",
                "password": "SELECT password as label, hits as count FROM pass_intel_proto WHERE proto=? ORDER BY hits DESC LIMIT 100",
                "username": "SELECT username as label, hits as count FROM user_intel_proto WHERE proto=? ORDER BY hits DESC LIMIT 100",
                "isp":      "SELECT isp as label, hits as count FROM isp_intel_proto WHERE proto=? ORDER BY hits DESC LIMIT 100",
                "ip":       "SELECT p.ip as label, p.hits as count, i.ban_until FROM ip_intel_proto p LEFT JOIN ip_intel i ON p.ip=i.ip WHERE p.proto=? ORDER BY p.hits DESC LIMIT 100",
            }
            cur.execute(queries[stat_type], (proto,))
        rows = cur.fetchall()
        conn.close()
        now = int(time.time())
        result = [dict(row) for row in rows]
        if stat_type == "ip":
            for row in result:
                bu = row.pop("ban_until", None)
                row["banned"] = bu is not None and (bu == 0 or bu > now)
        return result

# Initialize the global cache
stats_cache = GlobalStatsCache()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def get_kpm(self):
        try:
            total_val = await r.get("knock:total_global")
            total_knocks = int(total_val) if total_val else 0
            uptime_val = await r.get("knock:uptime_minutes")
            uptime_minutes = int(uptime_val) if uptime_val else 0
            if uptime_minutes == 0:
                return 0.0
            return round(total_knocks / uptime_minutes, 2)
        except Exception:
            return 0.0

    async def get_recent_knocks(self, key="knock:recent", limit=100):
        try:
            raw = await r.lrange(key, 0, limit - 1)
            return [json.loads(item) for item in raw]
        except Exception as e:
            print(f"Error fetching history ({key}): {e}")
            return []

    async def get_initial_data(self, include_protocol_config=True, include_history=True):
        total_val = await r.get("knock:total_global")
        uptime_val = await r.get("knock:uptime_minutes")
        last_knock_val = await r.get("knock:last_time")
        last_lat_val = await r.get("knock:last_lat")
        last_lng_val = await r.get("knock:last_lng")
        current_kpm = await self.get_kpm()
        proto_counts_raw = await r.hgetall("knock:proto_counts")
        is_aggregator = bool(await r.get("knock:is_aggregator"))
        enabled_protocols = []
        protocol_meta = {}
        if include_protocol_config:
            enabled_protocols, protocol_meta = await load_protocol_runtime_config()
        total_count = int(total_val) if total_val else 0
        proto_breakdown = {}
        for name in PROTO.keys():
            count = int(proto_counts_raw.get(name, 0))
            pct = round((count * 100.0 / total_count), 2) if total_count > 0 else 0.0
            proto_uptime_val = await r.get(f"knock:uptime:{name.lower()}")
            proto_uptime = int(proto_uptime_val) if proto_uptime_val else 0
            proto_breakdown[name] = {"count": count, "pct": pct, "uptime": proto_uptime}

        payload = {
            "top_locations": stats_cache.top_locations,
            "total": int(total_val) if total_val else 0,
            "uptime_minutes": int(uptime_val) if uptime_val else 0,
            "kpm": current_kpm,
            "last_knock_time": int(last_knock_val) if last_knock_val else None,
            "last_lat": float(last_lat_val) if last_lat_val else None,
            "last_lng": float(last_lng_val) if last_lng_val else None,
            "top_passwords": stats_cache.top_passwords,
            "top_providers": stats_cache.top_providers,
            "top_users": stats_cache.top_users,
            "top_ips": stats_cache.top_ips,
            "proto_stats": {str(k): v for k, v in stats_cache.proto_stats.items()},
            "proto_breakdown": proto_breakdown,
            "cache_ts": stats_cache.last_updated,
            "is_aggregator": is_aggregator,
            "source_counts": _build_source_counts(await r.hgetall("knock:source_counts")) if is_aggregator else [],
        }

        if include_history:
            history = await self.get_recent_knocks("knock:recent")
            proto_histories = {}
            proto_last_times = {}
            for name in PROTO_NAME.values():
                proto_histories[name.lower()] = await self.get_recent_knocks(f"knock:recent:{name.lower()}")
                lt = await r.get(f"knock:last_time:{name.lower()}")
                if lt:
                    proto_last_times[name.lower()] = int(lt)
            payload["history"] = history
            payload["proto_histories"] = proto_histories
            payload["proto_last_times"] = proto_last_times

        if include_protocol_config:
            payload["enabled_protocols"] = enabled_protocols
            payload["protocol_meta"] = protocol_meta
        return payload

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        # The 100ms breather we discussed for Cloudflare stability
        await asyncio.sleep(0.1)
        self.active_connections.append(websocket)

        try:
            stats = await self.get_initial_data()
            history = stats.get("history", [])

            payload = {
                "type": "init_stats",
                "data": {
                    "total": stats.get("total", 0),
                    "uptime_minutes": stats.get("uptime_minutes", 0),
                    "kpm": stats.get("kpm", 0.0),
                    "last_knock_time": stats.get("last_knock_time"),
                    "last_lat": stats.get("last_lat"),
                    "last_lng": stats.get("last_lng"),
                    "top_locations": stats.get("top_locations", []),
                    "history": history if history else [],
                    "top_passwords": stats.get("top_passwords", []),
                    "top_providers": stats.get("top_providers", []),
                    "top_users": stats.get("top_users", []),
                    "top_ips": stats.get("top_ips", []),
                    "proto_stats": stats.get("proto_stats", {}),
                    "proto_breakdown": stats.get("proto_breakdown", {}),
                    "enabled_protocols": stats.get("enabled_protocols", []),
                    "protocol_meta": stats.get("protocol_meta", {}),
                    "proto_histories": stats.get("proto_histories", {}),
                    "proto_last_times": stats.get("proto_last_times", {}),
                    "cache_ts": stats.get("cache_ts"),
                    "last_knock_stats": history[0] if history else None,
                    "is_aggregator": stats.get("is_aggregator", False),
                    "source_counts": stats.get("source_counts", []),
                }
            }
            await websocket.send_json(payload)
        except Exception as e:
            print(f"❌ ERROR in connect: {e}")
            self.disconnect(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        if self.active_connections:
            await asyncio.gather(
                *[c.send_text(message) for c in self.active_connections],
                return_exceptions=True
            )

manager = ConnectionManager()

async def redis_listener():
    pubsub = r.pubsub()
    await pubsub.subscribe("knocks_stream")
    async for message in pubsub.listen():
        if message["type"] == "message":
            data = json.loads(message["data"])
            data["kpm"] = await manager.get_kpm()
            total_val = await r.get("knock:total_global")
            uptime_val = await r.get("knock:uptime_minutes")
            data["total_global"] = int(total_val) if total_val else 0
            data["uptime_minutes"] = int(uptime_val) if uptime_val else 0
            proto_name = data.get("proto", "").upper()
            if proto_name:
                pu = await r.get(f"knock:uptime:{proto_name.lower()}")
                data["proto_uptime"] = int(pu) if pu else 0
            payload = json.dumps({"type": "new_knock", "data": data})
            await manager.broadcast(payload)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Log visitor in background (non-blocking)
    if LOG_VISITORS:
        client_ip = get_client_ip(websocket)
        if client_ip:
            referrer = websocket.headers.get('referer') or websocket.headers.get('referrer')
            if referrer and 'knock-knock' in referrer.lower():
                referrer = None
            user_agent = websocket.headers.get('user-agent')
            asyncio.get_event_loop().run_in_executor(None, log_visitor, client_ip, referrer, user_agent)

    await manager.connect(websocket)
    try:
        while True:
            # This handles incoming pings from the browser to keep CF alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.head("/")
@app.get("/")
async def get():
    return HTMLResponse(content=open("index.html").read(), headers={"Cache-Control": "no-cache"})

@app.head("/summary")
@app.get("/summary")
async def get_summary():
    return HTMLResponse(content=open("summary.html").read(), headers={"Cache-Control": "no-cache"})

@app.head("/summary.html")
@app.get("/summary.html")
async def get_summary_html():
    return HTMLResponse(content=open("summary.html").read(), headers={"Cache-Control": "no-cache"})

@app.head("/sitemap.xml")
@app.get("/sitemap.xml")
async def get_sitemap():
    return Response(
        content=open("sitemap.xml").read(),
        media_type="application/xml",
        headers={"Cache-Control": "no-cache"},
    )

@app.head("/robots.txt")
@app.get("/robots.txt")
async def get_robots():
    return Response(
        content=open("robots.txt").read(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache"},
    )

if __name__ == "__main__":
    ssl_args = {}
    if os.environ.get('ENABLE_SSL', '').lower() == 'true':
        ssl_args = {
            'ssl_keyfile': os.environ.get('KNOCK_KEYFILE', 'certs/key.pem'),
            'ssl_certfile': os.environ.get('KNOCK_CERTFILE', 'certs/cert.pem'),
        }
    uvicorn.run("main:app",
        host=os.environ.get('WEB_LISTEN', '0.0.0.0'),
        port=int(os.environ.get('WEB_PORT', 8080)),
        proxy_headers=True,
        forwarded_allow_ips='*',
        workers=int(os.environ.get('WEB_WORKERS', 2)),
        timeout_keep_alive=30,
        log_level='warning',
        **ssl_args)

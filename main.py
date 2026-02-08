import asyncio, json, sqlite3, os
import redis.asyncio as redis
import geoip2.database
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from datetime import datetime
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# --- Visitor Tracking ---
VISITORS_DB_PATH = os.environ.get('DB_DIR', 'data') + '/visitors.db'
GEOIP_CITY_PATH = '/usr/share/GeoIP/GeoLite2-City.mmdb'
GEOIP_ASN_PATH = '/usr/share/GeoIP/GeoLite2-ASN.mmdb'

# Initialize GeoIP readers for visitor tracking
visitor_city_reader = geoip2.database.Reader(GEOIP_CITY_PATH) if os.path.exists(GEOIP_CITY_PATH) else None
visitor_asn_reader = geoip2.database.Reader(GEOIP_ASN_PATH) if os.path.exists(GEOIP_ASN_PATH) else None

def init_visitors_db():
    conn = sqlite3.connect(VISITORS_DB_PATH)
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
        conn = sqlite3.connect(VISITORS_DB_PATH)
        cur = conn.cursor()
        cur.execute("""INSERT INTO visitors (ip, city, region, country, iso_code, isp, asn, referrer, user_agent)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ip, geo['city'], geo['region'], geo['country'], geo['iso'], geo['isp'], geo['asn'], referrer, user_agent))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Visitor log error: {e}")

# Initialize visitors DB on module load
init_visitors_db()

# This ensures /static/robot1.png is available immediately
app.mount("/static", StaticFiles(directory="static"), name="static")

r = redis.from_url(f"redis://{os.environ.get('REDIS_HOST', 'localhost')}", decode_responses=True)
DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'

class GlobalStatsCache:
    def __init__(self):
        self.top_locations = []
        self.top_passwords = []
        self.top_providers = []
        self.top_users = []
        self.top_ips = []
        self.last_updated = None

    async def _refresh_cache(self):
        loop = asyncio.get_event_loop()
        self.top_locations = await loop.run_in_executor(None, self._get_top_stats, "location")
        self.top_passwords = await loop.run_in_executor(None, self._get_top_stats, "password")
        self.top_providers = await loop.run_in_executor(None, self._get_top_stats, "isp")
        self.top_users = await loop.run_in_executor(None, self._get_top_stats, "username")
        self.top_ips = await loop.run_in_executor(None, self._get_top_stats, "ip")
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

                payload = await manager.get_initial_data()
                await manager.broadcast(json.dumps({"type": "init_stats", "data": payload}))
            except Exception as e:
                print(f"❌ Cache Update Error: {e}")

    def _get_top_stats(self, stat_type):
        """Synchronous helper for the executor - uses indexed intel tables."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        queries = {
            "location": "SELECT iso_code as iso, country, hits as count FROM country_intel ORDER BY hits DESC",
            "password": "SELECT password as label, hits as count FROM pass_intel ORDER BY hits DESC LIMIT 100",
            "username": "SELECT username as label, hits as count FROM user_intel ORDER BY hits DESC LIMIT 100",
            "isp": "SELECT isp as label, hits as count FROM isp_intel ORDER BY hits DESC LIMIT 100",
            "ip": "SELECT ip as label, hits as count FROM ip_intel ORDER BY hits DESC LIMIT 100",
        }
        cur.execute(queries[stat_type])
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

# Initialize the global cache
stats_cache = GlobalStatsCache()

def get_knock_intel_stats(knock):
    """Get intel stats for a knock (hits, last_seen for each field)."""
    if not knock:
        return knock
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("SELECT hits, last_seen FROM country_intel WHERE iso_code=?", (knock.get('iso'),))
        row = cur.fetchone()
        knock['country_hits'], knock['country_last'] = (row[0], row[1]) if row else (0, None)

        cur.execute("SELECT hits, last_seen FROM user_intel WHERE username=?", (knock.get('user'),))
        row = cur.fetchone()
        knock['user_hits'], knock['user_last'] = (row[0], row[1]) if row else (0, None)

        cur.execute("SELECT hits, last_seen FROM pass_intel WHERE password=?", (knock.get('pass'),))
        row = cur.fetchone()
        knock['pass_hits'], knock['pass_last'] = (row[0], row[1]) if row else (0, None)

        cur.execute("SELECT hits, last_seen FROM isp_intel WHERE isp=?", (knock.get('isp'),))
        row = cur.fetchone()
        knock['isp_hits'], knock['isp_last'] = (row[0], row[1]) if row else (0, None)

        cur.execute("SELECT hits, last_seen FROM ip_intel WHERE ip=?", (knock.get('ip'),))
        row = cur.fetchone()
        knock['ip_hits'], knock['ip_last'] = (row[0], row[1]) if row else (0, None)
    finally:
        conn.close()
    return knock

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def get_kpm(self):
        try:
            total_val = await r.get("knock:total_global")
            total_knocks = int(total_val) if total_val else 0
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM monitor_heartbeats")
            count_minutes = cur.fetchone()[0]
            conn.close()
            if count_minutes == 0:
                return 0.0
            return round(total_knocks / count_minutes, 2)
        except Exception:
            return 0.0

    async def get_recent_knocks(self, limit=10):
        try:
            raw = await r.lrange("knock:recent", 0, limit - 1)
            return [json.loads(item) for item in raw]
        except Exception as e:
            print(f"Error fetching history: {e}")
            return []

    async def get_initial_data(self):
        total_val = await r.get("knock:total_global")
        last_knock_val = await r.get("knock:last_time")
        last_lat_val = await r.get("knock:last_lat")
        last_lng_val = await r.get("knock:last_lng")
        current_kpm = await self.get_kpm()

        return {
            "top_locations": stats_cache.top_locations,
            "total": int(total_val) if total_val else 0,
            "kpm": current_kpm,
            "last_knock_time": int(last_knock_val) if last_knock_val else None,
            "last_lat": float(last_lat_val) if last_lat_val else None,
            "last_lng": float(last_lng_val) if last_lng_val else None,
            "top_passwords": stats_cache.top_passwords,
            "top_providers": stats_cache.top_providers,
            "top_users": stats_cache.top_users,
            "top_ips": stats_cache.top_ips,
            "cache_ts": stats_cache.last_updated
        }

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        # The 100ms breather we discussed for Cloudflare stability
        await asyncio.sleep(0.1)
        self.active_connections.append(websocket)
        
        try:
            stats = await self.get_initial_data()
            history = await self.get_recent_knocks(100)

            # Enrich most recent knock with intel stats
            last_knock_stats = None
            if history:
                last_knock_stats = get_knock_intel_stats(dict(history[0]))

            payload = {
                "type": "init_stats",
                "data": {
                    "total": stats.get("total", 0),
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
                    "cache_ts": stats.get("cache_ts"),
                    "last_knock_stats": last_knock_stats
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
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

async def redis_listener():
    pubsub = r.pubsub()
    await pubsub.subscribe("radiation_stream")
    async for message in pubsub.listen():
        if message["type"] == "message":
            data = json.loads(message["data"])
            data["kpm"] = await manager.get_kpm()
            total_val = await r.get("knock:total_global")
            data["total_global"] = int(total_val) if total_val else 0
            payload = json.dumps({"type": "new_knock", "data": data})
            await manager.broadcast(payload)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(redis_listener())
    asyncio.create_task(stats_cache.update_and_broadcast())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Log visitor in background (non-blocking)
    client_ip = websocket.client.host if websocket.client else None
    if client_ip:
        # Extract referrer from WebSocket upgrade request headers
        referrer = websocket.headers.get('referer') or websocket.headers.get('referrer')
        # Filter out self-referrals (same site)
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

@app.get("/")
async def get():
    return HTMLResponse(content=open("index.html").read(), headers={"Cache-Control": "no-cache"})
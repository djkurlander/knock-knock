import asyncio, json, sqlite3
import redis.asyncio as redis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from datetime import datetime
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# This ensures /static/robot1.png is available immediately
app.mount("/static", StaticFiles(directory="static"), name="static")

r = redis.from_url("redis://localhost", decode_responses=True)
DB_PATH = 'knock_knock.db'

class GlobalStatsCache:
    def __init__(self):
        self.top_passwords = []
        self.top_providers = []
        self.top_users = [] # NEW
        self.last_updated = None

    async def update(self):
        while True:
            try:
                loop = asyncio.get_event_loop()
                self.top_passwords = await loop.run_in_executor(None, self._get_top_stats, "password")
                self.top_providers = await loop.run_in_executor(None, self._get_top_stats, "isp")
                self.top_users = await loop.run_in_executor(None, self._get_top_stats, "username") # NEW
                
                self.last_updated = datetime.now().strftime("%H:%M:%S")
                print(f"📊 Stats Cache Updated: {self.last_updated}")
            except Exception as e:
                print(f"❌ Cache Update Error: {e}")
            
            # Refresh every 10 minutes
            await asyncio.sleep(600)

    def _get_top_stats(self, stat_type):
        """Synchronous helper for the executor - uses indexed intel tables."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        queries = {
            "password": "SELECT password as label, hits as count FROM pass_intel ORDER BY hits DESC LIMIT 100",
            "username": "SELECT username as label, hits as count FROM user_intel ORDER BY hits DESC LIMIT 100",
            "isp": "SELECT isp as label, hits as count FROM isp_intel ORDER BY hits DESC LIMIT 100",
        }
        cur.execute(queries[stat_type])
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

# Initialize the global cache
stats_cache = GlobalStatsCache()

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
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT ip_address as ip, username as user, password as pass, 
                       city, country, iso_code as iso, isp 
                FROM knocks ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error fetching history: {e}")
            return []

    async def get_initial_data(self):
        total_val = await r.get("knock:total_global")
        current_kpm = await self.get_kpm()
        # Get country stats from SQLite intel table
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT iso_code as iso, country, hits as count FROM country_intel ORDER BY hits DESC LIMIT 100")
        shame_list = [dict(row) for row in cur.fetchall()]
        conn.close()
        
        return {
            "shame": shame_list,
            "total": int(total_val) if total_val else 0,
            "kpm": current_kpm,
            "top_passwords": stats_cache.top_passwords,
            "top_providers": stats_cache.top_providers,
            "top_users": stats_cache.top_users, # NEW
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
            
            payload = {
                "type": "init_stats",
                "data": {
                    "total": stats.get("total", 0),
                    "kpm": stats.get("kpm", 0.0),
                    "shame": stats.get("shame", []),
                    "history": history if history else [],
                    "top_passwords": stats.get("top_passwords", []),
                    "top_providers": stats.get("top_providers", []),
                    "top_users": stats.get("top_users", []),
                    "cache_ts": stats.get("cache_ts")
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

async def periodic_stats_sync():
    while True:
        await asyncio.sleep(60)
        try:
            payload = await manager.get_initial_data()
            await manager.broadcast(json.dumps({"type": "init_stats", "data": payload}))
        except Exception as e:
            print(f"Sync error: {e}")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(redis_listener())
    asyncio.create_task(periodic_stats_sync())
    # START THE STATS CACHER
    asyncio.create_task(stats_cache.update())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # This handles incoming pings from the browser to keep CF alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def get():
    return HTMLResponse(content=open("index.html").read())
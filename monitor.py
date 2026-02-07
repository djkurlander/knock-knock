import subprocess
import geoip2.database
import redis
import json
import sqlite3
import os
import threading
import time
import argparse
from datetime import datetime

# --- Configuration ---
GEOIP_CITY_PATH = '/usr/share/GeoIP/GeoLite2-City.mmdb'
GEOIP_ASN_PATH = '/usr/share/GeoIP/GeoLite2-ASN.mmdb' 
DB_PATH = 'knock_knock.db'

def reset_all():
    """Wipes the SQLite database and clears relevant Redis keys."""
    print("🧹 Resetting all data as requested...")
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f"   [+] Deleted {DB_PATH}")
        except Exception as e:
            print(f"   [!] Error deleting {DB_PATH}: {e}")
    try:
        r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        keys_to_clear = ["knock:total_global", "knock:wall_of_shame", "knock:ip_hits", "knock:recent"]
        for key in keys_to_clear:
            r.delete(key)
        print("   [+] Cleared Redis keys")
    except Exception as e:
        print(f"   [!] Error clearing Redis: {e}")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS knocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT, iso_code TEXT, city TEXT, region TEXT, country TEXT, isp TEXT,
        username TEXT, password TEXT
    )""")
    # Add region column if it doesn't exist (migration for existing DBs)
    try:
        cur.execute("ALTER TABLE knocks ADD COLUMN region TEXT")
    except:
        pass  # Column already exists
    # Add asn column if it doesn't exist (migration for existing DBs)
    try:
        cur.execute("ALTER TABLE knocks ADD COLUMN asn INTEGER")
    except:
        pass  # Column already exists
    try:
        cur.execute("ALTER TABLE isp_intel ADD COLUMN asn INTEGER")
    except:
        pass  # Column already exists
    cur.execute("CREATE TABLE IF NOT EXISTS user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL)")
    cur.execute("CREATE TABLE IF NOT EXISTS monitor_heartbeats (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    # Indexes for fast top-N queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_intel_hits ON user_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pass_intel_hits ON pass_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country_intel_hits ON country_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_isp_intel_hits ON isp_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_hits ON ip_intel(hits DESC)")
    conn.commit()
    conn.close()

def heartbeat_worker():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO monitor_heartbeats DEFAULT VALUES")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Heartbeat Error: {e}")
        time.sleep(60)

def log_to_maximalist_db(data, save_knocks=True):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        if save_knocks:
            cur.execute("""INSERT INTO knocks (ip_address, iso_code, city, region, country, isp, asn, username, password)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (data['ip'], data['iso'], data['city'], data.get('region'), data['country'], data['isp'], data.get('asn'), data['user'], data['pass']))
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("INSERT INTO user_intel VALUES (?, 1, ?) ON CONFLICT(username) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], now, now))
        cur.execute("INSERT INTO pass_intel VALUES (?, 1, ?) ON CONFLICT(password) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], now, now))
        cur.execute("INSERT INTO country_intel VALUES (?, ?, 1, ?) ON CONFLICT(iso_code) DO UPDATE SET hits=hits+1, last_seen=?", (data['iso'], data['country'], now, now))
        cur.execute("INSERT INTO isp_intel VALUES (?, 1, ?, ?) ON CONFLICT(isp) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], now, data.get('asn'), now, data.get('asn')))
        cur.execute("INSERT INTO ip_intel VALUES (?, 1, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET hits=hits+1, last_seen=?, lat=?, lng=?",
                    (data['ip'], now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
        conn.commit()
    finally:
        conn.close()

def get_intel_stats_before_update(data):
    """Get hit counts and last_seen BEFORE updating - so we get the previous values."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    stats = {}
    try:
        cur.execute("SELECT hits, last_seen FROM country_intel WHERE iso_code=?", (data['iso'],))
        row = cur.fetchone()
        stats['country_hits'], stats['country_last'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM user_intel WHERE username=?", (data['user'],))
        row = cur.fetchone()
        stats['user_hits'], stats['user_last'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM pass_intel WHERE password=?", (data['pass'],))
        row = cur.fetchone()
        stats['pass_hits'], stats['pass_last'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM isp_intel WHERE isp=?", (data['isp'],))
        row = cur.fetchone()
        stats['isp_hits'], stats['isp_last'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM ip_intel WHERE ip=?", (data['ip'],))
        row = cur.fetchone()
        stats['ip_hits'], stats['ip_last'] = (row[0] + 1, row[1]) if row else (1, None)
    finally:
        conn.close()
    return stats

def get_geo_maximal(ip, city_reader, asn_reader):
    geo = {"iso": "XX", "country": "Unknown", "city": "Unknown", "region": None, "isp": "Unknown", "asn": None, "lat": None, "lng": None}
    try:
        if city_reader:
            c_res = city_reader.city(ip)
            geo["iso"] = c_res.country.iso_code
            geo["country"] = c_res.country.name
            geo["city"] = c_res.city.name or "Unknown"
            if c_res.subdivisions.most_specific.name:
                geo["region"] = c_res.subdivisions.most_specific.name
            if c_res.location:
                geo["lat"] = c_res.location.latitude
                geo["lng"] = c_res.location.longitude
        if asn_reader:
            a_res = asn_reader.asn(ip)
            geo["isp"] = a_res.autonomous_system_organization or "Unknown"
            geo["asn"] = a_res.autonomous_system_number
    except:
        pass
    return geo

def monitor(save_knocks=False):
    init_db()
    threading.Thread(target=heartbeat_worker, daemon=True).start()
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    c_reader = geoip2.database.Reader(GEOIP_CITY_PATH) if os.path.exists(GEOIP_CITY_PATH) else None
    a_reader = geoip2.database.Reader(GEOIP_ASN_PATH) if os.path.exists(GEOIP_ASN_PATH) else None

    cmd = ["journalctl", "-u", "knock-honeypot", "-f", "-n", "0"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    print("🚀 Maximalist Monitor Active...")

    for line in process.stdout:
        if "[*] KNOCK |" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4: continue
            _, ip, user, pw = parts
            geo = get_geo_maximal(ip, c_reader, a_reader)
            package = {
                "ip": ip, "user": user, "pass": pw,
                "city": geo['city'], "region": geo['region'], "country": geo['country'],
                "iso": geo['iso'], "isp": geo['isp'], "asn": geo['asn'],
                "lat": geo['lat'], "lng": geo['lng']
            }
            package.update(get_intel_stats_before_update(package))
            log_to_maximalist_db(package, save_knocks=save_knocks)
            r.lpush("knock:recent", json.dumps(package))
            r.ltrim("knock:recent", 0, 99)
            shame_key = f"{geo['iso']}:{geo['country']}"
            r.zincrby("knock:wall_of_shame", 1, shame_key)
            r.incr("knock:total_global")
            r.set("knock:last_time", int(time.time()))
            if geo['lat'] is not None:
                r.set("knock:last_lat", geo['lat'])
                r.set("knock:last_lng", geo['lng'])
            r.publish("radiation_stream", json.dumps(package))
            print(f"📡 {geo['iso']} | {user}:{pw} via {geo['isp']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock Monitor")
    parser.add_argument("--reset-all", action="store_true", help="Delete DB and clear Redis")
    parser.add_argument("--save-knocks", action="store_true", help="Save individual knocks to SQLite (off by default)")
    args = parser.parse_args()
    if args.reset_all: reset_all()
    monitor(save_knocks=args.save_knocks)
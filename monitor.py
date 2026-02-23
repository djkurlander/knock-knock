import sys
import subprocess
import signal
import queue
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
DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'

from constants import PROTO, PROTO_NAME

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
        r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)
        keys_to_clear = ["knock:total_global", "knock:uptime_minutes", "knock:last_time", "knock:last_lat", "knock:last_lng", "knock:recent",
                         "knock:recent:ssh", "knock:recent:tnet", "knock:recent:smtp", "knock:recent:rdp", "knock:recent:mail", "knock:recent:ftp"]
        for key in keys_to_clear:
            r.delete(key)
        print("   [+] Cleared Redis keys")
    except Exception as e:
        print(f"   [!] Error clearing Redis: {e}")

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS knocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT, iso_code TEXT, city TEXT, region TEXT, country TEXT, isp TEXT, asn INTEGER,
        username TEXT, password TEXT, proto INTEGER
    )""")
    # Migrate: add proto column to existing databases
    knock_cols = [row[1] for row in cur.execute("PRAGMA table_info(knocks)").fetchall()]
    if 'proto' not in knock_cols:
        cur.execute("ALTER TABLE knocks ADD COLUMN proto INTEGER")
        print("✅ Migrated knocks: added proto column")
    cur.execute("CREATE TABLE IF NOT EXISTS user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL)")
    cur.execute("CREATE TABLE IF NOT EXISTS monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0)")
    # Migrate old schema (many timestamp rows) to single uptime_minutes row
    cols = [row[1] for row in cur.execute("PRAGMA table_info(monitor_heartbeats)").fetchall()]
    if 'timestamp' in cols:
        old_count = cur.execute("SELECT COUNT(*) FROM monitor_heartbeats").fetchone()[0]
        cur.execute("DROP TABLE monitor_heartbeats")
        cur.execute("CREATE TABLE monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0)")
        cur.execute("INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, ?)", (old_count,))
        conn.commit()
        print(f"✅ Migrated monitor_heartbeats: {old_count} rows → uptime_minutes={old_count}")
    # Indexes for fast top-N queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_intel_hits ON user_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pass_intel_hits ON pass_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country_intel_hits ON country_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_isp_intel_hits ON isp_intel(hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_hits ON ip_intel(hits DESC)")
    # Per-protocol intel tables (composite PK: value + proto)
    cur.execute("CREATE TABLE IF NOT EXISTS user_intel_proto (username TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, PRIMARY KEY (username, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel_proto (password TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, PRIMARY KEY (password, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel_proto (iso_code TEXT, proto INTEGER, country TEXT, hits INTEGER, last_seen DATETIME, PRIMARY KEY (iso_code, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel_proto (isp TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, asn INTEGER, PRIMARY KEY (isp, proto))")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_intel_proto (ip TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL, PRIMARY KEY (ip, proto))")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_intel_proto_hits ON user_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pass_intel_proto_hits ON pass_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country_intel_proto_hits ON country_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_isp_intel_proto_hits ON isp_intel_proto(proto, hits DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_proto_hits ON ip_intel_proto(proto, hits DESC)")
    cur.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()

def heartbeat_worker(redis_conn):
    while True:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            cur = conn.cursor()
            cur.execute("INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET uptime_minutes = uptime_minutes + 1")
            conn.commit()
            conn.close()
            redis_conn.incr("knock:uptime_minutes")
        except Exception as e:
            print(f"❌ Heartbeat Error: {e}")
        time.sleep(60)

def log_to_maximalist_db(data, save_knocks=True):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    try:
        if save_knocks:
            cur.execute("""INSERT INTO knocks (ip_address, iso_code, city, region, country, isp, asn, username, password, proto)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (data['ip'], data['iso'], data['city'], data.get('region'), data['country'], data['isp'], data.get('asn'), data['user'], data['pass'],
                         PROTO.get(data.get('proto', 'SSH'), 0)))
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        proto_int = PROTO.get(data.get('proto', 'SSH'), 0)
        cur.execute("INSERT INTO user_intel VALUES (?, 1, ?) ON CONFLICT(username) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], now, now))
        cur.execute("INSERT INTO pass_intel VALUES (?, 1, ?) ON CONFLICT(password) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], now, now))
        cur.execute("INSERT INTO country_intel VALUES (?, ?, 1, ?) ON CONFLICT(iso_code) DO UPDATE SET hits=hits+1, last_seen=?, country=?", (data['iso'], data['country'], now, now, data['country']))
        cur.execute("INSERT INTO isp_intel VALUES (?, 1, ?, ?) ON CONFLICT(isp) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], now, data.get('asn'), now, data.get('asn')))
        cur.execute("INSERT INTO ip_intel VALUES (?, 1, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET hits=hits+1, last_seen=?, lat=?, lng=?",
                    (data['ip'], now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
        cur.execute("INSERT INTO user_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(username, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], proto_int, now, now))
        cur.execute("INSERT INTO pass_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(password, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], proto_int, now, now))
        cur.execute("INSERT INTO country_intel_proto VALUES (?, ?, ?, 1, ?) ON CONFLICT(iso_code, proto) DO UPDATE SET hits=hits+1, last_seen=?, country=?", (data['iso'], proto_int, data['country'], now, now, data['country']))
        cur.execute("INSERT INTO isp_intel_proto VALUES (?, ?, 1, ?, ?) ON CONFLICT(isp, proto) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], proto_int, now, data.get('asn'), now, data.get('asn')))
        cur.execute("INSERT INTO ip_intel_proto VALUES (?, ?, 1, ?, ?, ?) ON CONFLICT(ip, proto) DO UPDATE SET hits=hits+1, last_seen=?, lat=?, lng=?",
                    (data['ip'], proto_int, now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
        conn.commit()
    finally:
        conn.close()

def get_intel_stats_before_update(data):
    """Get hit counts and last_seen BEFORE updating - so we get the previous values."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
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

def sanitize_credential(s):
    if not s:
        return s
    if '\ufffd' in s or not s.isprintable():
        return '<cryptic binary>'
    return s

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
    r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)
    while True:
        try:
            c_reader = geoip2.database.Reader(GEOIP_CITY_PATH)
            a_reader = geoip2.database.Reader(GEOIP_ASN_PATH)
            print("✅ GeoIP databases loaded")
            break
        except Exception as e:
            print(f"⏳ Waiting for GeoIP databases... ({e})")
            time.sleep(5)

    # Seed Redis totals from SQLite on startup to stay in sync
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        total = conn.execute("SELECT SUM(hits) FROM ip_intel").fetchone()[0] or 0
        uptime = conn.execute("SELECT uptime_minutes FROM monitor_heartbeats WHERE id=1").fetchone()
        uptime = uptime[0] if uptime else 0
        conn.close()
        r.set("knock:total_global", total)
        if not r.get("knock:uptime_minutes"):
            r.set("knock:uptime_minutes", uptime)
    except Exception as e:
        print(f"⚠️ Could not seed totals from SQLite: {e}")

    # Spawn honeypots as subprocesses
    honeypots = {
        "SSH":  subprocess.Popen([sys.executable, "-u", "ssh_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
        "TNET": subprocess.Popen([sys.executable, "-u", "telnet_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
        "SMTP": subprocess.Popen([sys.executable, "-u", "smtp_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
        "MAIL": subprocess.Popen([sys.executable, "-u", "smtp25_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
        "RDP":  subprocess.Popen([sys.executable, "-u", "rdp_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
        "FTP":  subprocess.Popen([sys.executable, "-u", "ftp_honeypot.py"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True),
    }

    knock_queue = queue.Queue()

    def pipe_reader(proc, name):
        for line in proc.stdout:
            knock_queue.put(line)
        code = proc.wait()
        print(f"⚠️ {name} honeypot exited (code {code}), shutting down")
        knock_queue.put(None)  # sentinel — signals main loop to shut down

    for name, proc in honeypots.items():
        threading.Thread(target=pipe_reader, args=(proc, name), daemon=True).start()

    # If monitor is killed, take all honeypots down too
    def cleanup(signum, frame):
        for proc in honeypots.values():
            proc.terminate()
        sys.exit(0)
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    threading.Thread(target=heartbeat_worker, args=(r,), daemon=True).start()

    print("🚀 Maximalist Monitor Active...")

    while True:
        line = knock_queue.get()
        if line is None:  # a honeypot exited — terminate all and let systemd restart us
            for proc in honeypots.values():
                proc.terminate()
            sys.exit(1)
        try:
            knock = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            print(line, end='', flush=True)  # pass through diagnostic output from honeypots
            continue
        if knock.get("type") == "KNOCK":
            ip, user, pw = knock["ip"], knock["user"], knock["pass"]
            user = sanitize_credential(user)
            pw   = sanitize_credential(pw)
            geo = get_geo_maximal(ip, c_reader, a_reader)
            package = {
                "ip": ip, "user": user, "pass": pw,
                "proto": knock.get("proto", "SSH"),
                "city": geo['city'], "region": geo['region'], "country": geo['country'],
                "iso": geo['iso'], "isp": geo['isp'], "asn": geo['asn'],
                "lat": geo['lat'], "lng": geo['lng']
            }
            if knock.get("subject"):
                package["subject"] = knock["subject"]
            try:
                package.update(get_intel_stats_before_update(package))
                log_to_maximalist_db(package, save_knocks=save_knocks)
            except Exception as e:
                print(f"⚠️ DB error (knock skipped): {e}")
            r.lpush("knock:recent", json.dumps(package))
            r.ltrim("knock:recent", 0, 99)
            proto_key = "knock:recent:" + package['proto'].lower()
            r.lpush(proto_key, json.dumps(package))
            r.ltrim(proto_key, 0, 99)
            r.incr("knock:total_global")
            r.set("knock:last_time", int(time.time()))
            if geo['lat'] is not None:
                r.set("knock:last_lat", geo['lat'])
                r.set("knock:last_lng", geo['lng'])
            r.publish("radiation_stream", json.dumps(package))
            if package.get("subject"):
                print(f"📧 MAIL {geo['iso']} | {user} → {pw} | {package['subject'][:60]} via {geo['isp']}")
            else:
                print(f"📡 {knock.get('proto', 'SSH')} {geo['iso']} | {user}:{pw} via {geo['isp']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock Monitor")
    parser.add_argument("--reset-all", action="store_true", help="Delete DB and clear Redis")
    parser.add_argument("--save-knocks", action="store_true", help="Save individual knocks to SQLite (off by default)")
    args = parser.parse_args()
    if args.reset_all: reset_all()
    monitor(save_knocks=args.save_knocks)
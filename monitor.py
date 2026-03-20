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
import re
import socket
from datetime import datetime

# --- Configuration ---
GEOIP_CITY_PATH = '/usr/share/GeoIP/GeoLite2-City.mmdb'
GEOIP_ASN_PATH = '/usr/share/GeoIP/GeoLite2-ASN.mmdb'
DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'
BLOCKLIST_FILE = os.environ.get('DB_DIR', 'data') + '/blocklist.txt'

from constants import PROTO, PROTO_NAME, PROTOCOL_META, DEFAULT_ENABLED_PROTOCOLS, sort_protocols_for_ui

USER_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_user_panel')}
PASS_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_pass_panel')}
MAIL_FORENSICS_MAX = int(os.environ.get("MAIL_FORENSICS_MAX", "100"))

def parse_enabled_protocols():
    raw = os.environ.get("ENABLED_PROTOCOLS", "").strip()
    if not raw:
        return list(DEFAULT_ENABLED_PROTOCOLS)
    enabled = []
    for token in raw.split(','):
        name = token.strip().upper()
        if not name:
            continue
        if name not in PROTO:
            print(f"⚠️ Ignoring unknown protocol in ENABLED_PROTOCOLS: {name}", flush=True)
            continue
        if name not in enabled:
            enabled.append(name)
    if not enabled:
        print("⚠️ ENABLED_PROTOCOLS resolved to empty set; using defaults", flush=True)
        return list(DEFAULT_ENABLED_PROTOCOLS)
    return enabled

def publish_protocol_config(redis_conn, enabled_protocols):
    enabled = sort_protocols_for_ui([p for p in enabled_protocols if p in PROTO])
    meta = {}
    for name in PROTO.keys():
        base = PROTOCOL_META.get(name, {})
        meta[name] = {
            "proto_int": PROTO.get(name),
            "enabled": name in enabled,
            "supports_user_panel": bool(base.get("supports_user_panel", False)),
            "supports_pass_panel": bool(base.get("supports_pass_panel", False)),
            "color": base.get("color", "#ffcc00"),
        }
    redis_conn.set("knock:config:enabled_protocols", json.dumps(enabled))
    redis_conn.set("knock:config:protocol_meta", json.dumps(meta))

def _discover_self_identifiers():
    ips = set()
    hosts = set()
    host_suffixes = set()

    # Explicit operator-provided aliases are always honored.
    for key in ('REDACT_SELF_IPS', 'SERVER_IP', 'PUBLIC_IP', 'HOST_IP', 'HONEYPOT_IP'):
        for v in os.environ.get(key, '').split(','):
            v = v.strip()
            if v:
                ips.add(v)
    for key in ('REDACT_SELF_HOSTS', 'SERVER_HOST', 'PUBLIC_HOST', 'HOST_FQDN', 'HONEYPOT_HOST'):
        for v in os.environ.get(key, '').split(','):
            v = v.strip().lower()
            if v:
                hosts.add(v)
    for v in os.environ.get('REDACT_SELF_HOST_SUFFIXES', '').split(','):
        v = v.strip().lower().lstrip('.')
        if v:
            host_suffixes.add(v)

    # Auto-discover local hostnames.
    try:
        hn = socket.gethostname().strip().lower()
        if hn:
            hosts.add(hn)
    except Exception:
        pass
    try:
        fqn = socket.getfqdn().strip().lower()
        if fqn:
            hosts.add(fqn)
    except Exception:
        pass

    # Auto-discover primary outbound IPv4 used by this host.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip:
            ips.add(ip)
    except Exception:
        pass

    # Auto-discover IPv4s bound/resolved to this hostname.
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            if family == socket.AF_INET and sockaddr and sockaddr[0]:
                ips.add(sockaddr[0])
    except Exception:
        pass
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(socket.getfqdn(), None):
            if family == socket.AF_INET and sockaddr and sockaddr[0]:
                ips.add(sockaddr[0])
    except Exception:
        pass
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL).strip()
        for tok in out.split():
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", tok):
                ips.add(tok)
    except Exception:
        pass

    # Reverse lookup discovered IPs for host aliases.
    for ip in list(ips):
        try:
            ptr = socket.gethostbyaddr(ip)[0].strip().lower()
            if ptr:
                hosts.add(ptr)
        except Exception:
            pass

    return ips, hosts, host_suffixes

def _build_self_redaction_patterns():
    ips, hosts, host_suffixes = _discover_self_identifiers()
    pats = []
    # Hostnames first, then IPs, to avoid partial replacements inside host tokens.
    for host in sorted(hosts, key=len, reverse=True):
        pats.append((re.compile(re.escape(host), re.IGNORECASE), "<target-host>"))
    for suffix in sorted(host_suffixes, key=len, reverse=True):
        pats.append((re.compile(rf"[A-Za-z0-9._-]+\.{re.escape(suffix)}", re.IGNORECASE), "<target-host>"))
    # Longest-first replacement avoids partial overlap artifacts.
    for ip in sorted(ips, key=len, reverse=True):
        pats.append((re.compile(re.escape(ip)), "<target-ip>"))
        # Common dash-notation seen in hostnames (e.g. 1-2-3-4.example.tld).
        dashed = ip.replace('.', '-')
        if dashed != ip:
            pats.append((re.compile(re.escape(dashed), re.IGNORECASE), "<target-ip>"))
    return pats

SELF_REDACTION_PATTERNS = _build_self_redaction_patterns()

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
        preserve = {'knock:blocked', 'knock:alerted:'}
        for key in r.scan_iter('knock:*'):
            if any(key == p or key.startswith(p) for p in preserve):
                continue
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
    # Migrate v1 (SSH-only) → v2 (multi-protocol): add proto column
    knock_cols = [row[1] for row in cur.execute("PRAGMA table_info(knocks)").fetchall()]
    v1_migration = 'proto' not in knock_cols
    if v1_migration:
        cur.execute("ALTER TABLE knocks ADD COLUMN proto INTEGER")
        cur.execute("UPDATE knocks SET proto = 0 WHERE proto IS NULL")
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
    # Add per-protocol uptime columns (one per known protocol)
    hb_cols = [row[1] for row in cur.execute("PRAGMA table_info(monitor_heartbeats)").fetchall()]
    added_uptime_cols = False
    for proto_name in PROTO:
        col = f"uptime_{proto_name.lower()}"
        if col not in hb_cols:
            cur.execute(f"ALTER TABLE monitor_heartbeats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            added_uptime_cols = True
    if added_uptime_cols:
        # Seed uptime for any protocol that has recorded knocks (it was running)
        active_protos = [row[0] for row in cur.execute(
            "SELECT DISTINCT proto FROM ip_intel_proto").fetchall()]
        seeded = []
        for proto_int in active_protos:
            name = PROTO_NAME.get(proto_int)
            if name:
                col = f"uptime_{name.lower()}"
                cur.execute(f"UPDATE monitor_heartbeats SET {col} = uptime_minutes WHERE id = 1")
                seeded.append(name)
        print(f"✅ Added per-protocol uptime tracking (seeded from total uptime: {', '.join(seeded) or 'none'})")
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
    # Seed _proto tables from ALL tables (v1 single-protocol data → proto=0)
    has_all = cur.execute("SELECT 1 FROM ip_intel LIMIT 1").fetchone()
    has_proto = cur.execute("SELECT 1 FROM ip_intel_proto LIMIT 1").fetchone()
    if has_all and not has_proto:
        cur.execute("INSERT OR REPLACE INTO user_intel_proto (username, proto, hits, last_seen) SELECT username, 0, hits, last_seen FROM user_intel")
        cur.execute("INSERT OR REPLACE INTO pass_intel_proto (password, proto, hits, last_seen) SELECT password, 0, hits, last_seen FROM pass_intel")
        cur.execute("INSERT OR REPLACE INTO country_intel_proto (iso_code, proto, country, hits, last_seen) SELECT iso_code, 0, country, hits, last_seen FROM country_intel")
        cur.execute("INSERT OR REPLACE INTO isp_intel_proto (isp, proto, hits, last_seen, asn) SELECT isp, 0, hits, last_seen, asn FROM isp_intel")
        cur.execute("INSERT OR REPLACE INTO ip_intel_proto (ip, proto, hits, last_seen, lat, lng) SELECT ip, 0, hits, last_seen, lat, lng FROM ip_intel")
        print("✅ Seeded _proto tables from ALL tables (existing data tagged as SSH)")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.fetchone()  # consume PRAGMA result to avoid "statements in progress" error
    conn.commit()
    conn.close()

def heartbeat_worker(redis_conn, enabled_protocols):
    proto_cols = [f"uptime_{p.lower()}" for p in enabled_protocols]
    proto_set_clause = ", ".join(f"{col} = {col} + 1" for col in proto_cols)
    while True:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            cur = conn.cursor()
            cur.execute(f"INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET uptime_minutes = uptime_minutes + 1, {proto_set_clause}")
            conn.commit()
            conn.close()
            redis_conn.incr("knock:uptime_minutes")
            for p in enabled_protocols:
                redis_conn.incr(f"knock:uptime:{p.lower()}")
        except Exception as e:
            print(f"❌ Heartbeat Error: {e}")
        time.sleep(60)

def log_to_enriched_db(data, save_knocks=True):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    try:
        if save_knocks:
            cur.execute("""INSERT INTO knocks (ip_address, iso_code, city, region, country, isp, asn, username, password, proto)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (data['ip'], data['iso'], data['city'], data.get('region'), data['country'], data['isp'], data.get('asn'), data.get('user'), data.get('pass'),
                         PROTO.get(data.get('proto', 'SSH'), 0)))
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        proto_int = PROTO.get(data.get('proto', 'SSH'), 0)
        if data.get('user') is not None:
            cur.execute("INSERT INTO user_intel VALUES (?, 1, ?) ON CONFLICT(username) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], now, now))
            cur.execute("INSERT INTO user_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(username, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], proto_int, now, now))
        if data.get('pass') is not None:
            cur.execute("INSERT INTO pass_intel VALUES (?, 1, ?) ON CONFLICT(password) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], now, now))
            cur.execute("INSERT INTO pass_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(password, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], proto_int, now, now))
        cur.execute("INSERT INTO country_intel VALUES (?, ?, 1, ?) ON CONFLICT(iso_code) DO UPDATE SET hits=hits+1, last_seen=?, country=?", (data['iso'], data['country'], now, now, data['country']))
        cur.execute("INSERT INTO isp_intel VALUES (?, 1, ?, ?) ON CONFLICT(isp) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], now, data.get('asn'), now, data.get('asn')))
        cur.execute("INSERT INTO ip_intel VALUES (?, 1, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET hits=hits+1, last_seen=?, lat=?, lng=?",
                    (data['ip'], now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
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
    proto_int = PROTO.get(data.get('proto', 'SSH'), 0)
    try:
        cur.execute("SELECT hits, last_seen FROM country_intel WHERE iso_code=?", (data['iso'],))
        row = cur.fetchone()
        stats['country_hits'], stats['country_last'] = (row[0] + 1, row[1]) if row else (1, None)
        cur.execute("SELECT hits, last_seen FROM country_intel_proto WHERE iso_code=? AND proto=?", (data['iso'], proto_int))
        row = cur.fetchone()
        stats['country_hits_proto'], stats['country_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)

        if data.get('user') is not None:
            cur.execute("SELECT hits, last_seen FROM user_intel WHERE username=?", (data['user'],))
            row = cur.fetchone()
            stats['user_hits'], stats['user_last'] = (row[0] + 1, row[1]) if row else (1, None)
            cur.execute("SELECT hits, last_seen FROM user_intel_proto WHERE username=? AND proto=?", (data['user'], proto_int))
            row = cur.fetchone()
            stats['user_hits_proto'], stats['user_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)

        if data.get('pass') is not None:
            cur.execute("SELECT hits, last_seen FROM pass_intel WHERE password=?", (data['pass'],))
            row = cur.fetchone()
            stats['pass_hits'], stats['pass_last'] = (row[0] + 1, row[1]) if row else (1, None)
            cur.execute("SELECT hits, last_seen FROM pass_intel_proto WHERE password=? AND proto=?", (data['pass'], proto_int))
            row = cur.fetchone()
            stats['pass_hits_proto'], stats['pass_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM isp_intel WHERE isp=?", (data['isp'],))
        row = cur.fetchone()
        stats['isp_hits'], stats['isp_last'] = (row[0] + 1, row[1]) if row else (1, None)
        cur.execute("SELECT hits, last_seen FROM isp_intel_proto WHERE isp=? AND proto=?", (data['isp'], proto_int))
        row = cur.fetchone()
        stats['isp_hits_proto'], stats['isp_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)

        cur.execute("SELECT hits, last_seen FROM ip_intel WHERE ip=?", (data['ip'],))
        row = cur.fetchone()
        stats['ip_hits'], stats['ip_last'] = (row[0] + 1, row[1]) if row else (1, None)
        cur.execute("SELECT hits, last_seen FROM ip_intel_proto WHERE ip=? AND proto=?", (data['ip'], proto_int))
        row = cur.fetchone()
        stats['ip_hits_proto'], stats['ip_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)
    finally:
        conn.close()
    return stats

def sanitize_credential(s):
    if not s:
        return s
    if '\ufffd' in s or not s.isprintable():
        return '<cryptic binary>'
    for pat, replacement in SELF_REDACTION_PATTERNS:
        s = pat.sub(replacement, s)
    return s

def sanitize_body(s, max_len=2000):
    """Preserve readable multiline text while stripping non-printable control chars."""
    if not s:
        return s
    out = []
    for ch in s:
        if ch in ('\n', '\r', '\t') or ch.isprintable():
            out.append(ch)
    clean = ''.join(out)
    for pat, replacement in SELF_REDACTION_PATTERNS:
        clean = pat.sub(replacement, clean)
    return clean[:max_len]

def build_smtp_diag(knock):
    return {
        "proto": knock.get("proto", "SMTP"),
        "ip": knock.get("ip"),
        "session_id": knock.get("session_id"),
        "event": sanitize_credential(str(knock.get("event", ""))),
        "duration_ms": int(knock.get("duration_ms", 0) or 0),
        "commands_seen": int(knock.get("commands_seen", 0) or 0),
        "stop_reason": sanitize_credential(str(knock.get("stop_reason", ""))),
        "no_knock_reason": sanitize_credential(str(knock.get("no_knock_reason", ""))),
        "no_knock_detail": sanitize_credential(str(knock.get("no_knock_detail", ""))),
        "last_cmd": sanitize_credential(str(knock.get("last_cmd", ""))),
        "tls_active": bool(knock.get("tls_active", False)),
        "authed": bool(knock.get("authed", False)),
        "saw_starttls": bool(knock.get("saw_starttls", False)),
        "saw_auth": bool(knock.get("saw_auth", False)),
        "saw_mail": bool(knock.get("saw_mail", False)),
        "saw_rcpt": bool(knock.get("saw_rcpt", False)),
        "saw_data": bool(knock.get("saw_data", False)),
        "ts": int(time.time()),
    }

def store_smtp_diag(redis_conn, diag):
    proto = diag.get("proto", "SMTP").lower()
    redis_conn.lpush(f"knock:diag:{proto}:no_knock", json.dumps(diag))
    redis_conn.ltrim(f"knock:diag:{proto}:no_knock", 0, 499)
    redis_conn.set(f"knock:diag:{proto}:last", json.dumps(diag))
    if diag["no_knock_reason"]:
        redis_conn.hincrby(f"knock:diag:{proto}:reason_counts", diag["no_knock_reason"], 1)
    label = "SMTP25" if proto == "mail" else "SMTP587"
    print(
        f"🧪 {label} no-knock {diag['ip']} | reason={diag['no_knock_reason']} "
        f"stop={diag['stop_reason']} cmds={diag['commands_seen']}",
        flush=True,
    )

def build_mail_forensic(knock, proto, ip):
    mail_from = knock.get("mail_from", knock.get("smtp_mail_from"))
    mail_to = knock.get("mail_to", knock.get("smtp_rcpt_to"))
    subject = knock.get("subject")
    body = knock.get("body")
    if proto not in ("SMTP", "MAIL"):
        return None
    if not any(v is not None for v in (mail_from, mail_to, subject, body)):
        return None
    return {
        "ts": int(time.time()),
        "proto": proto,
        "ip": ip,
        "session_id": knock.get("session_id"),
        "mail_from": str(mail_from) if mail_from is not None else None,
        "mail_to": str(mail_to) if mail_to is not None else None,
        "subject": str(subject) if subject is not None else None,
        "body": str(body) if body is not None else None,
    }

def store_mail_forensic(redis_conn, forensic):
    if not forensic:
        return
    redis_conn.lpush("knock:forensics:mail_raw", json.dumps(forensic))
    redis_conn.ltrim("knock:forensics:mail_raw", 0, max(0, MAIL_FORENSICS_MAX - 1))

def is_over_limit_and_block(redis_conn, ip, projected_hits, max_knocks):
    if not max_knocks:
        return False
    if projected_hits <= max_knocks:
        return False
    if not redis_conn.sismember("knock:blocked", ip):
        add_to_blocklist(ip, redis_conn)
    print(f"⛔ Dropped knock from over-limit IP {ip} ({projected_hits}>{max_knocks})", flush=True)
    return True

def format_cred_summary(user, pw):
    if user is not None and pw is not None:
        return f"{user}:{pw}"
    if user is not None:
        return f"user={user}"
    if pw is not None:
        return f"pass={pw}"
    return "no-credentials"

def get_geo_enriched(ip, city_reader, asn_reader):
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

def add_to_blocklist(ip, r):
    """Append ip to blocklist.txt and add to Redis knock:blocked set."""
    try:
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"{ip}  # auto-blocked {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        r.sadd("knock:blocked", ip)
        print(f"🚫 Auto-blocked {ip}", flush=True)
    except Exception as e:
        print(f"⚠️ Could not write blocklist: {e}")

def monitor(save_knocks=False, max_knocks=None):
    init_db()
    r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)
    enabled_protocols = parse_enabled_protocols()
    publish_protocol_config(r, enabled_protocols)
    print(f"🧭 Enabled protocols: {', '.join(enabled_protocols)}", flush=True)
    while True:
        try:
            c_reader = geoip2.database.Reader(GEOIP_CITY_PATH)
            a_reader = geoip2.database.Reader(GEOIP_ASN_PATH)
            print("✅ GeoIP databases loaded")
            break
        except Exception as e:
            print(f"⏳ Waiting for GeoIP databases... ({e})")
            time.sleep(5)

    # Seed knock:blocked Redis set from blocklist file BEFORE spawning honeypots
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE) as f:
                ips = [line.split('#')[0].strip() for line in f if line.split('#')[0].strip()]
            if ips:
                r.sadd("knock:blocked", *ips)
            print(f"🚫 Loaded {len(ips)} blocked IP(s) into Redis (knock:blocked)")
        except Exception as e:
            print(f"⚠️ Could not load blocklist: {e}")

    # Seed Redis totals from SQLite on startup to stay in sync
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        total = conn.execute("SELECT SUM(hits) FROM ip_intel").fetchone()[0] or 0
        hb_row = conn.execute("SELECT * FROM monitor_heartbeats WHERE id=1").fetchone()
        hb_cols = [desc[0] for desc in conn.execute("SELECT * FROM monitor_heartbeats LIMIT 0").description] if hb_row else []
        uptime = 0
        proto_uptimes = {}
        if hb_row and hb_cols:
            col_map = dict(zip(hb_cols, hb_row))
            uptime = col_map.get('uptime_minutes', 0) or 0
            for proto_name in PROTO:
                col = f"uptime_{proto_name.lower()}"
                proto_uptimes[proto_name] = col_map.get(col, 0) or 0
        proto_rows = conn.execute("SELECT proto, SUM(hits) AS c FROM ip_intel_proto GROUP BY proto").fetchall()
        conn.close()
        r.set("knock:total_global", total)
        r.delete("knock:proto_counts")
        for proto_int, count in proto_rows:
            proto_name = PROTO_NAME.get(proto_int)
            if proto_name:
                r.hset("knock:proto_counts", proto_name, int(count))
        for proto_name in PROTO.keys():
            if not r.hexists("knock:proto_counts", proto_name):
                r.hset("knock:proto_counts", proto_name, 0)
        r.set("knock:uptime_minutes", uptime)
        for proto_name, proto_up in proto_uptimes.items():
            r.set(f"knock:uptime:{proto_name.lower()}", proto_up)
    except Exception as e:
        print(f"⚠️ Could not seed totals from SQLite: {e}")

    # Spawn enabled honeypots as subprocesses
    honeypots = {}
    for proto in enabled_protocols:
        script = PROTOCOL_META.get(proto, {}).get("honeypot_script")
        if not script:
            print(f"⚠️ No honeypot script configured for protocol {proto}; skipping", flush=True)
            continue
        extra_args = PROTOCOL_META.get(proto, {}).get("honeypot_args", [])
        honeypots[proto] = subprocess.Popen(
            [sys.executable, "-u", script] + extra_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if not honeypots:
        print("❌ No honeypots enabled after parsing ENABLED_PROTOCOLS", flush=True)
        sys.exit(1)

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

    threading.Thread(target=heartbeat_worker, args=(r, enabled_protocols), daemon=True).start()

    print("🚀 Knock-Knock Monitor Active...")

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
        if knock.get("type") == "SMTP_DIAG":
            store_smtp_diag(r, build_smtp_diag(knock))
            continue
        if knock.get("type") == "KNOCK":
            proto = str(knock.get("proto", "SSH")).upper()
            ip = knock["ip"]
            forensic = build_mail_forensic(knock, proto, ip)
            raw_user = knock.get("user")
            raw_pass = knock.get("pass")
            user = sanitize_credential(raw_user if isinstance(raw_user, str) else str(raw_user)) if proto in USER_PANEL_PROTOCOLS and raw_user is not None else None
            pw = sanitize_credential(raw_pass if isinstance(raw_pass, str) else str(raw_pass)) if proto in PASS_PANEL_PROTOCOLS and raw_pass is not None else None
            geo = get_geo_enriched(ip, c_reader, a_reader)
            package = {
                "ip": ip, "user": user, "pass": pw,
                "proto": proto,
                "city": geo['city'], "region": geo['region'], "country": geo['country'],
                "iso": geo['iso'], "isp": geo['isp'], "asn": geo['asn'],
                "lat": geo['lat'], "lng": geo['lng']
            }
            if user is None:
                package.pop("user")
            if pw is None:
                package.pop("pass")
            if knock.get("subject"):
                package["subject"] = sanitize_credential(str(knock["subject"]))
            if knock.get("body"):
                package["body"] = sanitize_body(knock.get("body"))
            if proto == "RDP":
                raw_domain = knock.get("domain")
                if raw_domain is not None:
                    domain = sanitize_credential(str(raw_domain))
                    if domain:
                        package["rdp_domain"] = domain
            # Pass through protocol-specific extended telemetry into Redis/websocket payloads.
            # This is intentionally not persisted in SQLite.
            for k, v in knock.items():
                if not isinstance(k, str) or not k.startswith(("sip_", "smtp_", "mail_", "smb_", "rdp_")):
                    continue
                if isinstance(v, str):
                    package[k] = sanitize_credential(v)
                elif isinstance(v, (int, float, bool)) or v is None:
                    package[k] = v
                else:
                    package[k] = sanitize_credential(str(v))
            try:
                package.update(get_intel_stats_before_update(package))
                projected_hits = int(package.get('ip_hits', 0) or 0)
                if is_over_limit_and_block(r, ip, projected_hits, max_knocks):
                    continue
                store_mail_forensic(r, forensic)
                log_to_enriched_db(package, save_knocks=save_knocks)
            except Exception as e:
                print(f"⚠️ DB error (knock dropped): {e}", flush=True)
                continue
            r.lpush("knock:recent", json.dumps(package))
            r.ltrim("knock:recent", 0, 99)
            proto_key = "knock:recent:" + package['proto'].lower()
            r.lpush(proto_key, json.dumps(package))
            r.ltrim(proto_key, 0, 99)
            r.incr("knock:total_global")
            r.hincrby("knock:proto_counts", package['proto'], 1)
            r.set("knock:last_time", int(time.time()))
            r.set(f"knock:last_time:{package['proto'].lower()}", int(time.time()))
            if geo['lat'] is not None:
                r.set("knock:last_lat", geo['lat'])
                r.set("knock:last_lng", geo['lng'])
            r.publish("radiation_stream", json.dumps(package))
            if package.get("subject"):
                left = user if user is not None else package.get("mail_from", package.get("smtp_mail_from", "<none>"))
                right = pw if pw is not None else package.get("mail_to", package.get("smtp_rcpt_to", "<none>"))
                print(f"📧 MAIL {geo['iso']} | {left} → {right} | {package['subject'][:60]} via {geo['isp']}")
            else:
                cred = format_cred_summary(user, pw)
                print(f"📡 {proto} {geo['iso']} | {cred} via {geo['isp']}")
            if max_knocks and int(package.get('ip_hits', 0) or 0) >= max_knocks and not r.sismember("knock:blocked", ip):
                add_to_blocklist(ip, r)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock Monitor")
    parser.add_argument("--reset-all", action="store_true", help="Delete DB and clear Redis")
    parser.add_argument("--save-knocks", action="store_true", help="Save individual knocks to SQLite (off by default)")
    parser.add_argument("--max-knocks", type=int, default=None, metavar="N",
                        help="Auto-add IP to blocklist after N knocks (default: disabled)")
    args = parser.parse_args()
    if args.reset_all: reset_all()
    monitor(save_knocks=args.save_knocks, max_knocks=args.max_knocks)

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

SOURCE_ID       = os.environ.get('SOURCE_ID', socket.gethostname().split('.')[0])
AGGREGATOR_HOST = os.environ.get('AGGREGATOR_HOST', '').strip()
AGGREGATOR_PORT = int(os.environ.get('AGGREGATOR_PORT', '9999'))
INGEST_PORT     = int(os.environ.get('INGEST_PORT', '0') or '0') or None

from constants import PROTO, PROTO_NAME, PROTOCOL_META, sort_protocols_for_ui

USER_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_user_panel')}
PASS_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_pass_panel')}
MAIL_FORENSICS_MAX = int(os.environ.get("MAIL_FORENSICS_MAX", "100"))

_DEFAULT_ENABLED_STR = 'SSH,TNET,FTP,RDP,SMB,SIP,SMTP:25,SMTP:587,HTTP:80,HTTP:443'

def parse_enabled_protocols():
    """
    Parse ENABLED_PROTOCOLS env var (e.g. 'SSH,SMTP:25,SMTP:587,HTTP:80') into:
      - names: ordered list of unique protocol names (for DB init, UI config, etc.)
      - entries: list of (proto, port_or_None) tuples (for spawning)
    Returns (names, entries).
    """
    raw = os.environ.get("ENABLED_PROTOCOLS", "").strip() or _DEFAULT_ENABLED_STR
    entries = []
    names = []
    for token in raw.split(','):
        token = token.strip().upper()
        if not token:
            continue
        if ':' in token:
            proto, port_str = token.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                print(f"⚠️ Ignoring malformed token in ENABLED_PROTOCOLS: {token}", flush=True)
                continue
        else:
            proto, port = token, None
        if proto not in PROTO:
            print(f"⚠️ Ignoring unknown protocol in ENABLED_PROTOCOLS: {proto}", flush=True)
            continue
        entries.append((proto, port))
        if proto not in names:
            names.append(proto)
    if not entries:
        print("⚠️ ENABLED_PROTOCOLS resolved to empty set; using defaults", flush=True)
        entries = []
        names = []
        for token in _DEFAULT_ENABLED_STR.split(','):
            proto, _, port_str = token.partition(':')
            port = int(port_str) if port_str else None
            entries.append((proto, port))
            if proto not in names:
                names.append(proto)
    return names, entries

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

def _registrable_domain(host):
    host = (host or '').strip().lower().rstrip('.')
    if not host or '.' not in host:
        return None
    labels = [part for part in host.split('.') if part]
    if len(labels) < 2:
        return None
    # Heuristic for common ccTLD second-level patterns (e.g. example.co.uk).
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac'}:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])

def _discover_self_identifiers():
    ips = set()
    hosts = set()
    host_suffixes = set()

    # Explicit operator-provided redaction inputs.
    for v in os.environ.get('REDACT_SELF_IPS', '').split(','):
        v = v.strip()
        if v:
            ips.add(v)
    for v in os.environ.get('REDACT_SELF_HOSTS', '').split(','):
        v = v.strip().lower()
        if v:
            hosts.add(v)
    for key in ('REDACT_SELF_DOMAINS', 'REDACT_SELF_HOST_SUFFIXES'):
        for v in os.environ.get(key, '').split(','):
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

    # Derive registrable domains from discovered hostnames/PTRs by default.
    for host in list(hosts):
        domain = _registrable_domain(host)
        if domain:
            host_suffixes.add(domain)

    return ips, hosts, host_suffixes

def _build_self_redaction_patterns():
    ips, hosts, host_suffixes = _discover_self_identifiers()
    pats = []
    # Hostnames first, then domains, then IPs to avoid partial overlap artifacts.
    for host in sorted(hosts, key=len, reverse=True):
        pats.append((re.compile(re.escape(host), re.IGNORECASE), "<target-host>"))
    for suffix in sorted(host_suffixes, key=len, reverse=True):
        pats.append((
            re.compile(rf"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]+\.)*{re.escape(suffix)}(?![A-Za-z0-9_-])", re.IGNORECASE),
            "<target-domain>",
        ))
    # Longest-first replacement avoids partial overlap artifacts.
    for ip in sorted(ips, key=len, reverse=True):
        pats.append((re.compile(re.escape(ip)), "<target-ip>"))
        # Common dash-notation seen in hostnames (e.g. 1-2-3-4.example.tld).
        dashed = ip.replace('.', '-')
        if dashed != ip:
            pats.append((re.compile(re.escape(dashed), re.IGNORECASE), "<target-ip>"))
    return pats

SELF_REDACTION_PATTERNS = _build_self_redaction_patterns()

# --- Per-protocol knock table definitions ---
# Common columns for all knock tables (after id and timestamp)
_COMMON_KNOCK_COLS = [
    'ip_address TEXT', 'iso_code TEXT', 'city TEXT', 'region TEXT',
    'country TEXT', 'isp TEXT', 'asn TEXT', 'source INTEGER DEFAULT 0',
]

# Protocol-specific extra columns
_KNOCK_EXTRA_COLS = {
    'SSH':  ['username TEXT', 'password TEXT'],
    'TNET': ['username TEXT', 'password TEXT'],
    'FTP':  ['username TEXT', 'password TEXT'],
    'SMTP': ['username TEXT', 'password TEXT', 'smtp_port INTEGER', 'smtp_stage TEXT',
             'smtp_mail_from TEXT', 'smtp_rcpt_to TEXT',
             'subject TEXT', 'body TEXT'],
    'HTTP': ['http_port INTEGER', 'http_method TEXT', 'http_path TEXT', 'http_purpose TEXT',
             'http_exploit TEXT', 'http_host TEXT', 'http_user_agent TEXT', 'http_body TEXT'],
    'SIP':  ['sip_method TEXT', 'sip_dial_string TEXT', 'sip_dial_number TEXT',
             'sip_call_id TEXT', 'sip_cseq TEXT', 'sip_extension TEXT',
             'sip_dial_country TEXT', 'sip_dial_country_name TEXT',
             'sip_dial_lat REAL', 'sip_dial_lng REAL'],
    'SMB':  ['username TEXT', 'smb_action TEXT', 'smb_share TEXT', 'smb_file TEXT',
             'smb_version TEXT', 'smb_domain TEXT', 'smb_host TEXT'],
    'RDP':  ['username TEXT', 'rdp_source TEXT', 'domain TEXT', 'rdp_workstation TEXT'],
}

# Maps JSON knock data keys -> column names for common fields
_COMMON_KEY_MAP = [
    ('ip', 'ip_address'), ('iso', 'iso_code'), ('city', 'city'),
    ('region', 'region'), ('country', 'country'), ('isp', 'isp'), ('asn', 'asn'),
    ('source_int', 'source'),
]

# Maps JSON knock data keys -> column names for protocol-specific fields
_PROTO_KEY_MAP = {
    'SSH':  [('user', 'username'), ('pass', 'password')],
    'TNET': [('user', 'username'), ('pass', 'password')],
    'FTP':  [('user', 'username'), ('pass', 'password')],
    'SMTP': [('user', 'username'), ('pass', 'password'), ('smtp_port', 'smtp_port'),
             ('smtp_stage', 'smtp_stage'),
             ('smtp_mail_from', 'smtp_mail_from'), ('smtp_rcpt_to', 'smtp_rcpt_to'),
             ('subject', 'subject'), ('body', 'body')],
    'HTTP': [('http_port', 'http_port'), ('http_method', 'http_method'), ('http_path', 'http_path'),
             ('http_purpose', 'http_purpose'), ('http_exploit', 'http_exploit'),
             ('http_host', 'http_host'), ('http_user_agent', 'http_user_agent'),
             ('http_body', 'http_body')],
    'SIP':  [('sip_method', 'sip_method'), ('sip_dial_string', 'sip_dial_string'),
             ('sip_dial_number', 'sip_dial_number'), ('sip_call_id', 'sip_call_id'),
             ('sip_cseq', 'sip_cseq'), ('sip_extension', 'sip_extension'),
             ('sip_dial_country', 'sip_dial_country'), ('sip_dial_country_name', 'sip_dial_country_name'),
             ('sip_dial_lat', 'sip_dial_lat'), ('sip_dial_lng', 'sip_dial_lng')],
    'SMB':  [('user', 'username'), ('smb_action', 'smb_action'), ('smb_share', 'smb_share'),
             ('smb_file', 'smb_file'), ('smb_version', 'smb_version'),
             ('smb_domain', 'smb_domain'), ('smb_host', 'smb_host')],
    'RDP':  [('user', 'username'), ('rdp_source', 'rdp_source'), ('domain', 'domain'), ('rdp_workstation', 'rdp_workstation')],
}

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

def init_db(save_protos=None, enabled_protocols=None):
    """save_protos: None=all, False/empty=none, set=specific protocols"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    # Migrate old generic knocks table -> per-protocol tables (before creating new tables)
    # Old schema only had username+password (no protocol-specific fields), so only
    # SSH/TNET/FTP rows (user+pass protocols) get meaningful data. Non-user/pass
    # protocols (SIP, etc.) had their specific fields discarded by the old schema.
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='knocks'")
    if cur.fetchone():
        # Check if proto column exists (v2) or not (v1 = all SSH)
        knock_cols = [row[1] for row in cur.execute("PRAGMA table_info(knocks)").fetchall()]
        has_proto = 'proto' in knock_cols
        # Migrate each protocol's rows to its per-protocol table
        _user_pass_protos = {'SSH': 0, 'TNET': 1, 'FTP': 5}
        migrated = 0
        for pname, pidx in _user_pass_protos.items():
            if has_proto:
                where = f"WHERE proto = {pidx}"
            else:
                where = "" if pname == 'SSH' else "WHERE 0"  # v1 = all SSH
            cur.execute(f"SELECT COUNT(*) FROM knocks {where}")
            count = cur.fetchone()[0]
            if count == 0:
                continue
            table = f"knocks_{pname.lower()}"
            extra_cols = _KNOCK_EXTRA_COLS[pname]
            cols_def = ['id INTEGER PRIMARY KEY AUTOINCREMENT',
                        "timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))"]
            cols_def += _COMMON_KNOCK_COLS + extra_cols
            cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols_def)})")
            cur.execute(f"""INSERT INTO {table} (timestamp, ip_address, iso_code, city, region, country, isp, asn, username, password)
                            SELECT timestamp, ip_address, iso_code, city, region, country, isp, asn, username, password FROM knocks {where}""")
            migrated += cur.rowcount
        conn.commit()
        if migrated > 0:
            print(f"✅ Migrated {migrated} rows from knocks → per-protocol tables", file=sys.stderr)
        cur.execute("DROP TABLE knocks")
        conn.commit()
    # Create per-protocol knock tables (only for protocols being saved)
    if save_protos is None:
        protos_to_create = list(_KNOCK_EXTRA_COLS.keys())
    elif save_protos:
        protos_to_create = [p for p in save_protos if p in _KNOCK_EXTRA_COLS]
    else:
        protos_to_create = []
    for proto_name in protos_to_create:
        extra_cols = _KNOCK_EXTRA_COLS[proto_name]
        table = f"knocks_{proto_name.lower()}"
        cols = ['id INTEGER PRIMARY KEY AUTOINCREMENT',
                "timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))"]
        cols += _COMMON_KNOCK_COLS + extra_cols
        cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)})")
    cur.execute("CREATE TABLE IF NOT EXISTS user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL)")
    if enabled_protocols and 'SIP' in enabled_protocols:
        cur.execute("""CREATE TABLE IF NOT EXISTS dial_intel
            (number TEXT PRIMARY KEY, hits INTEGER, first_seen DATETIME, last_seen DATETIME,
             country TEXT, country_name TEXT, lat REAL, lng REAL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS sources (
        id           INTEGER PRIMARY KEY,
        source_id    TEXT UNIQUE NOT NULL,
        display_name TEXT,
        hits         INTEGER NOT NULL DEFAULT 0,
        first_seen   DATETIME,
        last_seen    DATETIME,
        active       INTEGER NOT NULL DEFAULT 1
    )""")
    # Local machine is always id=0
    cur.execute("INSERT OR IGNORE INTO sources (id, source_id) VALUES (0, ?)", (SOURCE_ID,))
    # Migrate existing sources rows that predate hits/last_seen columns
    _src_cols = [row[1] for row in cur.execute("PRAGMA table_info(sources)").fetchall()]
    if 'hits' not in _src_cols:
        cur.execute("ALTER TABLE sources ADD COLUMN hits INTEGER NOT NULL DEFAULT 0")
    if 'first_seen' not in _src_cols:
        cur.execute("ALTER TABLE sources ADD COLUMN first_seen DATETIME")
    if 'last_seen' not in _src_cols:
        cur.execute("ALTER TABLE sources ADD COLUMN last_seen DATETIME")
    if 'active' not in _src_cols:
        cur.execute("ALTER TABLE sources ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    # Add source column to any existing knock tables that predate this feature
    for _tname in [f"knocks_{p.lower()}" for p in _KNOCK_EXTRA_COLS]:
        try:
            _tcols = [row[1] for row in cur.execute(f"PRAGMA table_info({_tname})").fetchall()]
            if _tcols and 'source' not in _tcols:
                cur.execute(f"ALTER TABLE {_tname} ADD COLUMN source INTEGER DEFAULT 0")
        except Exception:
            pass
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
    _seed_uptime_cols = False
    for proto_name in PROTO:
        col = f"uptime_{proto_name.lower()}"
        if col not in hb_cols:
            cur.execute(f"ALTER TABLE monitor_heartbeats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            added_uptime_cols = True
    if added_uptime_cols:
        _seed_uptime_cols = True  # deferred until after proto tables are created
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
    # Seed per-protocol uptime columns (deferred from above — must run after proto tables are populated)
    if _seed_uptime_cols:
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
    cur.execute("PRAGMA journal_mode=WAL")
    cur.fetchone()  # consume PRAGMA result to avoid "statements in progress" error
    conn.commit()
    conn.close()

def _load_sources(conn):
    """Load sources table. Returns (encode, decode, hits):
       encode: {source_id → id}
       decode: {id → display_label}
       hits:   {source_id → hits}
    """
    rows = conn.execute("SELECT id, source_id, display_name, hits FROM sources").fetchall()
    encode = {row[1]: row[0] for row in rows}
    decode  = {row[0]: row[2] or row[1] for row in rows}  # display_name if set, else source_id
    hits    = {row[1]: row[3] or 0 for row in rows}
    return encode, decode, hits

def _ensure_source(source_id, encode, decode):
    """Return integer id for source_id, registering a new row if first seen."""
    if source_id in encode:
        return encode[source_id]
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute("INSERT OR IGNORE INTO sources (source_id) VALUES (?)", (source_id,))
        conn.commit()
        new_id = conn.execute("SELECT id FROM sources WHERE source_id=?", (source_id,)).fetchone()[0]
    finally:
        conn.close()
    encode[source_id] = new_id
    decode[new_id] = source_id
    print(f"[INGEST] Registered new source: {source_id!r} → id={new_id}", flush=True)
    return new_id

_forward_queue = queue.Queue(maxsize=500)

def _start_forward_worker():
    def _worker():
        while True:
            sock = None
            try:
                sock = socket.create_connection((AGGREGATOR_HOST, AGGREGATOR_PORT), timeout=10)
                print(f"[FORWARD] Connected to {AGGREGATOR_HOST}:{AGGREGATOR_PORT}", flush=True)
                while True:
                    knock = _forward_queue.get()
                    sock.sendall((json.dumps(knock) + '\n').encode())
            except Exception as e:
                print(f"[FORWARD] {e}", flush=True)
            finally:
                if sock:
                    try: sock.close()
                    except: pass
            time.sleep(5)
    threading.Thread(target=_worker, daemon=True).start()

def _start_ingest_server(knock_queue):
    def _handler(conn):
        try:
            with conn.makefile('r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        knock_queue.put(line)
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    def _server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', INGEST_PORT))
        srv.listen(20)
        print(f"[INGEST] Listening on port {INGEST_PORT}", flush=True)
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handler, args=(conn,), daemon=True).start()
            except Exception as e:
                print(f"[INGEST] Accept error: {e}", flush=True)

    threading.Thread(target=_server, daemon=True).start()

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

def log_to_enriched_db(data, save_protos=None):
    """save_protos: None=save all, False=save none, set=save only those protos"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    try:
        proto_name = data.get('proto', 'SSH')
        should_save = (save_protos is None or
                       (save_protos and proto_name in save_protos))
        if should_save and proto_name in _PROTO_KEY_MAP:
            table = f"knocks_{proto_name.lower()}"
            col_names = [col for _, col in _COMMON_KEY_MAP]
            values = [data.get(key) for key, _ in _COMMON_KEY_MAP]
            for key, col in _PROTO_KEY_MAP[proto_name]:
                col_names.append(col)
                values.append(data.get(key))
            placeholders = ', '.join(['?'] * len(col_names))
            cur.execute(f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({placeholders})", values)
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
        dial_number = data.get('sip_dial_number')
        if dial_number:
            cur.execute("""INSERT INTO dial_intel VALUES (?, 1, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(number) DO UPDATE SET hits=hits+1, last_seen=?, country_name=?""",
                        (dial_number, now, now, data.get('sip_dial_country'), data.get('sip_dial_country_name'),
                         data.get('sip_dial_lat'), data.get('sip_dial_lng'), now, data.get('sip_dial_country_name')))
        src_id = data.get('source', SOURCE_ID)
        cur.execute("""INSERT INTO sources (source_id, hits, first_seen, last_seen)
                       VALUES (?, 1, ?, ?)
                       ON CONFLICT(source_id) DO UPDATE SET
                           hits=hits+1,
                           first_seen=COALESCE(first_seen, excluded.first_seen),
                           last_seen=excluded.last_seen""",
                    (src_id, now, now))
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
    label = f"SMTP{diag.get('smtp_port', 25)}"
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

def is_over_limit_and_block(redis_conn, ip, projected_hits, proto_hits, proto, max_knocks):
    if not max_knocks:
        return False
    if proto in max_knocks:
        limit = max_knocks[proto]
    else:
        limit = max_knocks.get(None)
    if not limit:
        return False
    hits = proto_hits if proto in max_knocks else projected_hits
    if hits <= limit:
        return False
    if not redis_conn.sismember("knock:blocked", ip):
        add_to_blocklist(ip, redis_conn, proto=proto, knock_count=hits)
    print(f"⛔ Dropped knock from over-limit IP {ip} ({hits}>{limit} {proto})", flush=True)
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

def add_to_blocklist(ip, r, proto=None, knock_count=None):
    """Append ip to blocklist.txt and add to Redis knock:blocked set."""
    try:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        proto_label = (proto or 'UNKNOWN').upper()
        count_label = int(knock_count) if knock_count is not None else '?'
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"{ip}  # autoblocked {ts}, {proto_label}, {count_label}\n")
        r.sadd("knock:blocked", ip)
        print(f"🚫 Auto-blocked {ip}", flush=True)
    except Exception as e:
        print(f"⚠️ Could not write blocklist: {e}")

def monitor(save_knocks=None, max_knocks=None):
    # Parse save_knocks: None from no flag, 'ALL' from bare --save-knocks, 'SIP,SMTP' from --save-knocks=SIP,SMTP
    if save_knocks == 'ALL':
        save_protos = None  # None means save all
    elif save_knocks:
        save_protos = set(p.strip().upper() for p in save_knocks.split(','))
    else:
        save_protos = False  # --save-knocks not passed at all
    enabled_protocols, proto_entries = parse_enabled_protocols()
    # Intersect save_protos with enabled protocols — never create tables for disabled protocols
    if save_protos is None:
        save_protos = set(enabled_protocols)
    elif save_protos:
        save_protos = save_protos & set(enabled_protocols)
    init_db(save_protos=save_protos, enabled_protocols=enabled_protocols)
    r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)
    publish_protocol_config(r, enabled_protocols)
    entry_strs = [f"{p}:{port}" if port else p for p, port in proto_entries]
    print(f"🧭 Enabled protocols: {', '.join(entry_strs)}", flush=True)
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
        source_rows = conn.execute("SELECT source_id, hits FROM sources").fetchall()
        conn.close()
        r.set("knock:total_global", total)
        r.delete("knock:proto_counts")
        for proto_int, count in proto_rows:
            proto_name = PROTO_NAME.get(proto_int)
            if proto_name:
                r.hset("knock:proto_counts", proto_name, int(count))
        r.delete("knock:source_counts")
        for src_id, src_hits in source_rows:
            r.hset("knock:source_counts", src_id, int(src_hits or 0))
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
    for proto, port_override in proto_entries:
        meta = PROTOCOL_META.get(proto, {})
        script = meta.get("honeypot_script")
        if not script:
            print(f"⚠️ No honeypot script configured for protocol {proto}; skipping", flush=True)
            continue
        args = list(meta.get("honeypot_args", []))
        if port_override is not None:
            if '--port' in args:
                args[args.index('--port') + 1] = str(port_override)
            else:
                args = ['--port', str(port_override)] + args
        key = f"{proto}_{port_override}" if port_override is not None else proto
        honeypots[key] = subprocess.Popen(
            [sys.executable, "-u", script] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if not honeypots:
        print("❌ No honeypots enabled after parsing ENABLED_PROTOCOLS", flush=True)
        sys.exit(1)

    knock_queue = queue.Queue()

    # Load sources dimension dict (used in main loop — single-threaded, no lock needed)
    _sc = sqlite3.connect(DB_PATH, timeout=10)
    _src_encode, _src_decode, _src_hits = _load_sources(_sc)
    _sc.close()

    if AGGREGATOR_HOST:
        _start_forward_worker()
        print(f"[FORWARD] Feeder mode → {AGGREGATOR_HOST}:{AGGREGATOR_PORT} as source={SOURCE_ID!r}", flush=True)

    if INGEST_PORT:
        _start_ingest_server(knock_queue)
        r.set("knock:is_aggregator", "1")

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
        # Feeder: forward raw knock to aggregator before local enrichment
        if AGGREGATOR_HOST and knock.get('type') == 'KNOCK':
            try:
                _forward_queue.put_nowait({**knock, 'source': SOURCE_ID})
            except queue.Full:
                pass
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
                        package["domain"] = domain
            # Source tagging — integer for SQLite, string+display for Redis/WebSocket
            _src_id = knock.get('source', SOURCE_ID)
            package['source_int']     = _ensure_source(_src_id, _src_encode, _src_decode)
            package['source']         = _src_id
            package['source_display'] = _src_decode.get(package['source_int'], _src_id)
            # Pass through protocol-specific extended telemetry into Redis/websocket payloads.
            # This is intentionally not persisted in SQLite.
            for k, v in knock.items():
                if not isinstance(k, str) or not k.startswith(("sip_", "smtp_", "mail_", "smb_", "rdp_", "http_")):
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
                proto_hits = int(package.get('ip_hits_proto', 0) or 0)
                if is_over_limit_and_block(r, ip, projected_hits, proto_hits, proto, max_knocks):
                    continue
                store_mail_forensic(r, forensic)
                log_to_enriched_db(package, save_protos=save_protos)
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
            r.hincrby("knock:source_counts", package['source'], 1)
            r.set("knock:last_time", int(time.time()))
            r.set(f"knock:last_time:{package['proto'].lower()}", int(time.time()))
            if geo['lat'] is not None:
                r.set("knock:last_lat", geo['lat'])
                r.set("knock:last_lng", geo['lng'])
            r.publish("knocks_stream", json.dumps(package))
            if package.get("subject"):
                left = user if user is not None else package.get("mail_from", package.get("smtp_mail_from", "<none>"))
                right = pw if pw is not None else package.get("mail_to", package.get("smtp_rcpt_to", "<none>"))
                print(f"📧 MAIL {geo['iso']} | {left} → {right} | {package['subject'][:60]} via {geo['isp']}")
            elif proto == 'SIP' and package.get('sip_dial_number'):
                dial_raw = package.get('sip_dial_string', '')
                dial_e164 = package.get('sip_dial_number', '')
                dial_dest = package.get('sip_dial_country_name', '')
                print(f"📡 SIP {geo['iso']} | {dial_raw} → {dial_e164} → {dial_dest} via {geo['isp']}")
            else:
                cred = format_cred_summary(user, pw)
                print(f"📡 {proto} {geo['iso']} | {cred} via {geo['isp']}")
            if max_knocks and not r.sismember("knock:blocked", ip):
                limit = max_knocks.get(proto) or max_knocks.get(None)
                hits = proto_hits if proto in max_knocks else projected_hits
                if limit and hits >= limit:
                    add_to_blocklist(ip, r, proto=proto, knock_count=hits)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock Monitor")
    parser.add_argument("--reset-all", action="store_true", help="Delete DB and clear Redis")
    parser.add_argument("--save-knocks", nargs='?', const='ALL', default=None, metavar='PROTOS',
                        help="Save individual knocks to SQLite. Optional: comma-separated protocols (e.g. SIP,SMTP). Default: ALL")
    parser.add_argument("--max-knocks", default=None, metavar="LIMIT",
                        help="Auto-block IP after N knocks. Examples: 5000, RDP:500, 5000,RDP:500,SIP:NONE")
    args = parser.parse_args()
    if args.reset_all: reset_all()
    # Parse --max-knocks: "5000" → {None: 5000}, "RDP:500" → {'RDP': 500}, "5000,RDP:500" → {None: 5000, 'RDP': 500}
    max_knocks = None
    if args.max_knocks:
        max_knocks = {}
        for part in args.max_knocks.split(','):
            part = part.strip()
            if ':' in part:
                proto_name, val = part.split(':', 1)
                val = val.strip().upper()
                max_knocks[proto_name.strip().upper()] = None if val == 'NONE' else int(val)
            else:
                max_knocks[None] = int(part)
    monitor(save_knocks=args.save_knocks, max_knocks=max_knocks)

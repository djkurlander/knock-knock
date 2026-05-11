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
import importlib
from datetime import datetime, timezone
from dataclasses import dataclass

# --- Configuration ---
GEOIP_CITY_PATH = '/usr/share/GeoIP/GeoLite2-City.mmdb'
GEOIP_ASN_PATH = '/usr/share/GeoIP/GeoLite2-ASN.mmdb'
DB_PATH = os.environ.get('DB_DIR', 'data') + '/knock_knock.db'

TRACE_KNOCK     = os.environ.get('TRACE_KNOCK', '').lower()  # 'true' or 'verbose'
REDIS_DB        = int(os.environ.get('REDIS_DB', '0'))
SOURCE_ID       = os.environ.get('SOURCE_ID', socket.gethostname().split('.')[0])
AGGREGATOR_HOST = os.environ.get('AGGREGATOR_HOST', '').strip()
AGGREGATOR_PORT = int(os.environ.get('AGGREGATOR_PORT', '9999'))
INGEST_PORT     = int(os.environ.get('INGEST_PORT', '0') or '0') or None

from constants import PROTO, PROTO_NAME, PROTOCOL_META, sort_protocols_for_ui

USER_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_user_panel')}
PASS_PANEL_PROTOCOLS = {name for name, meta in PROTOCOL_META.items() if meta.get('supports_pass_panel')}


_DEFAULT_ENABLED_STR = 'SSH,TNET,FTP,RDP,SMB,SIP,SMTP:25,SMTP:587,HTTP:80,HTTP:443'
_UNKNOWN_PROTO_WARNED = set()
_read_conn = None


@dataclass(frozen=True)
class ProtocolEntry:
    proto: str
    port: int | None = None
    options: tuple[str, ...] = ()

    def label(self):
        parts = [self.proto]
        if self.port is not None:
            parts.append(str(self.port))
        parts.extend(self.options)
        return ':'.join(parts)


def _protocol_options(proto):
    definition = (PROTOCOL_META.get(proto) or {}).get('definition')
    if not definition:
        return set()
    return set(definition.option_args) | set(definition.option_env)


def _parse_protocol_entry(token):
    parts = [part.strip().upper() for part in token.split(':')]
    if not parts or not parts[0]:
        return None
    proto = parts[0]
    if proto not in PROTO:
        print(f"⚠️ Ignoring unknown protocol in ENABLED_PROTOCOLS: {proto}", flush=True)
        return None
    port = None
    option_start = 1
    if len(parts) > 1 and parts[1]:
        try:
            port = int(parts[1])
        except ValueError:
            print(f"⚠️ Ignoring malformed token in ENABLED_PROTOCOLS: {token}", flush=True)
            return None
        option_start = 2
    options = tuple(part for part in parts[option_start:] if part)
    allowed = _protocol_options(proto)
    bad_options = [opt for opt in options if opt not in allowed]
    if bad_options:
        print(
            f"⚠️ Ignoring token with unsupported option(s) in ENABLED_PROTOCOLS: "
            f"{token} ({proto}: {', '.join(bad_options)})",
            flush=True,
        )
        return None
    return ProtocolEntry(proto, port, options)


def _parse_enabled_token(token):
    parts = [part.strip().upper() for part in token.split(':')]
    if len(parts) == 1 and parts[0]:
        definition = (PROTOCOL_META.get(parts[0]) or {}).get('definition')
        if definition and definition.default_enabled_entries:
            return [
                entry
                for default_token in definition.default_enabled_entries
                for entry in [_parse_protocol_entry(default_token)]
                if entry
            ]
    entry = _parse_protocol_entry(token)
    return [entry] if entry else []


def _apply_port_arg(args, port):
    if port is None:
        return args
    args = list(args)
    if '--port' in args:
        args[args.index('--port') + 1] = str(port)
    else:
        args = ['--port', str(port)] + args
    return args


def _spawn_config(entry):
    meta = PROTOCOL_META.get(entry.proto, {})
    definition = meta.get('definition')
    script = meta.get("honeypot_script")
    args = list(meta.get("honeypot_args", []))
    env = None

    if definition:
        script = definition.honeypot_script
        args = list(definition.honeypot_args)
        env_updates = dict(definition.honeypot_env)
        for option in entry.options:
            args.extend(definition.option_args.get(option, []))
            env_updates.update(definition.option_env.get(option, {}))
        if env_updates:
            env = os.environ.copy()
            env.update(env_updates)

    return script, _apply_port_arg(args, entry.port), env


def _warn_unknown_proto(proto, ip=None, source=None):
    if proto in _UNKNOWN_PROTO_WARNED:
        return
    _UNKNOWN_PROTO_WARNED.add(proto)
    detail = f" proto={proto!r}"
    if ip:
        detail += f" ip={ip}"
    if source:
        detail += f" source={source!r}"
    print(f"⚠️ Dropping knock for unknown protocol:{detail}", flush=True)


def parse_enabled_protocols():
    """
    Parse ENABLED_PROTOCOLS env var (e.g. 'SSH,SMTP:25,MQTT:8883:TLS') into:
      - names: ordered list of unique protocol names (for DB init, UI config, etc.)
      - entries: list of ProtocolEntry objects (for spawning)
    Returns (names, entries).
    """
    raw_env = os.environ.get("ENABLED_PROTOCOLS")  # None=unset, ""=explicitly empty
    if raw_env is not None and raw_env.strip() == '':
        # Explicitly set to empty — pure ingest mode, no local honeypots
        print("🔌 ENABLED_PROTOCOLS='' — ingest-only mode, no local honeypots will be spawned", flush=True)
        return [], []
    raw = raw_env.strip() if raw_env else _DEFAULT_ENABLED_STR
    entries = []
    names = []
    for token in raw.split(','):
        token = token.strip()
        if not token:
            continue
        for entry in _parse_enabled_token(token):
            entries.append(entry)
            if entry.proto not in names:
                names.append(entry.proto)
    if not entries:
        print("⚠️ ENABLED_PROTOCOLS resolved to empty set; using defaults", flush=True)
        entries = []
        names = []
        for token in _DEFAULT_ENABLED_STR.split(','):
            entry = _parse_protocol_entry(token)
            if not entry:
                continue
            entries.append(entry)
            if entry.proto not in names:
                names.append(entry.proto)
    return names, entries

def publish_protocol_config(redis_conn, enabled_protocols):
    enabled = sort_protocols_for_ui([p for p in enabled_protocols if p in PROTO])
    meta = {}
    for name in PROTO.keys():
        base = PROTOCOL_META.get(name, {})
        definition = base.get("definition")
        meta[name] = {
            "proto_int": PROTO.get(name),
            "enabled": name in enabled,
            "supports_user_panel": bool(base.get("supports_user_panel", False)),
            "supports_pass_panel": bool(base.get("supports_pass_panel", False)),
            "color": base.get("color", "#ffcc00"),
            "badge": base.get("badge", name),
            "description": base.get("description", ""),
            "ports_label": base.get("ports_label", ""),
        }
        if definition:
            meta[name]["display_fields"] = [
                {"key": f.key, "label": f.label, "format": f.format}
                for f in definition.display_fields
            ]
            meta[name]["display_formats"] = definition.display_formats
            if definition.display_format_field:
                meta[name]["display_format_field"] = definition.display_format_field
            if definition.default_display_format:
                meta[name]["default_display_format"] = definition.default_display_format
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

# Common columns for all knock tables (after id and timestamp)
_COMMON_KNOCK_COLS = [
    'ip_address TEXT', 'iso_code TEXT', 'city TEXT', 'region TEXT',
    'country TEXT', 'isp TEXT', 'asn TEXT', 'source INTEGER DEFAULT 0',
]

# Maps JSON knock data keys -> column names for common fields
_COMMON_KEY_MAP = [
    ('ip', 'ip_address'), ('iso', 'iso_code'), ('city', 'city'),
    ('region', 'region'), ('country', 'country'), ('isp', 'isp'), ('asn', 'asn'),
    ('source_int', 'source'),
]

_SQL_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _sql_ident(name):
    if not _SQL_IDENT_RE.fullmatch(str(name or '')):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return str(name)


def _registered_saved_definitions(save_protos):
    for proto, meta in PROTOCOL_META.items():
        definition = meta.get('definition')
        if definition and definition.knock_table and (save_protos is None or (save_protos and proto in save_protos)):
            yield proto, definition


def _column_sql(column):
    return f"{_sql_ident(column.name)} {column.type}"


def _registered_knock_mapping(proto_name):
    definition = (PROTOCOL_META.get(proto_name) or {}).get('definition')
    if not definition or not definition.knock_table:
        return None
    field_map = [(column.name, column.name) for column in definition.columns]
    overrides = {mapped.column: mapped.source for mapped in definition.field_map}
    return definition.knock_table, [(overrides.get(col, key), col) for key, col in field_map]


def _build_passthrough_policies():
    out = {}
    for proto, meta in PROTOCOL_META.items():
        definition = meta.get('definition')
        if not definition:
            continue
        fields = {}
        for item in definition.passthrough_fields:
            fields[item if isinstance(item, str) else item.key] = item
        out[proto] = (fields, tuple(definition.passthrough_prefixes))
    return out


_PASSTHROUGH_POLICIES = _build_passthrough_policies()


def _resolve_hook(path):
    if not path:
        return None
    module_name, sep, func_name = path.partition(':')
    if not sep or not module_name or not func_name:
        raise ValueError(f"Invalid hook path: {path!r}")
    func = getattr(importlib.import_module(module_name), func_name)
    if not callable(func):
        raise ValueError(f"Hook is not callable: {path!r}")
    return func


def _build_hooks():
    hooks = {}
    for proto, meta in PROTOCOL_META.items():
        definition = meta.get('definition')
        if not definition:
            continue
        process = _resolve_hook(definition.process_knock)
        db_update = _resolve_hook(definition.db_update)
        after = _resolve_hook(definition.after_save)
        if process or db_update or after:
            hooks[proto] = {'process': process, 'db_update': db_update, 'after_save': after}
    return hooks


_PROTOCOL_HOOKS = _build_hooks()


def _hook_context(proto):
    return {'proto': proto, 'db_path': DB_PATH, 'source_id': SOURCE_ID}


def _process_knock_hook(proto, knock):
    hook = (_PROTOCOL_HOOKS.get(proto) or {}).get('process')
    if not hook:
        return knock
    try:
        return hook(knock, _hook_context(proto))
    except Exception as e:
        print(f"⚠️ process_knock hook failed for {proto}; dropping knock: {e}", flush=True)
        return None


def _after_save_hook(proto, knock, package):
    hook = (_PROTOCOL_HOOKS.get(proto) or {}).get('after_save')
    if not hook:
        return
    try:
        hook(knock, package, _hook_context(proto))
    except Exception as e:
        print(f"⚠️ after_save hook failed for {proto}: {e}", flush=True)


def _db_update_hook(proto, data, cur, now):
    hook = (_PROTOCOL_HOOKS.get(proto) or {}).get('db_update')
    if not hook:
        return
    ctx = _hook_context(proto)
    ctx['now'] = now
    try:
        hook(data, cur, ctx)
    except Exception as e:
        print(f"⚠️ db_update hook failed for {proto}: {e}", flush=True)


def _registered_passthrough_items(knock):
    policy = _PASSTHROUGH_POLICIES.get(str(knock.get('proto', '')).upper())
    if not policy:
        return []
    fields, prefixes = policy
    items = []
    for key, value in knock.items():
        if key in fields:
            items.append((key, value, fields[key]))
        elif prefixes and isinstance(key, str) and key.startswith(prefixes):
            items.append((key, value, None))
    return items


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
        r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=REDIS_DB, decode_responses=True)
        preserve = {'knock:alerted:'}
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
    cur.execute("PRAGMA journal_mode=WAL")
    cur.fetchone()
    for _, definition in _registered_saved_definitions(save_protos):
        table = _sql_ident(definition.knock_table)
        proto_cols = [_column_sql(column) for column in definition.columns]
        cols = ['id INTEGER PRIMARY KEY AUTOINCREMENT',
                "timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))"]
        cols += _COMMON_KNOCK_COLS + proto_cols
        cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)})")
    for proto in (enabled_protocols or []):
        definition = (PROTOCOL_META.get(proto) or {}).get('definition')
        if not definition:
            continue
        for extra in definition.extra_tables:
            extra_table = _sql_ident(extra.name)
            extra_cols = [_column_sql(column) for column in extra.columns]
            cur.execute(f"CREATE TABLE IF NOT EXISTS {extra_table} ({', '.join(extra_cols)})")
    cur.execute("CREATE TABLE IF NOT EXISTS user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME)")
    cur.execute("CREATE TABLE IF NOT EXISTS isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER)")
    cur.execute("""CREATE TABLE IF NOT EXISTS ip_intel (
        ip TEXT PRIMARY KEY,
        hits INTEGER,
        last_seen DATETIME,
        lat REAL,
        lng REAL,
        hits_since_cleared INTEGER NOT NULL DEFAULT 0,
        ban_until INTEGER,
        ban_count INTEGER NOT NULL DEFAULT 0
    )""")
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
    enabled_protocols = enabled_protocols or []
    hb_cols = ['id INTEGER PRIMARY KEY', 'uptime_minutes INTEGER NOT NULL DEFAULT 0']
    hb_cols += [f"uptime_{proto_name.lower()} INTEGER NOT NULL DEFAULT 0" for proto_name in enabled_protocols]
    cur.execute(f"CREATE TABLE IF NOT EXISTS monitor_heartbeats ({', '.join(hb_cols)})")
    hb_existing = {row[1] for row in cur.execute("PRAGMA table_info(monitor_heartbeats)").fetchall()}
    for proto_name in enabled_protocols:
        col = f"uptime_{proto_name.lower()}"
        if col not in hb_existing:
            cur.execute(f"ALTER TABLE monitor_heartbeats ADD COLUMN {_sql_ident(col)} INTEGER NOT NULL DEFAULT 0")
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

def log_to_enriched_db(data, cur, save_protos=None):
    """Write one knock to the DB using the provided cursor. Caller commits."""
    proto_name = data.get('proto') or ''
    should_save = (save_protos is None or (save_protos and proto_name in save_protos))
    registered_mapping = _registered_knock_mapping(proto_name)
    event_t = int(data.get('t') or time.time())
    event_ts = datetime.fromtimestamp(event_t, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    if should_save and registered_mapping:
        table, proto_key_map = registered_mapping
        table = _sql_ident(table)
        col_names = ['timestamp'] + [col for _, col in _COMMON_KEY_MAP]
        values = [event_ts] + [data.get(key) for key, _ in _COMMON_KEY_MAP]
        for key, col in proto_key_map:
            col_names.append(col)
            values.append(data.get(key))
        placeholders = ', '.join(['?'] * len(col_names))
        col_sql = ', '.join(_sql_ident(col) for col in col_names)
        cur.execute(f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})", values)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    proto_int = PROTO.get(data.get('proto') or '', 0)
    if data.get('user') is not None:
        cur.execute("INSERT INTO user_intel VALUES (?, 1, ?) ON CONFLICT(username) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], now, now))
        cur.execute("INSERT INTO user_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(username, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['user'], proto_int, now, now))
    if data.get('pass') is not None:
        cur.execute("INSERT INTO pass_intel VALUES (?, 1, ?) ON CONFLICT(password) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], now, now))
        cur.execute("INSERT INTO pass_intel_proto VALUES (?, ?, 1, ?) ON CONFLICT(password, proto) DO UPDATE SET hits=hits+1, last_seen=?", (data['pass'], proto_int, now, now))
    cur.execute("INSERT INTO country_intel VALUES (?, ?, 1, ?) ON CONFLICT(iso_code) DO UPDATE SET hits=hits+1, last_seen=?, country=?", (data['iso'], data['country'], now, now, data['country']))
    cur.execute("INSERT INTO isp_intel VALUES (?, 1, ?, ?) ON CONFLICT(isp) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], now, data.get('asn'), now, data.get('asn')))
    cur.execute("""INSERT INTO ip_intel (ip, hits, last_seen, lat, lng, hits_since_cleared)
                   VALUES (?, 1, ?, ?, ?, 1)
                   ON CONFLICT(ip) DO UPDATE SET
                       hits=hits+1, last_seen=?, lat=?, lng=?, hits_since_cleared=hits_since_cleared+1""",
                (data['ip'], now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
    cur.execute("INSERT INTO country_intel_proto VALUES (?, ?, ?, 1, ?) ON CONFLICT(iso_code, proto) DO UPDATE SET hits=hits+1, last_seen=?, country=?", (data['iso'], proto_int, data['country'], now, now, data['country']))
    cur.execute("INSERT INTO isp_intel_proto VALUES (?, ?, 1, ?, ?) ON CONFLICT(isp, proto) DO UPDATE SET hits=hits+1, last_seen=?, asn=?", (data['isp'], proto_int, now, data.get('asn'), now, data.get('asn')))
    cur.execute("INSERT INTO ip_intel_proto VALUES (?, ?, 1, ?, ?, ?) ON CONFLICT(ip, proto) DO UPDATE SET hits=hits+1, last_seen=?, lat=?, lng=?",
                (data['ip'], proto_int, now, data.get('lat'), data.get('lng'), now, data.get('lat'), data.get('lng')))
    _db_update_hook(proto_name, data, cur, now)
    src_id = data.get('source', SOURCE_ID)
    cur.execute("""INSERT INTO sources (source_id, hits, first_seen, last_seen)
                   VALUES (?, 1, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                       hits=hits+1,
                       first_seen=COALESCE(first_seen, excluded.first_seen),
                       last_seen=excluded.last_seen""",
                (src_id, now, now))

def get_intel_stats_before_update(data):
    """Get hit counts and last_seen BEFORE updating — uses persistent read connection."""
    cur = _read_conn.cursor()
    stats = {}
    proto_int = PROTO.get(data.get('proto') or '', 0)

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

    cur.execute("SELECT hits, last_seen, hits_since_cleared FROM ip_intel WHERE ip=?", (data['ip'],))
    row = cur.fetchone()
    stats['ip_hits'], stats['ip_last'] = (row[0] + 1, row[1]) if row else (1, None)
    stats['ip_hits_since_cleared'] = (row[2] or 0) + 1 if row else 1
    cur.execute("SELECT hits, last_seen FROM ip_intel_proto WHERE ip=? AND proto=?", (data['ip'], proto_int))
    row = cur.fetchone()
    stats['ip_hits_proto'], stats['ip_last_proto'] = (row[0] + 1, row[1]) if row else (1, None)

    return stats

_db_write_queue = queue.Queue()

def _start_db_writer(save_protos):
    def _writer():
        conn = sqlite3.connect(DB_PATH, timeout=30)
        while True:
            items = [_db_write_queue.get()]
            deadline = time.monotonic() + 0.1
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    items.append(_db_write_queue.get(timeout=remaining))
                except queue.Empty:
                    break
            cur = conn.cursor()
            try:
                for package in items:
                    log_to_enriched_db(package, cur, save_protos=save_protos)
                conn.commit()
            except Exception as e:
                print(f"⚠️ DB writer error ({len(items)} knock(s)): {e}", flush=True)
                try:
                    conn.rollback()
                except Exception:
                    pass
    threading.Thread(target=_writer, daemon=True).start()

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

_SANITIZE_SIMPLE_FIELDS = ('user', 'pass')


def sanitize_passthrough_value(value, policy=None):
    if not isinstance(value, str):
        return value
    sanitizer = getattr(policy, 'sanitizer', 'credential') if policy else 'credential'
    max_len = getattr(policy, 'max_len', None) if policy else None
    if sanitizer == 'body':
        return sanitize_body(value, max_len=max_len or 2000)
    value = sanitize_credential(value)
    return value[:max_len] if max_len and value else value


def sanitize_knock(knock):
    """Sanitize raw knock fields and return (knock, passthrough_keys)."""
    passthrough_keys = []
    for field in _SANITIZE_SIMPLE_FIELDS:
        if field in knock:
            knock[field] = sanitize_credential(knock[field] if isinstance(knock[field], str) else str(knock[field]))
    for k, v, policy in _registered_passthrough_items(knock):
        knock[k] = sanitize_passthrough_value(v, policy)
        passthrough_keys.append(k)
    return knock, passthrough_keys

def is_over_limit_and_block(redis_conn, ip, hits_since_cleared, proto, max_knocks, ban_duration_days=30):
    if not max_knocks:
        return False
    if redis_conn.exists(f"knock:blocked:{ip}"):
        print(f"⛔ Dropped knock from blocked IP {ip} ({proto})", flush=True)
        return True
    limit = max_knocks.get(proto) or max_knocks.get(None)
    if not limit or hits_since_cleared <= limit:
        return False
    add_to_blocklist(ip, redis_conn, proto=proto, knock_count=hits_since_cleared, ban_duration_days=ban_duration_days)
    print(f"⛔ Dropped knock from over-limit IP {ip} ({hits_since_cleared}>={limit} {proto})", flush=True)
    return True


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

def add_to_blocklist(ip, r, proto=None, knock_count=None, ban_duration_days=30):
    """Block ip: write ban_until to SQLite, set Redis key with TTL, reset hits_since_cleared."""
    try:
        now = int(time.time())
        ban_until = 0 if ban_duration_days == 0 else now + int(ban_duration_days * 86400)
        proto_label = (proto or 'UNKNOWN').upper()
        count_label = int(knock_count) if knock_count is not None else '?'
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute("UPDATE ip_intel SET hits_since_cleared=0, ban_until=?, ban_count=ban_count+1 WHERE ip=?", (ban_until, ip))
            conn.commit()
        finally:
            conn.close()
        if ban_until == 0:
            r.set(f"knock:blocked:{ip}", 1)
        else:
            r.set(f"knock:blocked:{ip}", 1, ex=ban_until - now)
        dur_str = "permanently" if ban_until == 0 else f"for {ban_duration_days}d"
        print(f"🚫 Auto-blocked {ip} {dur_str} ({proto_label}, {count_label} knocks)", flush=True)
    except Exception as e:
        print(f"⚠️ Could not block {ip}: {e}")

def monitor(save_knocks=None, max_knocks=None, ban_duration_days=30):
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
    global _read_conn
    _read_conn = sqlite3.connect(DB_PATH, timeout=10)
    _start_db_writer(save_protos)
    r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=REDIS_DB, decode_responses=True)
    publish_protocol_config(r, enabled_protocols)
    entry_strs = [entry.label() for entry in proto_entries]
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

    # Seed knock:blocked:{ip} Redis keys from SQLite BEFORE spawning honeypots
    try:
        _now = int(time.time())
        _bconn = sqlite3.connect(DB_PATH, timeout=10)
        _brows = _bconn.execute("SELECT ip, ban_until FROM ip_intel WHERE ban_until IS NOT NULL").fetchall()
        _bconn.close()
        _seeded = 0
        for _bip, _ban_until in _brows:
            if _ban_until == 0:
                r.set(f"knock:blocked:{_bip}", 1)
                _seeded += 1
            elif _ban_until > _now:
                r.set(f"knock:blocked:{_bip}", 1, ex=int(_ban_until - _now))
                _seeded += 1
        if _seeded:
            print(f"🚫 Seeded {_seeded} active block(s) into Redis", flush=True)
    except Exception as e:
        print(f"⚠️ Could not seed blocks from SQLite: {e}")

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
    for entry in proto_entries:
        proto = entry.proto
        script, args, env = _spawn_config(entry)
        if not script:
            print(f"⚠️ No honeypot script configured for protocol {proto}; skipping", flush=True)
            continue
        key = entry.label().replace(':', '_')
        honeypots[key] = subprocess.Popen(
            [sys.executable, "-u", script] + args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if not honeypots and not INGEST_PORT:
        print("❌ No honeypots enabled and INGEST_PORT not set — nothing to do", flush=True)
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
            if re.match(r'^[A-Z]+TRACE\b', line):
                print(line, end='', flush=True)
            elif TRACE_KNOCK in ('true', 'verbose'):
                print(line, end='', flush=True)  # pass through diagnostic output from honeypots
            continue
        passthrough_keys = []
        # Sanitize credential fields once, before any processing or forwarding
        if knock.get('type') == 'KNOCK':
            knock, passthrough_keys = sanitize_knock(knock)
        if knock.get("type") == "KNOCK":
            knock["t"] = int(time.time())
            proto = str(knock.get("proto") or "").upper()
            if proto not in PROTO:
                _warn_unknown_proto(proto, ip=knock.get("ip"), source=knock.get("source"))
                continue
            processed = _process_knock_hook(proto, knock)
            if processed is None:
                continue
            knock = processed
            proto = str(knock.get("proto", proto)).upper()
            if proto not in PROTO:
                _warn_unknown_proto(proto, ip=knock.get("ip"), source=knock.get("source"))
                continue
            ip = knock["ip"]
            has_user = "user" in knock
            raw_user = knock.get("user")
            raw_pass = knock.get("pass")
            user = raw_user if proto in USER_PANEL_PROTOCOLS and has_user else None
            pw = raw_pass if proto in PASS_PANEL_PROTOCOLS and raw_pass is not None else None
            geo = get_geo_enriched(ip, c_reader, a_reader)
            package = {
                "t": knock["t"],
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
            if knock.get("display_format"):
                package["display_format"] = knock["display_format"]
            if knock.get("display_lines"):
                package["display_lines"] = knock["display_lines"]
            try:
                # Source tagging — integer for SQLite, string+display for Redis/WebSocket
                _src_id = knock.get('source', SOURCE_ID)
                package['source_int']     = _ensure_source(_src_id, _src_encode, _src_decode)
                package['source']         = _src_id
                package['source_display'] = _src_decode.get(package['source_int'], _src_id)
                # Pass through protocol-specific extended telemetry into Redis/websocket payloads.
                # This is intentionally not persisted in SQLite.
                for k in passthrough_keys:
                    package[k] = knock.get(k)
                package.update(get_intel_stats_before_update(package))
                hits_since_cleared = int(package.get('ip_hits_since_cleared', 0) or 0)
                if is_over_limit_and_block(r, ip, hits_since_cleared, proto, max_knocks, ban_duration_days):
                    continue
                if AGGREGATOR_HOST:
                    try:
                        _forward_queue.put_nowait({**knock, 'source': SOURCE_ID})
                    except queue.Full:
                        pass
                _db_write_queue.put(package.copy())
            except Exception as e:
                print(f"⚠️ Knock processing error (knock dropped): {e}", flush=True)
                continue
            _after_save_hook(proto, knock, package)
            r.lpush("knock:recent", json.dumps(package))
            r.ltrim("knock:recent", 0, 99)
            proto_key = "knock:recent:" + package['proto'].lower()
            r.lpush(proto_key, json.dumps(package))
            r.ltrim(proto_key, 0, 99)
            r.incr("knock:total_global")
            r.hincrby("knock:proto_counts", package['proto'], 1)
            r.hincrby("knock:source_counts", package['source'], 1)
            r.set("knock:last_time", package["t"])
            r.set(f"knock:last_time:{package['proto'].lower()}", package["t"])
            if geo['lat'] is not None:
                r.set("knock:last_lat", geo['lat'])
                r.set("knock:last_lng", geo['lng'])
            r.publish("knocks_stream", json.dumps(package))
            if TRACE_KNOCK:
                print(f"📡 {proto} {geo['iso']} | {geo['country']}, {ip} via {geo['isp']}")
            if TRACE_KNOCK == 'verbose':
                print(json.dumps(package))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Knock-Knock Monitor")
    parser.add_argument("--reset-all", action="store_true", help="Delete DB and clear Redis")
    parser.add_argument("--save-knocks", nargs='?', const='ALL', default=None, metavar='PROTOS',
                        help="Save individual knocks to SQLite. Optional: comma-separated protocols (e.g. SIP,SMTP). Default: ALL")
    parser.add_argument("--max-knocks", default=None, metavar="LIMIT",
                        help="Auto-block IP after N knocks. Examples: 5000, RDP:500, 5000,RDP:500,SIP:NONE")
    parser.add_argument("--ban-duration", type=int, default=None, metavar="DAYS",
                        help="Duration of auto-ban in days (default: 30, 0 = permanent)")
    args = parser.parse_args()
    if args.reset_all: reset_all()
    # CLI takes precedence; fall back to env vars
    save_knocks = args.save_knocks
    if save_knocks is None:
        env = os.environ.get('SAVE_KNOCKS', '').strip()
        save_knocks = 'ALL' if env.upper() in ('TRUE', '1') else env or None
    # Parse --max-knocks / MAX_KNOCKS: "5000" → {None: 5000}, "RDP:500" → {'RDP': 500}, "5000,RDP:500" → {None: 5000, 'RDP': 500}
    max_knocks = None
    for part in (args.max_knocks or os.environ.get('MAX_KNOCKS', '')).split(','):
        part = part.strip()
        if not part: continue
        max_knocks = max_knocks or {}
        if ':' in part:
            proto_name, val = part.split(':', 1)
            max_knocks[proto_name.strip().upper()] = None if val.strip().upper() == 'NONE' else int(val)
        else:
            max_knocks[None] = int(part)
    ban_duration = args.ban_duration if args.ban_duration is not None else int(os.environ.get('BAN_DURATION', 30))
    monitor(save_knocks=save_knocks, max_knocks=max_knocks, ban_duration_days=ban_duration)

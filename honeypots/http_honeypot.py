#!/usr/bin/env python3
"""
HTTP honeypot — listens on port 80 (configurable via HTTP_PORT), captures every
HTTP request as a JSON knock on stdout, and returns a convincing fake Apache response.

Standalone: outputs JSON to stdout only. Not yet wired into monitor.py.

Usage:
    python http_honeypot.py
    HTTP_PORT=8080 python http_honeypot.py
"""
import json
import os
import re
import socket
import threading
import time

from common import create_dualstack_tcp_listener, is_blocked, normalize_ip

# ---------------------------------------------------------------------------
# Exploit database — loaded once at startup from honeypots/http_exploits.json
# ---------------------------------------------------------------------------

def _load_exploits():
    """
    Load and compile http_exploits.json from the same directory as this script.
    Each entry may have: path_pattern, body_pattern, ua_pattern (all optional regexes),
    plus name, cve (optional), and purpose.
    Returns a list of compiled exploit dicts.
    """
    candidates = [
        os.path.join(os.path.dirname(__file__), 'http_exploits.json'),
    ]
    for path in candidates:
        path = os.path.normpath(path)
        if os.path.exists(path):
            try:
                with open(path) as f:
                    entries = json.load(f)
                compiled = []
                for e in entries:
                    compiled.append({
                        'name':         e['name'],
                        'cve':          e.get('cve'),
                        'purpose':      e.get('purpose'),
                        'path_re':      re.compile(e['path_pattern'], re.IGNORECASE) if e.get('path_pattern') else None,
                        'body_re':      re.compile(e['body_pattern'], re.IGNORECASE) if e.get('body_pattern') else None,
                        'ua_re':        re.compile(e['ua_pattern'],   re.IGNORECASE) if e.get('ua_pattern')   else None,
                    })
                print(f'[http] Loaded {len(compiled)} exploit signatures from {path}', flush=True)
                return compiled
            except Exception as ex:
                print(f'[http] Failed to load http_exploits.json: {ex}', flush=True)
    print('[http] http_exploits.json not found — exploit matching disabled', flush=True)
    return []

_EXPLOITS = _load_exploits()


def _match_exploit(path: str, ua: str, body: str):
    """
    Check path/ua/body against the compiled exploit list.
    Returns (name, cve, purpose) for the first match, or (None, None, None).
    Matching rules per entry:
      - path_re only:            path must match
      - ua_re only:              ua must match
      - path_re + body_re:       both must match
      - path_re + ua_re:         both must match
      - all three:               all must match
    """
    for e in _EXPLOITS:
        p_ok = e['path_re'].search(path) if e['path_re'] else None
        b_ok = e['body_re'].search(body) if e['body_re'] else None
        u_ok = e['ua_re'].search(ua)     if e['ua_re']   else None

        has_path = e['path_re'] is not None
        has_body = e['body_re'] is not None
        has_ua   = e['ua_re']   is not None

        if not has_path and not has_body and not has_ua:
            continue

        # All present fields must match
        if has_path and not p_ok:
            continue
        if has_body and not b_ok:
            continue
        if has_ua   and not u_ok:
            continue

        return e['name'], e.get('cve'), e.get('purpose')
    return None, None, None

HTTP_PORT        = int(os.environ.get('HTTP_PORT',        80))
HTTP_TIMEOUT     = int(os.environ.get('HTTP_TIMEOUT',     15))
HTTP_MAX_HEADERS = int(os.environ.get('HTTP_MAX_HEADERS', 8192))
HTTP_MAX_BODY    = int(os.environ.get('HTTP_MAX_BODY',    4096))

# Per-IP knock throttle: max this many knocks per second per IP.
_HTTP_THROTTLE_PER_SEC = 20

_throttle_lock   = threading.Lock()
_throttle_window = 0       # current second (int)
_throttle_counts: dict = {}

# ---------------------------------------------------------------------------
# Fake HTTP responses
# ---------------------------------------------------------------------------

_HEADERS_COMMON = (
    'Server: Apache/2.4.41 (Ubuntu)\r\n'
    'Content-Type: text/html; charset=utf-8\r\n'
    'Connection: close\r\n'
)

_RESPONSE_200 = (
    'HTTP/1.1 200 OK\r\n'
    + _HEADERS_COMMON
    + '\r\n'
    + '<html><body><h1>It works!</h1></body></html>'
)

_RESPONSE_404 = (
    'HTTP/1.1 404 Not Found\r\n'
    + _HEADERS_COMMON
    + '\r\n'
    + '<html><body><h1>Not Found</h1>'
    + '<p>The requested URL was not found on this server.</p>'
    + '</body></html>'
)

# ---------------------------------------------------------------------------
# Throttle
# ---------------------------------------------------------------------------

def _should_emit(client_ip: str) -> bool:
    global _throttle_window, _throttle_counts
    now = int(time.time())
    with _throttle_lock:
        if now != _throttle_window:
            _throttle_window = now
            _throttle_counts = {}
        count = _throttle_counts.get(client_ip, 0)
        if count >= _HTTP_THROTTLE_PER_SEC:
            return False
        _throttle_counts[client_ip] = count + 1
        return True

# ---------------------------------------------------------------------------
# Purpose classification
# ---------------------------------------------------------------------------
#
# Returns a short string describing the inferred intent of the request.
# Evaluated in priority order — first match wins.
#
# Categories (most → least severe):
#   rce               Remote/arbitrary code execution exploit attempt
#   credential_theft  Brute-force or credential-harvesting login probe
#   device_infiltration  Router/IoT/embedded-device takeover
#   config_exposure   Fishing for credentials/config files left on disk
#   path_traversal    Directory traversal to read arbitrary files
#   proxy_abuse       Using the server as a proxy or SSRF pivot
#   recon_scanner     Identified benign research scanner (Shodan, Censys …)
#   protocol_probe    Non-HTTP protocol data sent to HTTP port (TLS, RDP …)
#   mass_scanner      Generic/unidentified automated scan
#   unknown           Nothing recognisable

_RE_RCE_PATH = re.compile(
    # General structural signals — age well, catch novel exploits.
    # Named CVE paths live in http_exploits.json instead.
    r'(\$\{jndi:)'                              # JNDI injection (Log4Shell family)
    r'|(/cgi-bin/(?:admin|login|luci|test|bash|sh|cmd|exec|run))'
    r'|((?:[?&;]|^/)(?:cmd|exec|command|shell|run|system|passthru|popen|eval)'
       r'\s*=)'                                 # common RCE param names
    r'|(/shell\b)'
    r'|(/cgi-bin/(?:vendor_ipcam_cgi|web_shell_cmd)\.cgi)',
    re.IGNORECASE,
)

_RE_RCE_BODY = re.compile(
    r'(\$\{jndi:)'                              # Log4Shell in body
    r'|(eval\s*\()'
    r'|(base64_decode\s*\()'
    r'|(system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\()'
    r'|(\|\s*(?:sh|bash|cmd\.exe))'            # pipe to shell
    r'|(`[^`]{1,120}`)',                        # backtick command sub
    re.IGNORECASE,
)

_RE_RCE_UA = re.compile(
    r'(\$\{jndi:)'
    r'|(;?\s*(?:wget|curl|bash|sh)\s+http)',
    re.IGNORECASE,
)

_RE_CRED_PATH = re.compile(
    # General credential-harvesting signals.
    # Named products (WordPress, phpMyAdmin, Tomcat, etc.) live in http_exploits.json.
    r'(/\.git/(?:credentials|COMMIT_EDITMSG|packed-refs))'  # git credential store
    r'|(/wp-admin/)'                            # WordPress admin area (not login — that's in JSON)
    r'|(/administrator(?:/|$))'
    r'|(/admin(?:istration)?/(?:login|index|auth|signin))'
    r'|(/(?:login|signin|auth|account/login|user/login|session/new)'
       r'(?:[?/]|$))'
    r'|(/+api/v1/users/login)',
    re.IGNORECASE,
)

_RE_CRED_BODY = re.compile(
    r'(?:^|&)(?:user(?:name)?|log(?:in)?|email|pass(?:word|wd)?|pwd)'
    r'\s*=',
    re.IGNORECASE,
)

_RE_DEVICE_PATH = re.compile(
    # General device/IoT structural signals.
    # Named products (Hikvision, D-Link, Ubiquiti, etc.) live in http_exploits.json.
    r'(/goform/)'                               # Tenda/TP-Link/etc
    r'|(/cgi-bin/luci(?:/|$))'                 # OpenWrt
    r'|(/cgi-bin/(?:login|admin|diagnostic|ping|traceroute)\.cgi)'
    r'|(/setup\.cgi)'                           # generic router setup CGI
    r'|(/apply\.cgi)'                           # Linksys / generic
    r'|(/boaform/)'                             # Boa httpd (many embedded devices)
    r'|(/GponForm/)'                            # GPON routers
    r'|(/api/auth/login)'                       # generic device API login
    r'|(/Streaming/Channels/)'                  # IP camera RTSP gateway
    r'|(/stssys\.htm|/rpSys\.htm)'             # Cisco router
    r'|(/cgi-bin/supervisor/CloudSetup\.cgi)'  # D-Link / AXIS
    r'|(/cgi-bin/qcmap_web_cgi)',               # Qualcomm MDM
    re.IGNORECASE,
)

_RE_CONFIG_PATH = re.compile(
    r'(/\.env(?:\b|$))'
    r'|(/\.git/(?:HEAD|config|FETCH_HEAD|index))'
    r'|(/wp-config\.php)'
    r'|(/(?:config|configuration)\.(?:php|inc|bak|old|yml|yaml|json)'
       r'(?:\b|$))'
    r'|(/\.htaccess|/\.htpasswd)'
    r'|(/phpinfo(?:\.php)?)'
    r'|(/web\.config)'
    r'|(/(?:dump|backup|db)\.(?:sql|gz|zip|tar))'
    r'|(/(?:credentials|secrets|keys|token)(?:\.json|\.yml|\.env|$))'
    r'|(/aws(?:credentials|config))'
    r'|(/server-status)'                        # Apache mod_status
    r'|(/metrics(?:/|$))'                       # Prometheus metrics endpoint
    r'|(/vendor/(?!phpunit)[^/]+/)',            # exposed composer deps (not phpunit — caught as rce)
    re.IGNORECASE,
)

_RE_TRAVERSAL = re.compile(
    r'\.\.[/\\]'                                # classic ../
    r'|%2e%2e[%2f%5c]'                         # URL-encoded
    r'|%252e%252e'                              # double-encoded
    r'|/etc/(?:passwd|shadow|hosts)'
    r'|/proc/self/',
    re.IGNORECASE,
)

_RE_PROXY_PATH = re.compile(
    r'^https?://',                              # absolute-form URI (proxy req)
    re.IGNORECASE,
)

_RE_SSRF = re.compile(
    r'(?:169\.254\.169\.254'                   # AWS metadata
    r'|localhost'
    r'|127\.0\.0\.1'
    r'|0\.0\.0\.0'
    r'|::1'
    r'|metadata\.google\.internal)',
    re.IGNORECASE,
)

# Self-identifying research scanners via methodology URL in UA — general structural signal.
# Named scanner orgs are in http_exploits.json.
_RE_RECON_UA = re.compile(
    r'\+https?://\S+/methodology',
    re.IGNORECASE,
)

_RECON_PATHS = frozenset({
    '/robots.txt', '/security.txt', '/.well-known/security.txt',
    '/sitemap.xml', '/humans.txt',
})

# Generic mass-scanner user-agents (not specifically research orgs)
_RE_MASS_UA = re.compile(
    r'(zgrab)'
    r'|(masscan)'
    r'|(Go-http-client)'
    r'|(python-requests)'
    r'|(libwww-perl)'
    r'|(curl/)'
    r'|(wget/)'
    r'|(Nuclei)'
    r'|(Nikto)'
    r'|(sqlmap)'
    r'|(nmap)'
    r'|(dirbuster)'
    r'|(gobuster)'
    r'|(wfuzz)'
    r'|(hydra)',
    re.IGNORECASE,
)


def _classify_purpose(method: str, path: str, ua: str, body: str):
    """
    Classify the inferred intent of an HTTP request.
    Returns (purpose: str, exploit_name: str|None, exploit_cve: str|None).
    Checks the exploit database first; falls back to general regex classifiers.
    """
    combined = path + ' ' + body   # body may be empty string

    # 0. Protocol probe — non-HTTP binary data on port 80 (TLS, RDP, etc.)
    #    All valid HTTP methods are printable ASCII; any non-printable first byte
    #    means binary protocol data (TLS ClientHello 0x16, RDP TPKT 0x03, etc.)
    if method and not method[0].isprintable():
        return 'protocol_probe', None, None

    # 1. Exploit database — specific match overrides general classifiers
    exp_name, exp_cve, exp_purpose = _match_exploit(path, ua, body)
    if exp_name:
        return exp_purpose or 'unknown', exp_name, exp_cve

    # 2. RCE — highest priority
    if (_RE_RCE_PATH.search(path)
            or _RE_RCE_BODY.search(body)
            or _RE_RCE_UA.search(ua)):
        return 'rce', None, None

    # 3. Credential theft
    if _RE_CRED_PATH.search(path):
        return 'credential_theft', None, None
    if method in ('POST', 'PUT') and _RE_CRED_BODY.search(body):
        # Only flag as cred theft if the path also looks login-ish
        if re.search(r'/(login|signin|auth|session|account|user|wp-|admin)',
                     path, re.IGNORECASE):
            return 'credential_theft', None, None

    # 4. Device / IoT infiltration
    if _RE_DEVICE_PATH.search(path):
        return 'device_infiltration', None, None

    # 5. Config / secret file exposure
    if _RE_CONFIG_PATH.search(path):
        return 'config_exposure', None, None

    # 6. Path traversal
    if _RE_TRAVERSAL.search(combined):
        return 'path_traversal', None, None

    # 7. Proxy abuse / SSRF
    if method == 'CONNECT':
        return 'proxy_abuse', None, None
    if _RE_PROXY_PATH.match(path):
        return 'proxy_abuse', None, None
    if _RE_SSRF.search(combined):
        return 'proxy_abuse', None, None

    # 8. Known benign research scanner
    if _RE_RECON_UA.search(ua) or path in _RECON_PATHS:
        return 'recon_scanner', None, None

    # 9. Generic mass scanner (identified tool or empty UA hammering non-root)
    if _RE_MASS_UA.search(ua):
        return 'mass_scanner', None, None
    if not ua and path not in ('/', ''):
        return 'mass_scanner', None, None

    return 'unknown', None, None


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------

def _recv_headers(sock) -> bytes:
    """Read from socket until \\r\\n\\r\\n or HTTP_MAX_HEADERS bytes."""
    buf = b''
    sock.settimeout(HTTP_TIMEOUT)
    try:
        while len(buf) < HTTP_MAX_HEADERS:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            if b'\r\n\r\n' in buf or b'\n\n' in buf:
                break
    except OSError:
        pass
    return buf


def _parse_request(raw: bytes) -> dict:
    """
    Parse raw HTTP request bytes. Returns dict with keys:
      method, path, host, user_agent, has_body, content_length, body_methods
    Returns empty dict on parse failure.
    """
    try:
        # Split header section from any body data that arrived with headers
        if b'\r\n\r\n' in raw:
            header_part, body_prefix = raw.split(b'\r\n\r\n', 1)
        elif b'\n\n' in raw:
            header_part, body_prefix = raw.split(b'\n\n', 1)
        else:
            header_part, body_prefix = raw, b''

        lines = header_part.decode('latin-1', errors='replace').split('\n')
        request_line = lines[0].strip()
        parts = request_line.split(' ', 2)
        if len(parts) < 2:
            return {}

        method = parts[0].upper()
        path   = parts[1]

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()

        return {
            'method':         method,
            'path':           path,
            'host':           headers.get('host', ''),
            'user_agent':     headers.get('user-agent', ''),
            'content_length': int(headers.get('content-length', 0) or 0),
            'body_prefix':    body_prefix,
            'has_body':       method in ('POST', 'PUT', 'PATCH'),
        }
    except Exception:
        return {}


def _read_body(sock, parsed: dict) -> str:
    """Read POST/PUT body up to HTTP_MAX_BODY bytes. Returns decoded string."""
    content_length = parsed.get('content_length', 0)
    if not content_length or not parsed.get('has_body'):
        return ''
    body = parsed.get('body_prefix', b'')
    remaining = min(content_length, HTTP_MAX_BODY) - len(body)
    if remaining > 0:
        try:
            sock.settimeout(HTTP_TIMEOUT)
            chunk = sock.recv(remaining)
            if chunk:
                body += chunk
        except OSError:
            pass
    return body[:HTTP_MAX_BODY].decode('latin-1', errors='replace')

# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def handle_connection(sock: socket.socket, client_ip: str):
    try:
        raw     = _recv_headers(sock)
        if not raw:
            return

        parsed  = _parse_request(raw)
        if not parsed:
            return

        method  = parsed['method']
        path    = parsed['path']
        host    = parsed['host']
        ua      = parsed['user_agent']
        body    = _read_body(sock, parsed) if parsed['has_body'] else ''

        # Send response before emitting knock — don't delay the bot
        response = _RESPONSE_200 if path in ('/', '') else _RESPONSE_404
        try:
            sock.sendall(response.encode())
        except OSError:
            pass

        if path == '/favicon.ico':
            return

        if not _should_emit(client_ip):
            return

        purpose, exploit_name, exploit_cve = _classify_purpose(method, path, ua, body)

        knock = {'type': 'KNOCK', 'proto': 'HTTP', 'ip': client_ip,
                 'http_method': method, 'http_path': path,
                 'http_purpose': purpose}
        if exploit_name:
            knock['http_exploit'] = exploit_name + (f' ({exploit_cve})' if exploit_cve else '')
        if host:
            knock['http_host'] = host
        if ua:
            knock['http_user_agent'] = ua
        if body:
            knock['http_body'] = body

        print(json.dumps(knock), flush=True)

    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    server = create_dualstack_tcp_listener(HTTP_PORT)
    print(f'🚀 HTTP Honeypot Active on Port {HTTP_PORT} (IPv4+IPv6). Collecting knocks...',
          flush=True)
    while True:
        try:
            conn, addr = server.accept()
            client_ip = normalize_ip(addr[0])
            if is_blocked(client_ip):
                conn.close()
                continue
            threading.Thread(target=handle_connection, args=(conn, client_ip),
                             daemon=True).start()
        except OSError:
            break


if __name__ == '__main__':
    main()

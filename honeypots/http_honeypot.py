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
import socket
import threading
import time

from common import create_dualstack_tcp_listener, is_blocked, normalize_ip

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

        if not _should_emit(client_ip):
            return

        knock = {'type': 'KNOCK', 'proto': 'HTTP', 'ip': client_ip,
                 'http_method': method, 'http_path': path}
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

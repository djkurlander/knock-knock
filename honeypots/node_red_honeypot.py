#!/usr/bin/env python3
"""
Node-RED honeypot — listens on port 1880 by default, returns shallow
Node-RED/Express-like responses, and emits NRED JSON knocks on stdout.

Standalone examples:
    python honeypots/node_red_honeypot.py
    NRED_AUTH_MODE=fake_token python honeypots/node_red_honeypot.py --port 1880
"""

import argparse
import json
import os
import random
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from collections import Counter

from common import (
    create_dualstack_tcp_listener,
    ensure_self_signed_server_cert,
    is_blocked,
    normalize_ip,
)


NRED_PORT = int(os.environ.get('NRED_PORT', '1880'))
KNOCK_PROTO = os.environ.get('KNOCK_PROTO', 'NRED').strip().upper() or 'NRED'
NRED_TIMEOUT = int(os.environ.get('NRED_TIMEOUT', '15'))
NRED_MAX_HEADERS = int(os.environ.get('NRED_MAX_HEADERS', '8192'))
NRED_MAX_BODY = int(os.environ.get('NRED_MAX_BODY', '8192'))
NRED_AUTH_MODE = os.environ.get('NRED_AUTH_MODE', 'open').strip().lower()
if NRED_AUTH_MODE not in ('open', 'require', 'fake_token'):
    NRED_AUTH_MODE = 'open'
NRED_TRACE = os.environ.get('NRED_TRACE', '0').lower() not in ('0', 'false', 'no')
NRED_TRACE_IP = os.environ.get('NRED_TRACE_IP', '').strip()
NRED_TLS_CERT_PATH = os.environ.get('NRED_TLS_CERT_PATH', 'data/nodered.crt')
NRED_TLS_KEY_PATH = os.environ.get('NRED_TLS_KEY_PATH', 'data/nodered.key')

_NRED_PORT = NRED_PORT
_THROTTLE_PER_SEC = 20
_throttle_lock = threading.Lock()
_throttle_window = 0
_throttle_counts = {}
_PROFILE = None


def _load_exploits():
    path = os.path.join(os.path.dirname(__file__), 'node_red_exploits.json')
    try:
        with open(path) as f:
            entries = json.load(f)
        compiled = []
        for idx, e in enumerate(entries):
            compiled.append({
                'name': e['name'],
                'purpose': e.get('purpose'),
                'priority': int(e.get('priority', 1000)),
                'order': idx,
                'method_re': re.compile(e['method_pattern'], re.IGNORECASE) if e.get('method_pattern') else None,
                'path_re': re.compile(e['path_pattern'], re.IGNORECASE) if e.get('path_pattern') else None,
                'body_re': re.compile(e['body_pattern'], re.IGNORECASE) if e.get('body_pattern') else None,
                'ua_re': re.compile(e['ua_pattern'], re.IGNORECASE) if e.get('ua_pattern') else None,
            })
        compiled.sort(key=lambda e: (e['priority'], e['order']))
        print(f'[nred] Loaded {len(compiled)} exploit signatures from {path}', flush=True)
        return compiled
    except Exception as ex:
        print(f'[nred] Failed to load node_red_exploits.json: {ex}', flush=True)
        return []


_EXPLOITS = _load_exploits()


def _match_exploit(method, path, ua, body):
    for e in _EXPLOITS:
        checks = []
        if e['method_re']:
            checks.append(bool(e['method_re'].search(method)))
        if e['path_re']:
            checks.append(bool(e['path_re'].search(path)))
        if e['body_re']:
            checks.append(bool(e['body_re'].search(body)))
        if e['ua_re']:
            checks.append(bool(e['ua_re'].search(ua)))
        if checks and all(checks):
            return e['name'], e.get('purpose')
    return None, None


def _trace(client_ip, stage, **kwargs):
    if not NRED_TRACE:
        return
    if NRED_TRACE_IP and client_ip != NRED_TRACE_IP:
        return
    parts = [f'NREDTRACE ip={client_ip}', f'stage={stage}']
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f'{k}={v!r}')
    print(' '.join(parts), flush=True)


def _should_emit(client_ip):
    global _throttle_window, _throttle_counts
    now = int(time.time())
    with _throttle_lock:
        if now != _throttle_window:
            _throttle_window = now
            _throttle_counts = {}
        count = _throttle_counts.get(client_ip, 0)
        if count >= _THROTTLE_PER_SEC:
            return False
        _throttle_counts[client_ip] = count + 1
        return True


def _safe_text(value, limit=400):
    if value is None:
        return None
    text = str(value)
    text = ''.join(ch if ch.isprintable() or ch in '\r\n\t' else '.' for ch in text)
    return text[:limit]


def _body_preview(body, limit=2000):
    return _safe_text(body, limit) if body else ''


def _recv_headers(sock):
    buf = b''
    sock.settimeout(NRED_TIMEOUT)
    try:
        while len(buf) < NRED_MAX_HEADERS:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            if b'\r\n\r\n' in buf or b'\n\n' in buf:
                break
    except OSError:
        pass
    return buf


def _parse_request(raw):
    try:
        if b'\r\n\r\n' in raw:
            header_part, body_prefix = raw.split(b'\r\n\r\n', 1)
        elif b'\n\n' in raw:
            header_part, body_prefix = raw.split(b'\n\n', 1)
        else:
            header_part, body_prefix = raw, b''
        lines = header_part.decode('latin-1', errors='replace').split('\n')
        parts = lines[0].strip().split(' ', 2)
        if len(parts) < 2:
            return {}
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()
        method = parts[0].upper()
        path = parts[1]
        return {
            'method': method,
            'path': path,
            'path_only': urllib.parse.urlsplit(path).path or '/',
            'host': headers.get('host', ''),
            'user_agent': headers.get('user-agent', ''),
            'authorization': headers.get('authorization', ''),
            'content_type': headers.get('content-type', ''),
            'content_length': int(headers.get('content-length', 0) or 0),
            'body_prefix': body_prefix,
            'has_body': method in ('POST', 'PUT', 'PATCH'),
        }
    except Exception:
        return {}


def _read_body(sock, parsed):
    content_length = parsed.get('content_length', 0)
    if not content_length or not parsed.get('has_body'):
        return ''
    body = parsed.get('body_prefix', b'')
    remaining = min(content_length, NRED_MAX_BODY) - len(body)
    if remaining > 0:
        try:
            sock.settimeout(NRED_TIMEOUT)
            chunk = sock.recv(remaining)
            if chunk:
                body += chunk
        except OSError:
            pass
    return body[:NRED_MAX_BODY].decode('latin-1', errors='replace')


def _parse_body_fields(body, content_type):
    if not body:
        return {}
    if 'application/json' in (content_type or '').lower():
        try:
            data = json.loads(body)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        return {k: v[-1] if v else '' for k, v in parsed.items()}
    except Exception:
        return {}


def _classify(method, path, ua, body):
    if method and not method[0].isprintable():
        return 'protocol_probe', None
    name, purpose = _match_exploit(method, path, ua, body)
    if name:
        return purpose or 'unknown', name
    if method in ('GET', 'HEAD') and path in ('/', '/red', '/red/'):
        return 'editor_probe', None
    if path.startswith('/red/'):
        return 'editor_asset_probe', None
    if path == '/credentials':
        return 'credentials_probe', None
    if path.startswith('/context/'):
        return 'context_probe', None
    if path == '/projects':
        return 'projects_probe', None
    if path.startswith('/library/'):
        return 'library_probe', None
    if path == '/comms':
        return 'editor_comms_probe', None
    if re.search(r'(Go-http-client|curl/|wget/|python-requests|zgrab|masscan)', ua or '', re.I):
        return 'mass_scanner', None
    return 'unknown', None


def _json_response(status, payload, extra_headers=''):
    body = json.dumps(payload)
    reason = {
        200: 'OK',
        201: 'Created',
        204: 'No Content',
        401: 'Unauthorized',
        404: 'Not Found',
    }.get(status, 'OK')
    if status == 204:
        body = ''
    headers = (
        f'HTTP/1.1 {status} {reason}\r\n'
        'X-Powered-By: Express\r\n'
        'Content-Type: application/json; charset=utf-8\r\n'
        f'Content-Length: {len(body.encode())}\r\n'
        'Connection: close\r\n'
        f'{extra_headers}'
        '\r\n'
    )
    return (headers + body).encode()


def _text_response(status, body, content_type):
    reason = {200: 'OK', 204: 'No Content', 404: 'Not Found'}.get(status, 'OK')
    if status == 204:
        body = ''
    headers = (
        f'HTTP/1.1 {status} {reason}\r\n'
        'X-Powered-By: Express\r\n'
        f'Content-Type: {content_type}\r\n'
        f'Content-Length: {len(body.encode())}\r\n'
        'Connection: close\r\n'
        '\r\n'
    )
    return (headers + body).encode()


def _html_response(status, body):
    reason = {200: 'OK', 404: 'Not Found'}.get(status, 'OK')
    headers = (
        f'HTTP/1.1 {status} {reason}\r\n'
        'X-Powered-By: Express\r\n'
        'Content-Type: text/html; charset=utf-8\r\n'
        f'Content-Length: {len(body.encode())}\r\n'
        'Connection: close\r\n'
        '\r\n'
    )
    return (headers + body).encode()


def _make_profile():
    version = random.choice(['3.0.2', '3.1.0', '3.1.7', '3.1.9'])
    theme = random.choice([
        ('Factory telemetry', 'plant-broker', '10.20.1.15', 'node-red-gateway', 'factory/line1/#', '/api/status'),
        ('Building automation', 'hvac-broker', '192.168.12.25', 'nodered-hvac', 'building/hvac/#', '/api/hvac/status'),
        ('Home sensors', 'home-mqtt', '192.168.1.22', 'node-red-home', 'home/+/status', '/api/home/status'),
    ])
    prefix = secrets.token_hex(3)
    return {
        'version': version,
        'token': f'nr-{secrets.token_hex(12)}',
        'tab_id': f'{prefix}tab',
        'broker_id': f'{prefix}broker',
        'mqtt_id': f'{prefix}mqttin',
        'http_in_id': f'{prefix}httpin',
        'http_resp_id': f'{prefix}httpresp',
        'debug_id': f'{prefix}debug',
        'tab': theme[0],
        'broker_name': theme[1],
        'broker_host': theme[2],
        'client_id': theme[3],
        'topic': theme[4],
        'http_url': theme[5],
    }


def _fake_flows():
    p = _PROFILE
    return [
        {'id': p['tab_id'], 'type': 'tab', 'label': p['tab'], 'disabled': False, 'info': ''},
        {'id': p['broker_id'], 'type': 'mqtt-broker', 'name': p['broker_name'], 'broker': p['broker_host'], 'port': '1883', 'clientid': p['client_id']},
        {'id': p['mqtt_id'], 'type': 'mqtt in', 'z': p['tab_id'], 'name': 'sensor feed', 'topic': p['topic'], 'broker': p['broker_id'], 'wires': [[p['debug_id']]]},
        {'id': p['http_in_id'], 'type': 'http in', 'z': p['tab_id'], 'name': 'status api', 'url': p['http_url'], 'method': 'get', 'wires': [[p['http_resp_id']]]},
        {'id': p['debug_id'], 'type': 'debug', 'z': p['tab_id'], 'name': 'debug telemetry', 'active': True},
        {'id': p['http_resp_id'], 'type': 'http response', 'z': p['tab_id'], 'statusCode': ''},
    ]


def _asset_response(path):
    if path == '/red/red.min.js':
        return _text_response(200, 'window.RED=window.RED||{};RED.settings={};RED.nodes={};RED.view={};', 'application/javascript; charset=utf-8')
    if path == '/red/style.min.css':
        return _text_response(200, 'body{margin:0;font-family:"Helvetica Neue",Arial,sans-serif;background:#f3f3f3;color:#333}#red-ui-editor{position:absolute;inset:0;background:#fff}', 'text/css; charset=utf-8')
    if path in ('/red/images/node-red.svg', '/red/images/node-red-icon.svg'):
        return _text_response(200, '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="8" fill="#8f0000"/><path d="M16 20h32v24H16z" fill="#fff" opacity=".92"/><path d="M22 28h20M22 36h20" stroke="#8f0000" stroke-width="4"/></svg>', 'image/svg+xml')
    if path == '/favicon.ico':
        return _text_response(204, '', 'image/x-icon')
    return None


def _response_for(parsed, body):
    method = parsed['method']
    path = parsed['path_only']
    authed = bool(parsed.get('authorization', '').lower().startswith('bearer '))

    asset = _asset_response(path)
    if asset is not None:
        return asset
    if path in ('/', '/red', '/red/'):
        return _html_response(200, (
            '<!doctype html><html><head><title>Node-RED</title>'
            '<link rel="stylesheet" href="red/style.min.css">'
            '</head><body><div id="red-ui-editor"></div>'
            '<script src="red/red.min.js"></script></body></html>'
        ))
    if path == '/auth/login':
        if NRED_AUTH_MODE == 'open':
            return _json_response(200, {})
        return _json_response(200, {
            'type': 'credentials',
            'prompts': [
                {'id': 'username', 'type': 'text', 'label': 'Username'},
                {'id': 'password', 'type': 'password', 'label': 'Password'},
            ],
        })
    if path == '/auth/token':
        if method == 'POST' and NRED_AUTH_MODE == 'fake_token':
            return _json_response(200, {
                'access_token': _PROFILE['token'],
                'expires_in': 604800,
                'token_type': 'Bearer',
            })
        return _json_response(401, {'error': 'invalid_grant'}, 'WWW-Authenticate: Bearer\r\n')
    if path == '/settings':
        if NRED_AUTH_MODE == 'require' and not authed:
            return _json_response(401, {'error': 'unauthorized'}, 'WWW-Authenticate: Bearer\r\n')
        return _json_response(200, {
            'httpNodeRoot': '/',
            'version': _PROFILE['version'],
            'context': {'default': 'memory'},
            'editorTheme': {'projects': {'enabled': False}},
            'paletteCategories': ['subflows', 'common', 'function', 'network', 'sequence', 'parser', 'storage'],
        })
    if path == '/credentials':
        if NRED_AUTH_MODE == 'require' and not authed:
            return _json_response(401, {'error': 'unauthorized'}, 'WWW-Authenticate: Bearer\r\n')
        return _json_response(200, {})
    if path.startswith('/context/'):
        if NRED_AUTH_MODE == 'require' and not authed:
            return _json_response(401, {'error': 'unauthorized'}, 'WWW-Authenticate: Bearer\r\n')
        return _json_response(200, {})
    if path == '/projects':
        return _json_response(200, {'enabled': False, 'projects': []})
    if path.startswith('/library/'):
        return _json_response(200, [])
    if path == '/comms':
        return _json_response(404, {'code': 'not_found', 'message': 'Not found'})
    if path == '/flows':
        if method in ('GET', 'HEAD'):
            if NRED_AUTH_MODE == 'require' and not authed:
                return _json_response(401, {'error': 'unauthorized'}, 'WWW-Authenticate: Bearer\r\n')
            return _json_response(200, _fake_flows())
        if method in ('POST', 'PUT'):
            if NRED_AUTH_MODE == 'require' and not authed:
                return _json_response(401, {'error': 'unauthorized'}, 'WWW-Authenticate: Bearer\r\n')
            return _json_response(204, {})
    if path == '/nodes':
        if method in ('GET', 'HEAD'):
            return _json_response(200, [
                {'id': 'node-red', 'version': _PROFILE['version'], 'local': True},
                {'id': 'node-red-dashboard', 'version': '3.6.5', 'local': True},
            ])
        if method in ('POST', 'PUT'):
            return _json_response(202, {'message': 'install started'})
    return _json_response(404, {'code': 'not_found', 'message': 'Not found'})


def _flow_summary(body):
    try:
        data = json.loads(body)
    except Exception:
        return None
    nodes = data if isinstance(data, list) else data.get('flows') if isinstance(data, dict) else None
    if not isinstance(nodes, list):
        return None
    types = Counter(str(n.get('type', 'unknown')) for n in nodes if isinstance(n, dict))
    return {
        'node_count': len(nodes),
        'node_types': dict(types.most_common(12)),
        'has_exec': bool(types.get('exec')),
        'has_function': bool(types.get('function')),
        'has_mqtt': any(t.startswith('mqtt') for t in types),
    }


def _display_format(method, path_only, purpose, exploit_name):
    if path_only in ('/auth/login', '/auth/token', '/credentials'):
        return 'auth'
    if method in ('POST', 'PUT') and path_only == '/flows':
        return 'flow'
    exploit_purposes = {
        'remote_code_execution',
        'credential_attempt',
        'node_install',
        'file_write',
        'mqtt_flow_deploy',
        'post_exploit_cleanup',
    }
    if purpose in exploit_purposes:
        return 'exploit'
    return 'request'


def handle_connection(sock, client_ip):
    try:
        raw = _recv_headers(sock)
        if not raw:
            return
        parsed = _parse_request(raw)
        if not parsed:
            return
        body = _read_body(sock, parsed) if parsed['has_body'] else ''
        method = parsed['method']
        path = parsed['path']
        path_only = parsed['path_only']
        ua = parsed['user_agent']
        host = parsed['host']

        _trace(client_ip, 'request', method=method, path=path, ua=ua or None, body_len=len(body))
        try:
            sock.sendall(_response_for(parsed, body))
        except OSError:
            pass

        if path_only == '/favicon.ico' or method == 'PRI':
            return
        if not _should_emit(client_ip):
            return

        purpose, exploit_name = _classify(method, path, ua, body)
        fields = _parse_body_fields(body, parsed.get('content_type', ''))
        username = fields.get('username') or fields.get('user')
        password = fields.get('password') or fields.get('pass')
        client_id = fields.get('client_id')
        grant_type = fields.get('grant_type')

        knock = {
            'type': 'KNOCK',
            'proto': KNOCK_PROTO,
            'ip': client_ip,
            'nred_port': _NRED_PORT,
            'nred_method': method,
            'nred_path': path,
            'nred_purpose': purpose,
            'nred_auth_mode': NRED_AUTH_MODE,
            'display_format': _display_format(method, path_only, purpose, exploit_name),
        }
        if exploit_name:
            knock['nred_exploit'] = exploit_name
        if host:
            knock['nred_host'] = host
        if ua:
            knock['nred_user_agent'] = ua
        if parsed.get('authorization'):
            knock['nred_authorization_seen'] = True
        if username is not None:
            knock['user'] = _safe_text(username, 200)
            knock['nred_user'] = _safe_text(username, 200)
        if password is not None:
            knock['pass'] = _safe_text(password, 300)
            knock['nred_pass'] = _safe_text(password, 300)
        if client_id:
            knock['nred_client_id'] = _safe_text(client_id, 120)
        if grant_type:
            knock['nred_grant_type'] = _safe_text(grant_type, 80)
        summary = _flow_summary(body) if method in ('POST', 'PUT') and path_only == '/flows' else None
        if summary:
            knock['nred_flow_summary'] = summary
            knock['nred_flow_node_count'] = summary.get('node_count')
            knock['nred_flow_has_exec'] = summary.get('has_exec')
            knock['nred_flow_has_mqtt'] = summary.get('has_mqtt')
        if body:
            knock['nred_body'] = _body_preview(body)

        print(json.dumps(knock), flush=True)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    global _NRED_PORT, _PROFILE
    parser = argparse.ArgumentParser(description='Node-RED honeypot')
    parser.add_argument('--port', type=int, default=NRED_PORT)
    parser.add_argument('--ssl', dest='ssl', action='store_true', default=None)
    parser.add_argument('--no-ssl', dest='ssl', action='store_false')
    parser.add_argument('--ssl-cert', default=NRED_TLS_CERT_PATH)
    parser.add_argument('--ssl-key', default=NRED_TLS_KEY_PATH)
    args = parser.parse_args()
    _NRED_PORT = args.port
    _PROFILE = _make_profile()
    use_ssl = args.ssl if args.ssl is not None else False

    ssl_context = None
    if use_ssl:
        ensure_self_signed_server_cert(
            cert_path=args.ssl_cert,
            key_path=args.ssl_key,
            subject='/CN=localhost/O=Node-RED/C=US',
            days=825,
        )
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=args.ssl_cert, keyfile=args.ssl_key)

    server = create_dualstack_tcp_listener(_NRED_PORT)
    label = 'NRED-HTTPS' if use_ssl else 'NRED'
    print(f'🚀 {label} Honeypot Active on Port {_NRED_PORT} (IPv4+IPv6). Collecting knocks...', flush=True)
    while True:
        try:
            conn, addr = server.accept()
            client_ip = normalize_ip(addr[0])
            if is_blocked(client_ip):
                conn.close()
                continue
            if ssl_context:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    conn.close()
                    continue
            threading.Thread(target=handle_connection, args=(conn, client_ip), daemon=True).start()
        except OSError:
            break


if __name__ == '__main__':
    main()

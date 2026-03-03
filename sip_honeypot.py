#!/root/knock-knock/.venv/bin/python
import base64
import json
import os
import random
import re
import socket
import string
import threading
import time
import uuid

import redis

_R = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

SIP_PORT = int(os.environ.get('SIP_PORT', '5060'))
SIP_REALM = os.environ.get('SIP_REALM', 'asterisk')
SIP_MAX_MESSAGES_PER_CONN = max(1, int(os.environ.get('SIP_MAX_MESSAGES_PER_CONN', '6')))
SIP_CONN_TIMEOUT = max(2.0, float(os.environ.get('SIP_CONN_TIMEOUT', '20')))
TRACE_ENABLED = os.environ.get('SIP_TRACE', '1').lower() not in ('0', 'false', 'no')
TRACE_IP = os.environ.get('SIP_TRACE_IP', '').strip()
SIP_AUTH_CHALLENGE_MODE = os.environ.get('SIP_AUTH_CHALLENGE_MODE', 'mixed').strip().lower()


def is_blocked(ip):
    try:
        return _R.sismember('knock:blocked', ip)
    except Exception:
        return False


def normalize_ip(ip):
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip


def trace(session_id, client_ip, stage, **fields):
    if not TRACE_ENABLED:
        return
    if TRACE_IP and client_ip != TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    base = f"SIPTRACE sid={session_id} ip={client_ip} stage={stage}"
    print(f"{base} {suffix}".rstrip(), flush=True)


def _nonce(size=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(size))


def _header_first(headers, name):
    values = headers.get(name.lower())
    if values:
        return values[0]
    return None


def parse_sip_message(raw_bytes):
    text = raw_bytes.decode('utf-8', errors='replace')
    header_end = text.find('\r\n\r\n')
    sep_len = 4
    if header_end < 0:
        header_end = text.find('\n\n')
        sep_len = 2
    if header_end < 0:
        header_text = text
        body = ''
    else:
        header_text = text[:header_end]
        body = text[header_end + sep_len:]

    lines = [ln.rstrip('\r') for ln in header_text.split('\n') if ln != '']
    if not lines:
        return None

    first = lines[0].strip()
    if 'SIP/2.0' not in first:
        return None

    parts = first.split()
    if len(parts) < 3:
        return None

    method = parts[0].upper()
    uri = parts[1]

    headers = {}
    current = None
    for line in lines[1:]:
        if line.startswith((' ', '\t')) and current:
            headers[current][-1] += ' ' + line.strip()
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key_l = key.strip().lower()
        headers.setdefault(key_l, []).append(value.strip())
        current = key_l

    return {
        'method': method,
        'uri': uri,
        'headers': headers,
        'body': body,
        'raw': text,
    }


def extract_user_pass_from_sip_uri(value):
    if not value:
        return None, None
    v = value.strip().strip('<>')
    m = re.search(r'sips?:([^@;>\s]+)@', v, re.IGNORECASE)
    if not m:
        return None, None
    userinfo = m.group(1)
    if ':' in userinfo:
        user, password = userinfo.split(':', 1)
        return user or None, password or None
    return userinfo or None, None


def parse_auth_header(auth_value):
    if not auth_value:
        return None, {}
    s = auth_value.strip()
    if ' ' not in s:
        return s.lower(), {}
    scheme, params = s.split(' ', 1)
    scheme_l = scheme.strip().lower()
    out = {}

    if scheme_l == 'basic':
        token = params.strip().split()[0] if params.strip() else ''
        try:
            decoded = base64.b64decode(token).decode('utf-8', errors='replace')
            if ':' in decoded:
                u, p = decoded.split(':', 1)
                out['username'] = u
                out['password'] = p
            else:
                out['username'] = decoded
                out['password'] = ''
        except Exception:
            pass
        return scheme_l, out

    if scheme_l == 'digest':
        for m in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', params):
            k = m.group(1).lower()
            v = m.group(2) if m.group(2) is not None else m.group(3)
            out[k] = v
        return scheme_l, out

    return scheme_l, out


def build_digest_challenge(req):
    nonce = _nonce()
    hdr = f'Digest realm="{SIP_REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"'
    return hdr


def choose_challenge():
    """
    Decide whether to challenge with:
      - 401 + WWW-Authenticate
      - 407 + Proxy-Authenticate
    """
    mode = SIP_AUTH_CHALLENGE_MODE
    if mode in ('401', 'www', 'www-authenticate'):
        return 401, 'Unauthorized', 'WWW-Authenticate'
    if mode in ('407', 'proxy', 'proxy-authenticate'):
        return 407, 'Proxy Authentication Required', 'Proxy-Authenticate'
    # mixed (default): probabilistically exercise both code paths.
    if random.random() < 0.5:
        return 401, 'Unauthorized', 'WWW-Authenticate'
    return 407, 'Proxy Authentication Required', 'Proxy-Authenticate'


def build_response(req, code, reason, extra_headers=None):
    headers = req.get('headers', {})
    via = _header_first(headers, 'via') or 'SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKknock'
    from_h = _header_first(headers, 'from') or '<sip:unknown@unknown>;tag=knock'
    to_h = _header_first(headers, 'to') or '<sip:unknown@unknown>'
    if 'tag=' not in to_h:
        to_h = f'{to_h};tag=knock{random.randint(1000,9999)}'
    call_id = _header_first(headers, 'call-id') or _nonce(12)
    cseq = _header_first(headers, 'cseq') or '1 REGISTER'

    lines = [
        f'SIP/2.0 {code} {reason}',
        f'Via: {via}',
        f'From: {from_h}',
        f'To: {to_h}',
        f'Call-ID: {call_id}',
        f'CSeq: {cseq}',
        'Server: Asterisk PBX 18.0.0',
        'Content-Length: 0',
    ]
    if extra_headers:
        lines[1:1] = extra_headers
    return ('\r\n'.join(lines) + '\r\n\r\n').encode()


def emit_knock(client_ip, username, password, extra=None):
    knock = {
        'type': 'KNOCK',
        'proto': 'SIP',
        'ip': client_ip,
        'user': username or '',
        'pass': password or '',
    }
    if extra:
        knock.update(extra)
    print(json.dumps(knock), flush=True)


def process_sip_request(req, client_ip):
    headers = req.get('headers', {})
    method = req.get('method', 'UNKNOWN')
    uri = req.get('uri', '')
    common = {
        'sip_method': method,
        'sip_request_uri': uri,
    }

    auth_h = _header_first(headers, 'authorization') or _header_first(headers, 'proxy-authorization')
    scheme, auth = parse_auth_header(auth_h)

    # Capture leaked credentials embedded in SIP URIs (rare but valuable).
    for field_name, candidate in [
        ('request_uri', req.get('uri')),
        ('from', _header_first(headers, 'from')),
        ('to', _header_first(headers, 'to')),
        ('contact', _header_first(headers, 'contact')),
    ]:
        u, p = extract_user_pass_from_sip_uri(candidate)
        if u and p:
            emit_knock(client_ip, u, p, extra={**common, 'sip_cred_source': f'uri:{field_name}'})

    if scheme == 'basic' and auth.get('username') is not None:
        emit_knock(
            client_ip,
            auth.get('username'),
            auth.get('password', ''),
            extra={
                **common,
                'sip_auth_scheme': 'basic',
                'sip_auth_user': auth.get('username', ''),
                'sip_cred_source': 'authorization',
            },
        )
        return 403, 'Forbidden', None

    if scheme == 'digest' and auth.get('username') is not None:
        # SIP Digest auth does not expose plaintext passwords.
        hashed_marker = '<digest response>'
        emit_knock(
            client_ip,
            auth.get('username'),
            hashed_marker,
            extra={
                **common,
                'sip_auth_scheme': 'digest',
                'sip_auth_user': auth.get('username', ''),
                'sip_digest_username': auth.get('username', ''),
                'sip_digest_realm': auth.get('realm', ''),
                'sip_digest_nonce': auth.get('nonce', ''),
                'sip_digest_uri': auth.get('uri', ''),
                'sip_digest_response': auth.get('response', ''),
                'sip_digest_algorithm': auth.get('algorithm', ''),
                'sip_digest_qop': auth.get('qop', ''),
                'sip_digest_nc': auth.get('nc', ''),
                'sip_digest_cnonce': auth.get('cnonce', ''),
                'sip_cred_source': 'authorization',
            },
        )
        return 403, 'Forbidden', None

    # No auth supplied yet. Capture any username hints from URI/From.
    u, _ = extract_user_pass_from_sip_uri(req.get('uri'))
    if not u:
        u, _ = extract_user_pass_from_sip_uri(_header_first(headers, 'from'))

    if method in ('REGISTER', 'INVITE', 'SUBSCRIBE', 'MESSAGE', 'OPTIONS'):
        challenge = build_digest_challenge(req)
        status_code, status_reason, auth_header_name = choose_challenge()
        if u:
            emit_knock(
                client_ip,
                u,
                '',
                extra={
                    **common,
                    'sip_cred_source': 'username_hint',
                    'sip_challenge_mode': str(status_code),
                },
            )
        return status_code, status_reason, [f'{auth_header_name}: {challenge}']

    return 200, 'OK', None


def udp_loop(sock):
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            client_ip = normalize_ip(addr[0])
            session_id = f"u{uuid.uuid4().hex[:8]}"
            if is_blocked(client_ip):
                trace(session_id, client_ip, 'udp_blocked')
                continue
            trace(session_id, client_ip, 'udp_recv', bytes=len(data))
            req = parse_sip_message(data)
            if not req:
                trace(session_id, client_ip, 'udp_parse_invalid')
                continue
            trace(session_id, client_ip, 'udp_parsed', method=req.get('method'), uri=req.get('uri'))
            code, reason, extra_headers = process_sip_request(req, client_ip)
            resp = build_response(req, code, reason, extra_headers=extra_headers)
            try:
                sock.sendto(resp, addr)
                trace(session_id, client_ip, 'udp_response_sent', code=code, reason=reason)
            except Exception:
                trace(session_id, client_ip, 'udp_response_send_failed')
                pass
        except Exception:
            pass


def recv_one_sip_message(sock, timeout):
    sock.settimeout(timeout)
    buf = b''
    start = time.time()

    while time.time() - start < timeout:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None, 'timeout', len(buf)
        except Exception as e:
            return None, f'recv_error:{type(e).__name__}', len(buf)
        if not chunk:
            return None, 'peer_closed', len(buf)
        buf += chunk

        header_end = buf.find(b'\r\n\r\n')
        delim_len = 4
        if header_end < 0:
            header_end = buf.find(b'\n\n')
            delim_len = 2
        if header_end < 0:
            continue

        header_blob = buf[:header_end].decode('utf-8', errors='replace')
        m = re.search(r'(?im)^Content-Length\s*:\s*(\d+)\s*$', header_blob)
        content_len = int(m.group(1)) if m else 0
        need = header_end + delim_len + content_len
        if len(buf) < need:
            continue

        msg = buf[:need]
        return msg, 'ok', len(buf)

    return None, 'incomplete_timeout', len(buf)


def handle_tcp_client(client_sock, client_ip):
    session_id = uuid.uuid4().hex[:8]
    started_at = time.time()
    message_count = 0
    stop_reason = 'unknown'
    trace(session_id, client_ip, 'tcp_connect')
    try:
        for _ in range(SIP_MAX_MESSAGES_PER_CONN):
            raw, recv_status, recv_bytes = recv_one_sip_message(client_sock, SIP_CONN_TIMEOUT)
            if not raw:
                stop_reason = recv_status
                trace(session_id, client_ip, 'tcp_recv_end', reason=recv_status, buffered_bytes=recv_bytes, message_count=message_count)
                break
            message_count += 1
            trace(session_id, client_ip, 'tcp_recv_message', index=message_count, bytes=recv_bytes)
            req = parse_sip_message(raw)
            if not req:
                stop_reason = 'parse_invalid'
                trace(session_id, client_ip, 'tcp_parse_invalid', index=message_count)
                break
            trace(session_id, client_ip, 'tcp_parsed', index=message_count, method=req.get('method'), uri=req.get('uri'))
            code, reason, extra_headers = process_sip_request(req, client_ip)
            resp = build_response(req, code, reason, extra_headers=extra_headers)
            try:
                client_sock.sendall(resp)
                trace(session_id, client_ip, 'tcp_response_sent', index=message_count, code=code, reason=reason)
            except Exception:
                stop_reason = 'send_failed'
                trace(session_id, client_ip, 'tcp_response_send_failed', index=message_count, code=code, reason=reason)
                break
        else:
            stop_reason = 'max_messages_reached'
            trace(session_id, client_ip, 'tcp_loop_limit', max_messages=SIP_MAX_MESSAGES_PER_CONN)
    except Exception:
        stop_reason = 'handler_exception'
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        duration_ms = int((time.time() - started_at) * 1000)
        trace(
            session_id,
            client_ip,
            'tcp_session_summary',
            duration_ms=duration_ms,
            message_count=message_count,
            multi_message=(message_count > 1),
            stop_reason=stop_reason,
        )


def tcp_loop(sock):
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            try:
                client.close()
            except Exception:
                pass
            continue
        threading.Thread(target=handle_tcp_client, args=(client, client_ip), daemon=True).start()


def start_honeypot():
    udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    udp_sock.bind(('::', SIP_PORT))

    tcp_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    tcp_sock.bind(('::', SIP_PORT))
    tcp_sock.listen(200)

    print(f'🚀 SIP Honeypot Active on Port {SIP_PORT} (UDP+TCP IPv4+IPv6). Collecting radiation...', flush=True)

    threading.Thread(target=udp_loop, args=(udp_sock,), daemon=True).start()
    tcp_loop(tcp_sock)


if __name__ == '__main__':
    start_honeypot()

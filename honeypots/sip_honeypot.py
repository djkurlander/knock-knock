#!/usr/bin/env python3
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

import phonenumbers
from phonenumbers import geocoder as pn_geocoder

from common import (
    create_dualstack_tcp_listener,
    create_dualstack_udp_listener,
    is_blocked,
    normalize_ip,
)

SIP_PORT = int(os.environ.get('SIP_PORT', '5060'))
SIP_REALM = os.environ.get('SIP_REALM', 'asterisk')
SIP_MAX_MESSAGES_PER_CONN = max(1, int(os.environ.get('SIP_MAX_MESSAGES_PER_CONN', '6')))
SIP_CONN_TIMEOUT = max(2.0, float(os.environ.get('SIP_CONN_TIMEOUT', '20')))
TRACE_ENABLED = os.environ.get('SIP_TRACE', '1').lower() not in ('0', 'false', 'no')
TRACE_IP = os.environ.get('SIP_TRACE_IP', '').strip()
SIP_AUTH_CHALLENGE_MODE = os.environ.get('SIP_AUTH_CHALLENGE_MODE', 'mixed').strip().lower()
SIP_THROTTLE_PER_SEC = 10
SIP_DEDUP_WINDOW_SEC = int(os.environ.get('SIP_DEDUP_WINDOW_SEC', '60'))

_emit_lock = threading.Lock()
_emit_window_sec = int(time.time())
_emit_window_counts = {}
_dedup_lock = threading.Lock()
_dedup_seen = {}
_ack_lock = threading.Lock()
_ack_seen = {}


def trace(session_id, client_ip, stage, **fields):
    if not TRACE_ENABLED:
        return
    if TRACE_IP and client_ip != TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    base = f"SIPTRACE sid={session_id} ip={client_ip} stage={stage}"
    print(f"{base} {suffix}".rstrip(), flush=True)


def should_emit_knock(client_ip):
    """
    Per-IP drop throttle: at most SIP_THROTTLE_PER_SEC knock events per second
    for each source IP. Applies across UDP and all TCP worker threads.
    """
    global _emit_window_sec, _emit_window_counts
    if SIP_THROTTLE_PER_SEC <= 0:
        return True
    now = int(time.time())
    with _emit_lock:
        if now != _emit_window_sec:
            _emit_window_sec = now
            _emit_window_counts = {}
        current = _emit_window_counts.get(client_ip, 0)
        if current >= SIP_THROTTLE_PER_SEC:
            return False
        _emit_window_counts[client_ip] = current + 1
        return True


def _dedup_key(client_ip, req):
    headers = req.get('headers', {})
    call_id = _header_first(headers, 'call-id') or ''
    method = req.get('method', 'UNKNOWN')
    uri = req.get('uri', '')
    return (client_ip, call_id, method, uri)


def should_emit_dedup(dedup_key):
    global _dedup_seen
    if SIP_DEDUP_WINDOW_SEC <= 0:
        return True
    now = time.time()
    with _dedup_lock:
        cutoff = now - SIP_DEDUP_WINDOW_SEC
        stale = [k for k, ts in _dedup_seen.items() if ts < cutoff]
        for k in stale:
            _dedup_seen.pop(k, None)
        ts = _dedup_seen.get(dedup_key)
        if ts is not None and (now - ts) < SIP_DEDUP_WINDOW_SEC:
            return False
        _dedup_seen[dedup_key] = now
        return True


def _ack_key(client_ip, req):
    headers = req.get('headers', {})
    call_id = _header_first(headers, 'call-id') or ''
    uri = req.get('uri', '')
    return (client_ip, call_id, uri)


def mark_ack_seen(client_ip, req):
    key = _ack_key(client_ip, req)
    now = time.time()
    with _ack_lock:
        # Keep only recent ACK markers to avoid unbounded growth.
        cutoff = now - 120
        stale = [k for k, ts in _ack_seen.items() if ts < cutoff]
        for k in stale:
            _ack_seen.pop(k, None)
        _ack_seen[key] = now


def get_ack_state(client_ip, req):
    key = _ack_key(client_ip, req)
    now = time.time()
    with _ack_lock:
        ts = _ack_seen.get(key)
    if ts is None:
        return False, None
    age_ms = int((now - ts) * 1000)
    return True, max(0, age_ms)


def _nonce(size=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(size))


def _sip_tag(size=10):
    # Keep tag token wire-safe and non-branded.
    alphabet = string.ascii_lowercase + string.digits
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

    raw = value.strip()
    if not raw:
        return None, None

    # SIP headers often embed the URI in angle brackets after a display name.
    if '<' in raw and '>' in raw:
        start = raw.find('<')
        end = raw.find('>', start + 1)
        if end > start:
            raw = raw[start + 1:end].strip()
    else:
        raw = raw.strip('<>')

    m = re.match(r'(?i)^sips?:', raw)
    if not m:
        return None, None

    remainder = raw[m.end():]
    at_idx = remainder.find('@')
    if at_idx <= 0:
        return None, None

    userinfo = remainder[:at_idx]
    if ':' in userinfo:
        user, password = userinfo.split(':', 1)
        return user or None, password or None
    return userinfo or None, None


def parse_dial_country(dial_string):
    """Extract target country (iso, name) from a SIP INVITE dial string."""
    if not dial_string:
        return None, None
    s = re.sub(r'^sips?:', '', dial_string)
    s = s.split('@')[0]
    s = s.lstrip('*#')

    def _result(pn):
        iso = phonenumbers.region_code_for_number(pn)
        desc = pn_geocoder.description_for_number(pn, 'en')
        name = desc or pn_geocoder.country_name_for_number(pn, 'en') or iso
        return iso, name

    if s.startswith('+'):
        try:
            pn = phonenumbers.parse(s, None)
            if phonenumbers.is_valid_number(pn) or phonenumbers.is_possible_number(pn):
                return _result(pn)
        except Exception:
            pass
        return None, None
    if not re.match(r'^\d+$', s):
        return None, None
    if len(s) < 7:
        return None, None
    # North American long-distance: 1 + 10 digits
    if re.match(r'^1\d{10}$', s):
        try:
            pn = phonenumbers.parse('+' + s, None)
            if phonenumbers.is_valid_number(pn):
                return _result(pn)
        except Exception:
            pass
        return None, None
    for prefix in ('011', '00'):
        idx = s.find(prefix)
        if idx >= 0:
            remainder = s[idx + len(prefix):]
            if len(remainder) >= 7:
                try:
                    pn = phonenumbers.parse('+' + remainder, None)
                    if phonenumbers.is_valid_number(pn) or phonenumbers.is_possible_number(pn):
                        return _result(pn)
                except Exception:
                    pass
    max_strip = min(8, len(s) - 7)
    for i in range(1, max_strip + 1):
        try:
            pn = phonenumbers.parse('+' + s[i:], None)
            if phonenumbers.is_valid_number(pn):
                return _result(pn)
        except Exception:
            continue
    return None, None


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
    via = _header_first(headers, 'via') or f'SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK{_sip_tag(12)}'
    from_h = _header_first(headers, 'from') or f'<sip:unknown@unknown>;tag={_sip_tag(10)}'
    to_h = _header_first(headers, 'to') or '<sip:unknown@unknown>'
    if not re.search(r'(^|;)\s*tag=', to_h, flags=re.IGNORECASE):
        to_h = f'{to_h};tag={_sip_tag(10)}'
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


def emit_knock(client_ip, extra=None, dedup_key=None):
    if not should_emit_knock(client_ip):
        return
    if dedup_key is not None and not should_emit_dedup(dedup_key):
        return
    knock = {
        'type': 'KNOCK',
        'proto': 'SIP',
        'ip': client_ip,
    }
    if extra:
        knock.update(extra)
    print(json.dumps(knock), flush=True)


def process_sip_request(req, client_ip):
    headers = req.get('headers', {})
    method = req.get('method', 'UNKNOWN')
    uri = req.get('uri', '')
    if method == 'ACK':
        # ACK is SIP transaction bookkeeping; do not count as a knock.
        mark_ack_seen(client_ip, req)
        return 200, 'OK', None
    dedup_key = _dedup_key(client_ip, req)
    ack_seen, ack_age_ms = get_ack_state(client_ip, req)
    common = {
        'sip_method': method,
        'sip_request_uri': uri,
        'sip_call_id': _header_first(headers, 'call-id') or '',
        'sip_cseq': _header_first(headers, 'cseq') or '',
        'sip_ack_seen': ack_seen,
    }
    if ack_age_ms is not None:
        common['sip_ack_age_ms'] = ack_age_ms
    if method == 'INVITE':
        dial_iso, dial_name = parse_dial_country(uri)
        if dial_iso:
            common['sip_dial_country'] = dial_iso
            common['sip_dial_country_name'] = dial_name

    auth_h = _header_first(headers, 'authorization') or _header_first(headers, 'proxy-authorization')
    scheme, auth = parse_auth_header(auth_h)

    # Capture URI userinfo candidates for fallback identity extraction.
    uri_candidates = []
    for field_name, candidate in [
        ('request_uri', req.get('uri')),
        ('from', _header_first(headers, 'from')),
        ('contact', _header_first(headers, 'contact')),
        ('to', _header_first(headers, 'to')),
    ]:
        u, p = extract_user_pass_from_sip_uri(candidate)
        if u:
            uri_candidates.append((field_name, u, p))

    if scheme == 'basic' and auth.get('username') is not None:
        emit_knock(
            client_ip,
            extra={
                **common,
                'sip_stage': 'auth',
                'sip_auth_scheme': 'basic',
                'sip_auth_user': auth.get('username', ''),
                'sip_auth_password': auth.get('password', ''),
                'sip_cred_source': 'authorization',
                'sip_extension': auth.get('username', ''),
            },
            dedup_key=dedup_key,
        )
        return 403, 'Forbidden', None

    if scheme == 'digest' and auth.get('username') is not None:
        # SIP Digest auth does not expose plaintext passwords.
        emit_knock(
            client_ip,
            extra={
                **common,
                'sip_stage': 'auth',
                'sip_auth_scheme': 'digest',
                'sip_auth_user': auth.get('username', ''),
                'sip_auth_password': '',
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
                'sip_extension': auth.get('username', ''),
            },
            dedup_key=dedup_key,
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
                extra={
                    **common,
                    'sip_stage': 'hint',
                    'sip_cred_source': 'username_hint',
                    'sip_extension': u,
                    'sip_challenge_mode': str(status_code),
                },
                dedup_key=dedup_key,
            )
        elif uri_candidates:
            field_name, uri_user, uri_pass = uri_candidates[0]
            extra = {
                **common,
                'sip_stage': 'uri',
                'sip_cred_source': f'uri:{field_name}',
                'sip_uri_user': uri_user,
                'sip_extension': uri_user,
                'sip_challenge_mode': str(status_code),
            }
            if uri_pass:
                extra['sip_uri_password'] = uri_pass
                extra['sip_uri_userinfo'] = f'{uri_user}:{uri_pass}'
            emit_knock(client_ip, extra=extra, dedup_key=dedup_key)
        return status_code, status_reason, [f'{auth_header_name}: {challenge}']

    if uri_candidates:
        field_name, uri_user, uri_pass = uri_candidates[0]
        extra = {
            **common,
            'sip_stage': 'uri',
            'sip_cred_source': f'uri:{field_name}',
            'sip_uri_user': uri_user,
            'sip_extension': uri_user,
        }
        if uri_pass:
            extra['sip_uri_password'] = uri_pass
            extra['sip_uri_userinfo'] = f'{uri_user}:{uri_pass}'
        emit_knock(client_ip, extra=extra, dedup_key=dedup_key)

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
            # SIP TCP sessions can carry multiple requests; enforce blocklist
            # on each loop so newly blocked IPs are cut off immediately.
            if is_blocked(client_ip):
                stop_reason = 'blocked_mid_session'
                trace(session_id, client_ip, 'tcp_blocked_mid_session', message_count=message_count)
                break
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
            trace(f"t{uuid.uuid4().hex[:8]}", client_ip, 'tcp_blocked_accept')
            try:
                client.close()
            except Exception:
                pass
            continue
        threading.Thread(target=handle_tcp_client, args=(client, client_ip), daemon=True).start()


def start_honeypot():
    udp_sock = create_dualstack_udp_listener(SIP_PORT)

    tcp_sock = create_dualstack_tcp_listener(SIP_PORT, backlog=200)

    print(f'🚀 SIP Honeypot Active on Port {SIP_PORT} (UDP+TCP IPv4+IPv6). Collecting radiation...', flush=True)

    threading.Thread(target=udp_loop, args=(udp_sock,), daemon=True).start()
    tcp_loop(tcp_sock)


if __name__ == '__main__':
    start_honeypot()

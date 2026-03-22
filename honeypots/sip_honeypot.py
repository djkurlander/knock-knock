#!/usr/bin/env python3
import base64
import json
import os
import random
import re
import socket
import string
import sys
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
_reg_lock = threading.Lock()
_registered_extensions = {}
_dial_cache_lock = threading.Lock()
_dial_cache = []  # list of (digits_str, iso, name), max 50 entries


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


COUNTRY_COORDS = {
    'AC': (-7.94, -14.36), 'AD': (42.51, 1.52), 'AE': (24.45, 54.65),
    'AF': (34.53, 69.17), 'AG': (17.12, -61.85), 'AI': (18.22, -63.05),
    'AL': (41.33, 19.82), 'AM': (40.18, 44.51), 'AO': (-8.84, 13.23),
    'AR': (-34.60, -58.38), 'AS': (-14.27, -170.70), 'AT': (48.21, 16.37),
    'AU': (-35.28, 149.13), 'AW': (12.51, -69.97), 'AX': (60.10, 19.94),
    'AZ': (40.41, 49.87), 'BA': (43.86, 18.41), 'BB': (13.10, -59.62),
    'BD': (23.81, 90.41), 'BE': (50.85, 4.35), 'BF': (12.37, -1.52),
    'BG': (42.70, 23.32), 'BH': (26.23, 50.58), 'BI': (-3.38, 29.36),
    'BJ': (6.50, 2.60), 'BL': (17.90, -62.83), 'BM': (32.29, -64.78),
    'BN': (4.94, 114.95), 'BO': (-16.50, -68.15), 'BQ': (12.14, -68.27),
    'BR': (-15.79, -47.88), 'BS': (25.05, -77.35), 'BT': (27.47, 89.64),
    'BW': (-24.65, 25.91), 'BY': (53.90, 27.57), 'BZ': (17.25, -88.77),
    'CA': (45.42, -75.70), 'CC': (-12.19, 96.83), 'CD': (-4.32, 15.31),
    'CF': (4.36, 18.56), 'CG': (-4.27, 15.28), 'CH': (46.95, 7.45),
    'CI': (6.85, -5.30), 'CK': (-21.21, -159.78), 'CL': (-33.45, -70.67),
    'CM': (3.87, 11.52), 'CN': (39.91, 116.40), 'CO': (4.71, -74.07),
    'CR': (9.93, -84.08), 'CU': (23.11, -82.37), 'CV': (14.93, -23.51),
    'CW': (12.17, -68.98), 'CX': (-10.49, 105.63), 'CY': (35.17, 33.37),
    'CZ': (50.08, 14.43), 'DE': (52.52, 13.41), 'DJ': (11.59, 43.15),
    'DK': (55.68, 12.57), 'DM': (15.30, -61.39), 'DO': (18.47, -69.90),
    'DZ': (36.74, 3.06), 'EC': (-0.18, -78.47), 'EE': (59.44, 24.75),
    'EG': (30.04, 31.24), 'EH': (27.15, -13.20), 'ER': (15.34, 38.93),
    'ES': (40.42, -3.70), 'ET': (9.02, 38.75), 'FI': (60.17, 24.94),
    'FJ': (-18.14, 178.44), 'FK': (-51.70, -57.85), 'FM': (6.92, 158.16),
    'FO': (62.01, -6.77), 'FR': (48.86, 2.35), 'GA': (0.39, 9.45),
    'GB': (51.51, -0.13), 'GD': (12.06, -61.75), 'GE': (41.69, 44.80),
    'GF': (4.94, -52.33), 'GG': (49.45, -2.54), 'GH': (5.56, -0.19),
    'GI': (36.14, -5.35), 'GL': (64.17, -51.74), 'GM': (13.45, -16.58),
    'GN': (9.64, -13.58), 'GP': (16.00, -61.73), 'GQ': (3.75, 8.78),
    'GR': (37.98, 23.73), 'GT': (14.63, -90.51), 'GU': (13.47, 144.75),
    'GW': (11.86, -15.60), 'GY': (6.80, -58.16), 'HK': (22.32, 114.17),
    'HN': (14.07, -87.19), 'HR': (45.81, 15.98), 'HT': (18.54, -72.34),
    'HU': (47.50, 19.04), 'ID': (-6.21, 106.85), 'IE': (53.35, -6.26),
    'IL': (31.77, 35.22), 'IM': (54.15, -4.48), 'IN': (28.61, 77.21),
    'IO': (-7.31, 72.42), 'IQ': (33.31, 44.37), 'IR': (35.69, 51.39),
    'IS': (64.15, -21.94), 'IT': (41.90, 12.50), 'JE': (49.21, -2.13),
    'JM': (18.00, -76.79), 'JO': (31.95, 35.93), 'JP': (35.68, 139.69),
    'KE': (-1.29, 36.82), 'KG': (42.87, 74.59), 'KH': (11.56, 104.92),
    'KI': (1.33, 172.98), 'KM': (-11.70, 43.26), 'KN': (17.30, -62.73),
    'KP': (39.02, 125.75), 'KR': (37.57, 126.98), 'KW': (29.38, 47.99),
    'KY': (19.30, -81.38), 'KZ': (51.17, 71.43), 'LA': (17.97, 102.63),
    'LB': (33.89, 35.50), 'LC': (14.01, -60.99), 'LI': (47.14, 9.52),
    'LK': (6.93, 79.84), 'LR': (6.30, -10.80), 'LS': (-29.31, 27.48),
    'LT': (54.69, 25.28), 'LU': (49.61, 6.13), 'LV': (56.95, 24.11),
    'LY': (32.90, 13.18), 'MA': (34.02, -6.84), 'MC': (43.73, 7.42),
    'MD': (47.01, 28.86), 'ME': (42.44, 19.26), 'MF': (18.07, -63.08),
    'MG': (-18.88, 47.51), 'MH': (7.09, 171.38), 'MK': (42.00, 21.43),
    'ML': (12.64, -8.00), 'MM': (19.76, 96.07), 'MN': (47.91, 106.91),
    'MO': (22.20, 113.54), 'MP': (15.18, 145.75), 'MQ': (14.60, -61.07),
    'MR': (18.09, -15.98), 'MS': (16.74, -62.19), 'MT': (35.90, 14.51),
    'MU': (-20.17, 57.50), 'MV': (4.18, 73.51), 'MW': (-13.97, 33.79),
    'MX': (19.43, -99.13), 'MY': (3.14, 101.69), 'MZ': (-25.97, 32.57),
    'NA': (-22.56, 17.08), 'NC': (-22.28, 166.46), 'NE': (13.51, 2.11),
    'NF': (-29.05, 167.95), 'NG': (9.06, 7.49), 'NI': (12.11, -86.27),
    'NL': (52.37, 4.90), 'NO': (59.91, 10.75), 'NP': (27.72, 85.32),
    'NR': (-0.52, 166.93), 'NU': (-19.05, -169.92), 'NZ': (-41.29, 174.78),
    'OM': (23.59, 58.54), 'PA': (8.98, -79.52), 'PE': (-12.05, -77.04),
    'PF': (-17.53, -149.57), 'PG': (-6.31, 147.00), 'PH': (14.60, 120.98),
    'PK': (33.69, 73.04), 'PL': (52.23, 21.01), 'PM': (46.78, -56.18),
    'PR': (18.47, -66.11), 'PS': (31.90, 35.20), 'PT': (38.72, -9.14),
    'PW': (7.50, 134.62), 'PY': (-25.26, -57.58), 'QA': (25.29, 51.53),
    'RE': (-20.88, 55.45), 'RO': (44.43, 26.10), 'RS': (44.79, 20.51),
    'RU': (55.76, 37.62), 'RW': (-1.94, 29.87), 'SA': (24.69, 46.72),
    'SB': (-9.43, 160.03), 'SC': (-4.62, 55.45), 'SD': (15.60, 32.53),
    'SE': (59.33, 18.07), 'SG': (1.35, 103.82), 'SH': (-15.97, -5.70),
    'SI': (46.06, 14.51), 'SJ': (78.22, 15.63), 'SK': (48.15, 17.11),
    'SL': (8.48, -13.23), 'SM': (43.94, 12.46), 'SN': (14.69, -17.44),
    'SO': (2.05, 45.32), 'SR': (5.85, -55.17), 'SS': (4.85, 31.60),
    'ST': (0.34, 6.73), 'SV': (13.69, -89.19), 'SX': (18.04, -63.06),
    'SY': (33.51, 36.29), 'SZ': (-26.31, 31.13), 'TA': (-37.07, -12.32),
    'TC': (21.47, -71.14), 'TD': (12.13, 15.05), 'TG': (6.17, 1.23),
    'TH': (13.76, 100.50), 'TJ': (38.56, 68.77), 'TK': (-9.20, -171.84),
    'TL': (-8.56, 125.57), 'TM': (37.95, 58.38), 'TN': (36.81, 10.18),
    'TO': (-21.21, -175.20), 'TR': (39.93, 32.85), 'TT': (10.66, -61.51),
    'TV': (-8.52, 179.20), 'TW': (25.03, 121.57), 'TZ': (-6.79, 39.28),
    'UA': (50.45, 30.52), 'UG': (0.35, 32.58), 'US': (38.90, -77.04),
    'UY': (-34.88, -56.18), 'UZ': (41.30, 69.28), 'VA': (41.90, 12.45),
    'VC': (13.16, -61.23), 'VE': (10.49, -66.88), 'VG': (18.43, -64.62),
    'VI': (18.34, -64.93), 'VN': (21.03, 105.85), 'VU': (-17.73, 168.32),
    'WF': (-13.28, -176.18), 'WS': (-13.83, -171.76), 'XK': (42.66, 21.17),
    'YE': (15.35, 44.21), 'YT': (-12.78, 45.23), 'ZA': (-25.75, 28.19),
    'ZM': (-15.39, 28.32), 'ZW': (-17.83, 31.05),
}


def parse_dial_country(dial_string):
    """Extract target country (iso, name, e164) from a SIP INVITE dial string."""
    if not dial_string:
        return None, None, None
    s = re.sub(r'^sips?:', '', dial_string)
    s = s.split('@')[0]
    s = s.lstrip('*#')
    s = s.replace('.', '').replace('-', '')
    if s.startswith('++'):
        s = s[1:]
    # PBX external line prefix before + (e.g. 0+421..., 00+421...)
    plus = s.find('+')
    if plus > 0 and s[:plus].isdigit():
        s = s[plus:]

    def _result(pn):
        iso = phonenumbers.region_code_for_number(pn)
        country = pn_geocoder.country_name_for_number(pn, 'en') or iso
        desc = pn_geocoder.description_for_number(pn, 'en')
        name = f'{desc}, {country}' if desc and desc != country else country
        e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        return iso, name, e164

    # Check suffix against recently seen valid numbers (catches arbitrary PBX prefixes)
    digits_only = s.lstrip('+')
    if re.match(r'^\d{7,}$', digits_only):
        with _dial_cache_lock:
            for cached_digits, cached_iso, cached_name in _dial_cache:
                if digits_only.endswith(cached_digits):
                    print(f'SIP CACHE: hit {digits_only} matched +{cached_digits} -> {cached_iso} ({cached_name})', file=sys.stderr)
                    return cached_iso, cached_name, f'+{cached_digits}'

    if s.startswith('+'):
        try:
            pn = phonenumbers.parse(s, None)
            if phonenumbers.is_valid_number(pn) or phonenumbers.is_possible_number(pn):
                iso, name, e164 = _result(pn)
                digits = e164.lstrip('+')
                with _dial_cache_lock:
                    _dial_cache[:] = [(d, i, n) for d, i, n in _dial_cache if d != digits]
                    _dial_cache.append((digits, iso, name))
                    if len(_dial_cache) > 50:
                        _dial_cache.pop(0)
                print(f'SIP CACHE: stored +{digits} -> {iso} ({name})', file=sys.stderr)
                return iso, name, e164
        except Exception:
            pass
        # Failed as E.164 — strip + and try as digits (e.g. ++011972... → 011972...)
        s = s.lstrip('+')
    if not re.match(r'^\d+$', s):
        return None, None, None
    if len(s) < 7:
        return None, None, None
    # North American long-distance: 1 + 10 digits
    if re.match(r'^1\d{10}$', s):
        try:
            pn = phonenumbers.parse('+' + s, None)
            if phonenumbers.is_valid_number(pn):
                return _result(pn)
        except Exception:
            pass
        return None, None, None
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
    # Raw E.164 without '+' (some PBXes accept country code directly)
    try:
        pn = phonenumbers.parse('+' + s, None)
        if phonenumbers.is_valid_number(pn):
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
    return None, None, None


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
    # Extract raw dial string from URI (strip sip: scheme and @host)
    dial_string = re.sub(r'^sips?:', '', uri).split('@')[0] if uri else ''
    common = {
        'sip_method': method,
        'sip_dial_string': dial_string,
        'sip_call_id': _header_first(headers, 'call-id') or '',
        'sip_cseq': _header_first(headers, 'cseq') or '',
        'sip_ack_seen': ack_seen,
    }
    if ack_age_ms is not None:
        common['sip_ack_age_ms'] = ack_age_ms
    if method == 'INVITE':
        dial_iso, dial_name, dial_e164 = parse_dial_country(uri)
        if not dial_iso:
            print(f'SIP: no location for INVITE uri={uri}', file=sys.stderr)
        if dial_iso:
            print(f'SIP DIAL: {dial_string} → {dial_e164} → {dial_iso} ({dial_name})', file=sys.stderr)
            common['sip_dial_number'] = dial_e164
            common['sip_dial_country'] = dial_iso
            common['sip_dial_country_name'] = dial_name
            coords = COUNTRY_COORDS.get(dial_iso)
            if coords:
                common['sip_dial_lat'] = coords[0]
                common['sip_dial_lng'] = coords[1]

    auth_h = _header_first(headers, 'authorization') or _header_first(headers, 'proxy-authorization')
    scheme, auth = parse_auth_header(auth_h)

    # Extract extension from auth header, request URI, or From header.
    ext = auth.get('username') if auth.get('username') else None
    if not ext:
        ext, _ = extract_user_pass_from_sip_uri(req.get('uri'))
    if not ext:
        ext, _ = extract_user_pass_from_sip_uri(_header_first(headers, 'from'))

    # --- REGISTER: never emit a knock; store extension, accept or challenge ---
    if method == 'REGISTER':
        if scheme in ('basic', 'digest') and auth.get('username') is not None:
            if ext:
                with _reg_lock:
                    _registered_extensions[client_ip] = ext
            return 200, 'OK', None
        # No auth yet — challenge so they send credentials.
        challenge = build_digest_challenge(req)
        status_code, status_reason, auth_header_name = choose_challenge()
        return status_code, status_reason, [f'{auth_header_name}: {challenge}']

    # --- INVITE: emit a knock if there's a number being dialed ---
    if method == 'INVITE':
        dial_user, _ = extract_user_pass_from_sip_uri(uri)
        if not dial_user:
            return 404, 'Not Found', None
        # Skip short extension probes (< 7 digits) — not toll fraud
        digits_only = re.sub(r'\D', '', dial_user)
        if len(digits_only) < 7:
            return 404, 'Not Found', None
        with _reg_lock:
            reg_ext = _registered_extensions.get(client_ip)
        if reg_ext:
            common['sip_extension'] = reg_ext
        emit_knock(client_ip, extra=common, dedup_key=dedup_key)
        return 484, 'Address Incomplete', None

    # --- Other methods: challenge or accept, no knock ---
    if scheme in ('basic', 'digest') and auth.get('username') is not None:
        return 200, 'OK', None
    if method in ('SUBSCRIBE', 'MESSAGE', 'OPTIONS'):
        challenge = build_digest_challenge(req)
        status_code, status_reason, auth_header_name = choose_challenge()
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

#!/usr/bin/env python3
"""Small SIP B2BUA bridge for the SIP honeypot.

This module deliberately implements a narrow bridge: UDP only, one PBX upstream,
and PCMU/PCMA SDP. It keeps Asterisk/PBX details out of sip_honeypot.py.
"""

import ipaddress
import os
import random
import re
import socket
import string
import struct
import sys
import threading
import time
import uuid

import sip_live_permit

PBX_HOST = os.environ.get('PBX_HOST', '').strip()
PBX_PORT = int(os.environ.get('PBX_PORT', '5060'))
PBX_DIAL_POLICY = os.environ.get('PBX_DIAL_POLICY', 'all').strip()
SIP_PUBLIC_IP = os.environ.get('SIP_PUBLIC_IP', '').strip()
PBX_RTP_PORT_START = int(os.environ.get('PBX_RTP_PORT_START', '30000'))
PBX_RTP_PORT_END = int(os.environ.get('PBX_RTP_PORT_END', '30100'))
PBX_CALL_TIMEOUT = max(5.0, float(os.environ.get('PBX_CALL_TIMEOUT', '120')))
# Tear a bridge down if the PBX answered but the attacker never ACKed within this
# many seconds (silent-abandon probers: INVITE, see 200, vanish). 0 disables.
PBX_ABANDON_SECONDS = float(os.environ.get('PBX_ABANDON_SECONDS', '4'))
# Reap a bridge the PBX never responds to *at all* (no 100/18x/2xx) within this many
# seconds. Asterisk emits 100 Trying near-instantly, so silence here means the INVITE
# was dropped (e.g. Asterisk overloaded under a pump). Without this, such zombie
# bridges squat their RTP relay ports until PBX_CALL_TIMEOUT. 0 disables.
PBX_NO_RESPONSE_SECONDS = float(os.environ.get('PBX_NO_RESPONSE_SECONDS', '10'))
# Cap on concurrent bridges from a single source IP. A single bot bursting INVITEs
# (e.g. ~70/min) can swamp the shared remote-Asterisk leg and the RTP port pool; this
# bounds how many bridges one IP can hold at once. Over-cap INVITEs are not bridged —
# maybe_start_bridge returns None and the honeypot answers them normally (no tell).
# Set generously so legitimate high-concurrency pump *holds* are still captured. 0 disables.
PBX_MAX_BRIDGES_PER_IP = int(os.environ.get('PBX_MAX_BRIDGES_PER_IP', '25'))
PBX_TRACE = os.environ.get('PBX_TRACE', '0').strip().lower() not in ('', '0', 'false', 'no')
# Durable, journald-independent capture: when set, every trace() line is also
# appended (with an ISO-8601 UTC timestamp) to this file. The systemd journal is
# a size-capped ring buffer; this file is the experiment system-of-record.
PBX_TRACE_FILE = os.environ.get('PBX_TRACE_FILE', '').strip()
# Opt-in capture of the attacker's inbound RTP (bot -> honeypot) to a per-bridge
# .rtp dump file. Unset = disabled. This is the pristine source-side copy of the
# audio the bot streams after answer (the same leg Asterisk records as `rx`,
# but grabbed before any jitter buffer / transcode). PBX side is never dumped.
PBX_RTP_DUMP_DIR = os.environ.get('PBX_RTP_DUMP_DIR', '').strip()
PBX_RTP_DUMP_MAX_PACKETS = int(os.environ.get('PBX_RTP_DUMP_MAX_PACKETS', '12000'))
# Live (permit) calls inject silence to the PBX to latch symmetric RTP and make
# Asterisk pump the callee leg. 0 = stream silence for the whole call (proven).
# >0 = experimental: stop once this many callee packets have arrived (latch + audio
# confirmed), so nothing lands in the callee's voicemail record phase.
PBX_SILENCE_STOP_AFTER_CALLEE = int(os.environ.get('PBX_SILENCE_STOP_AFTER_CALLEE', '0'))
SOURCE_ID = ''

_RTP_DUMP_MAGIC = b'KKRTP1\n'

_bridges_lock = threading.Lock()
_bridges = {}
_ports_lock = threading.Lock()
_used_ports = set()
_live_permit_redis = sip_live_permit.redis_client()


def reload_config():
    global PBX_HOST, PBX_PORT, PBX_DIAL_POLICY, SIP_PUBLIC_IP, SOURCE_ID
    global PBX_RTP_PORT_START, PBX_RTP_PORT_END, PBX_CALL_TIMEOUT, PBX_TRACE
    global PBX_ABANDON_SECONDS, PBX_NO_RESPONSE_SECONDS, PBX_MAX_BRIDGES_PER_IP, PBX_TRACE_FILE
    PBX_HOST = os.environ.get('PBX_HOST', '').strip()
    PBX_PORT = int(os.environ.get('PBX_PORT', '5060'))
    PBX_DIAL_POLICY = os.environ.get('PBX_DIAL_POLICY', 'all').strip()
    SIP_PUBLIC_IP = os.environ.get('SIP_PUBLIC_IP', '').strip()
    PBX_RTP_PORT_START = int(os.environ.get('PBX_RTP_PORT_START', '30000'))
    PBX_RTP_PORT_END = int(os.environ.get('PBX_RTP_PORT_END', '30100'))
    PBX_CALL_TIMEOUT = max(5.0, float(os.environ.get('PBX_CALL_TIMEOUT', '120')))
    PBX_ABANDON_SECONDS = float(os.environ.get('PBX_ABANDON_SECONDS', '4'))
    PBX_NO_RESPONSE_SECONDS = float(os.environ.get('PBX_NO_RESPONSE_SECONDS', '10'))
    PBX_MAX_BRIDGES_PER_IP = int(os.environ.get('PBX_MAX_BRIDGES_PER_IP', '25'))
    PBX_TRACE = os.environ.get('PBX_TRACE', '0').strip().lower() not in ('', '0', 'false', 'no')
    PBX_TRACE_FILE = os.environ.get('PBX_TRACE_FILE', '').strip()
    global PBX_RTP_DUMP_DIR, PBX_RTP_DUMP_MAX_PACKETS, PBX_SILENCE_STOP_AFTER_CALLEE
    PBX_RTP_DUMP_DIR = os.environ.get('PBX_RTP_DUMP_DIR', '').strip()
    PBX_RTP_DUMP_MAX_PACKETS = int(os.environ.get('PBX_RTP_DUMP_MAX_PACKETS', '12000'))
    PBX_SILENCE_STOP_AFTER_CALLEE = int(os.environ.get('PBX_SILENCE_STOP_AFTER_CALLEE', '0'))
    SOURCE_ID = _safe_source_id(os.environ.get('SOURCE_ID', ''))


def enabled():
    reload_config()
    return bool(PBX_HOST)


_trace_file_lock = threading.Lock()
_trace_fh = None


def _trace_to_file(line):
    """Append one trace line to PBX_TRACE_FILE with an ISO-8601 UTC timestamp.

    Durable system-of-record for the experiment, independent of journald's
    size-capped ring buffer. Lazy append-mode open, line-buffered; errors are
    swallowed so trace capture can never disrupt a live bridge."""
    global _trace_fh
    if not PBX_TRACE_FILE:
        return
    try:
        with _trace_file_lock:
            if _trace_fh is None or _trace_fh.name != PBX_TRACE_FILE:
                if _trace_fh is not None:
                    _trace_fh.close()
                _trace_fh = open(PBX_TRACE_FILE, 'a', buffering=1)
            _trace_fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime())} {line}\n")
    except Exception:
        pass


# Linux error-queue support for catching ICMP port-unreachable on relayed RTP.
# MSG_ERRQUEUE is the Linux indicator; IP_RECVERR is often not exported as a Python
# socket attribute even on Linux, so we fall back to its fixed numeric value (11) for
# the setsockopt. Absent on non-Linux → detection silently disabled, relay unaffected.
_IP_RECVERR = getattr(socket, 'IP_RECVERR', 11)
_ERRQ_OK = hasattr(socket, 'MSG_ERRQUEUE')


def _classify_media_ip(ip):
    """One-word reachability class for the RTP address a bot put in its INVITE SDP.
    'global' = a routable public address that could host a real listener; everything
    else means the callee/bait audio we relay there cannot reach a listener as-is
    (private = needs NAT we don't see; unspecified = 0.0.0.0/:: hold; etc.). This is
    the a-priori half of the 'is anyone listening?' question — the live half is the
    IP_RECVERR 'rtp_unreachable' signal on the bridge."""
    if not ip:
        return 'absent'
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return 'malformed'
    if a.is_unspecified:
        return 'unspecified'
    if a.is_loopback:
        return 'loopback'
    if a.is_link_local:
        return 'linklocal'
    if a.is_private:
        return 'private'
    if a.is_multicast or a.is_reserved:
        return 'reserved'
    if a.is_global:
        return 'global'
    return 'other'


def trace(bridge_id, stage, **fields):
    if not PBX_TRACE:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    line = f"SIPTRACE component=b2bua id={bridge_id} stage={stage} {suffix}".rstrip()
    print(line, file=sys.stderr, flush=True)
    _trace_to_file(line)


def new_bridge_id():
    return uuid.uuid4().hex[:10]


def _safe_source_id(value):
    value = re.sub(r'[^A-Za-z0-9_-]+', '_', (value or '').strip())
    return value.strip('_') or 'unknown'


def _token(size=12):
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(size))


def _header_first(headers, name):
    values = headers.get(name.lower()) if headers else None
    if values:
        return values[0]
    return None


def _discover_public_ip():
    if SIP_PUBLIC_IP:
        return SIP_PUBLIC_IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((PBX_HOST or '8.8.8.8', PBX_PORT or 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '0.0.0.0'


def should_bridge(dial_number=None, dial_country=None):
    reload_config()
    if not PBX_HOST:
        return False
    return _policy_matches(dial_number, dial_country)


def parse_sdp(body):
    media = {
        'connection_ip': None,
        'audio_port': None,
        'payloads': ['0', '8'],
    }
    if not body:
        return media
    for raw_line in body.replace('\r\n', '\n').split('\n'):
        line = raw_line.strip()
        if line.startswith('c='):
            parts = line.split()
            if len(parts) >= 3:
                media['connection_ip'] = parts[2]
        elif line.startswith('m=audio'):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                media['audio_port'] = int(parts[1])
            if len(parts) > 3:
                media['payloads'] = parts[3:]
    return media


def build_sdp(ip, port, payloads=None):
    payloads = _audio_payloads(payloads)
    session_id = random.randint(1000000000, 9999999999)
    payload_text = ' '.join(payloads)
    lines = [
        'v=0',
        f'o=- {session_id} {session_id} IN IP4 {ip}',
        's=Asterisk',
        f'c=IN IP4 {ip}',
        't=0 0',
        f'm=audio {port} RTP/AVP {payload_text}',
    ]
    if '0' in payloads:
        lines.append('a=rtpmap:0 PCMU/8000')
    if '8' in payloads:
        lines.append('a=rtpmap:8 PCMA/8000')
    return '\r\n'.join(lines) + '\r\n'


def _audio_payloads(payloads):
    allowed = [p for p in (payloads or []) if p in ('0', '8')]
    return allowed or ['0', '8']


def _parse_response(data):
    text = data.decode('utf-8', errors='replace')
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
    m = re.match(r'^SIP/2\.0\s+(\d{3})(?:\s+(.*))?$', first)
    if not m:
        return None
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
        'code': int(m.group(1)),
        'reason': (m.group(2) or '').strip(),
        'headers': headers,
        'body': body,
        'raw': text,
    }


def _parse_request(data):
    """Parse an inbound SIP *request* (e.g. a PBX-initiated BYE) on the bridge's
    PBX socket. _parse_response only matches status lines, so without this a BYE
    from Asterisk is silently dropped."""
    text = data.decode('utf-8', errors='replace')
    header_end = text.find('\r\n\r\n')
    if header_end < 0:
        header_end = text.find('\n\n')
    header_text = text if header_end < 0 else text[:header_end]
    lines = [ln.rstrip('\r') for ln in header_text.split('\n') if ln != '']
    if not lines:
        return None
    m = re.match(r'^([A-Za-z]+)\s+\S+\s+SIP/2\.0$', lines[0].strip())
    if not m:
        return None
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
    return {'method': m.group(1).upper(), 'headers': headers, 'raw': text}


def _alloc_udp_socket():
    with _ports_lock:
        for port in range(PBX_RTP_PORT_START, PBX_RTP_PORT_END + 1):
            if port in _used_ports:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(('0.0.0.0', port))
                sock.settimeout(0.5)
            except OSError:
                sock.close()
                continue
            _used_ports.add(port)
            return sock, port
    raise RuntimeError('no RTP relay ports available')


def _release_port(port):
    with _ports_lock:
        _used_ports.discard(port)


class _RtpDump:
    """Append-only capture of inbound RTP packets to a self-describing file.

    The file is opened lazily on the first real packet, so calls that answer
    and hang up without media leave no stub file behind. Format: magic line
    `KKRTP1\\n`, then per-packet records of
    `>dHIBH` = (arrival_time_rel, seq, rtp_timestamp, payload_type, payload_len)
    followed by the raw payload bytes (arrival_time_rel is relative to the first
    captured packet). Decode/convert with `extras/sip_rtp_to_wav.py`. Capped at
    max_packets to bound disk use.
    """

    def __init__(self, path, max_packets):
        self._path = path
        self._f = None  # opened lazily on first packet
        self._t0 = None
        self._n = 0
        self._max = max_packets
        self._failed = False
        self._lock = threading.Lock()

    def write(self, data):
        if len(data) < 12:
            return  # too short to be RTP
        if 192 <= data[1] <= 223:
            return  # RTCP (SR/RR/SDES/BYE/APP) muxed on the RTP port, not audio (RFC 5761)
        hdr = 12 + 4 * (data[0] & 0x0F)  # fixed header + CSRC list
        if len(data) <= hdr:
            return
        pt = data[1] & 0x7F
        seq = (data[2] << 8) | data[3]
        ts = struct.unpack('>I', data[4:8])[0]
        payload = data[hdr:]
        with self._lock:
            if self._failed or self._n >= self._max:
                return
            if self._f is None:  # first audio packet — create the file now
                try:
                    self._f = open(self._path, 'wb')
                    self._f.write(_RTP_DUMP_MAGIC)
                    self._f.flush()  # so a hard-killed bridge leaves a valid file, not 0 bytes
                except Exception:
                    self._failed = True
                    return
                self._t0 = time.time()
            rec = struct.pack('>dHIBH', time.time() - self._t0, seq, ts, pt, len(payload)) + payload
            self._f.write(rec)
            self._n += 1

    def opened(self):
        """True once a real audio packet has been captured (file created lazily)."""
        return self._f is not None

    def close(self):
        with self._lock:
            if self._f is not None:
                try:
                    self._f.close()
                except Exception:
                    pass


class Bridge:
    def __init__(
        self,
        inbound_req,
        client_ip,
        client_addr,
        send_to_attacker,
        dial_number,
        dial_country,
        bridge_id=None,
        live_permit=None,
    ):
        self.id = bridge_id or new_bridge_id()
        self.inbound_req = inbound_req
        self.client_ip = client_ip
        self.client_addr = client_addr
        self.send_to_attacker = send_to_attacker
        self.dial_number = dial_number
        self.dial_country = dial_country
        self.live_permit = live_permit or {}
        self.created_at = time.time()
        # Hard cap on total bridge life. For permit (live) bridges this is the
        # smaller of the global PBX_CALL_TIMEOUT and the permit's max_seconds, so
        # max_seconds actually bounds billable duration and the B2BUA stays the
        # teardown initiator — leading the Asterisk-side TIMEOUT(absolute) backstop
        # so the BYE flows B2BUA -> Asterisk (which we handle cleanly) rather than
        # the reverse.
        self.max_call_seconds = PBX_CALL_TIMEOUT
        permit_max = self.live_permit.get('max_seconds')
        if permit_max:
            try:
                self.max_call_seconds = min(PBX_CALL_TIMEOUT, float(permit_max))
            except (TypeError, ValueError):
                pass
        self.public_ip = _discover_public_ip()
        self.attacker_media = parse_sdp(inbound_req.get('body') or '')
        self.attacker_rtp_addr = self._initial_attacker_rtp_addr()
        self.pbx_rtp_addr = None
        self.pbx_response_headers = {}
        self.last_inbound_response = None
        self.pbx_sock = None
        self.attacker_rtp_sock = None
        self.pbx_rtp_sock = None
        self.attacker_rtp_port = None
        self.pbx_rtp_port = None
        self.out_call_id = f'{self.id}@knock-knock'
        self.out_from_tag = _token(10)
        self.out_from_header = None
        self.out_contact_header = None
        self.out_cseq = 1
        # Branch of our outbound INVITE — a CANCEL MUST reuse it (RFC 3261) or the
        # PBX can't match it to the INVITE transaction (replies 481) and rings on.
        self.invite_branch = f'z9hG4bK{_token(12)}'
        self.closed = False
        self.attacker_ack_seen = False
        self.pbx_answered = False      # PBX sent a 2xx for our INVITE
        self.pbx_responded = False     # PBX sent ANY response (incl 100) — liveness signal
        self.answered_at = None        # when that 2xx arrived (for no-ACK abandon timer)
        self.pbx_acked = False         # we have ACKed that 2xx
        self.pbx_byed = False          # we have torn the PBX dialog down (ACK+BYE)
        self.attacker_gone = False     # attacker tore down before the PBX answered
        self.rtp_dump = None           # attacker->callee (bot audio)
        self.pbx_rtp_dump = None       # callee->attacker (ringback/voicemail — the billed audio)
        self.last_attacker_rtp = 0.0   # last time the bot sent us RTP (silence gen yields to it)
        self.pbx_rtp_count = 0         # callee RTP packets received (silence-gen stop trigger)
        self.rtp_unreachable_seen = False  # ICMP port-unreachable seen for our relay

    def _initial_attacker_rtp_addr(self):
        port = self.attacker_media.get('audio_port')
        ip = self.attacker_media.get('connection_ip')
        if not port:
            return None
        if not ip or ip in ('0.0.0.0', '::'):
            ip = self.client_ip
        return (ip, port)

    def start(self):
        try:
            self.attacker_rtp_sock, self.attacker_rtp_port = _alloc_udp_socket()
            if _ERRQ_OK:
                try:
                    self.attacker_rtp_sock.setsockopt(socket.IPPROTO_IP, _IP_RECVERR, 1)
                except OSError:
                    pass
            self.pbx_rtp_sock, self.pbx_rtp_port = _alloc_udp_socket()
            self.pbx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.pbx_sock.bind(('0.0.0.0', 0))
            self.pbx_sock.settimeout(0.5)
        except Exception:
            # If a later allocation fails (e.g. the RTP pool is exhausted on the 2nd
            # port), do NOT leak the ports/sockets already grabbed — close them and
            # return them to _used_ports, then re-raise so maybe_start_bridge still
            # reports the setup failure. Without this, every exhaustion partial-alloc
            # permanently leaked a port from the in-memory pool, so once a flood
            # saturated it the pool stayed stuck-full (every later bridge failing)
            # until a restart, even after the OS sockets had all closed.
            for s in (self.pbx_sock, self.attacker_rtp_sock, self.pbx_rtp_sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            for p in (self.attacker_rtp_port, self.pbx_rtp_port):
                if p:
                    _release_port(p)
            raise
        self.rtp_dump = self._open_rtp_dump('attacker')
        # Callee->attacker (ringback/voicemail) is only worth recording on a real
        # permitted dialout. On non-permit bridges (e.g. PBX_DIAL_POLICY=all) the PBX
        # leg is just silence, so dumping it would litter the dir with empty WAVs.
        self.pbx_rtp_dump = self._open_rtp_dump('pbx') if self.live_permit else None
        self._register()
        threading.Thread(target=self._rtp_loop, args=(self.attacker_rtp_sock, 'attacker'), daemon=True).start()
        threading.Thread(target=self._rtp_loop, args=(self.pbx_rtp_sock, 'pbx'), daemon=True).start()
        if self.live_permit:
            threading.Thread(target=self._silence_loop, daemon=True).start()
        threading.Thread(target=self._sip_loop, daemon=True).start()
        threading.Thread(target=self._timeout_loop, daemon=True).start()
        self._send_invite_to_pbx()
        trace(self.id, 'started', attacker_rtp=self.attacker_rtp_port, pbx_rtp=self.pbx_rtp_port)
        # Record where the bot says it wants media. We never persisted this, so we
        # could not distinguish a real reachable listener from a bot advertising a
        # private/zero/unroutable port it isn't receiving on. sig_match flags whether
        # the media IP even equals the signaling source (mismatch ⇒ NAT or spoof).
        _adv_ip = self.attacker_media.get('connection_ip')
        trace(self.id, 'sdp_media',
              c_ip=_adv_ip or '-',
              port=self.attacker_media.get('audio_port') or 0,
              cls=_classify_media_ip(_adv_ip),
              sig_match=(_adv_ip == self.client_ip))
        return self

    def _open_rtp_dump(self, side='attacker'):
        if not PBX_RTP_DUMP_DIR:
            return None
        try:
            os.makedirs(PBX_RTP_DUMP_DIR, exist_ok=True)
            num = (self.dial_number or 'unknown').lstrip('+') or 'unknown'
            from_h = _header_first(self.inbound_req.get('headers'), 'from')
            caller = _extract_display_user(from_h) or 'unknown'
            safe = lambda s: re.sub(r'[^A-Za-z0-9_.+-]', '_', str(s))[:64]
            # Mirror the Asterisk MixMonitor field order: source-ip-caller-number-epoch-bridge.
            # The attacker (bot->callee) leg keeps the bare name; the callee->attacker
            # leg (ringback/voicemail the PBX sends back — the billed audio) gets a
            # -pbx suffix so the two directions decode to separate WAVs. Both share the
            # bridge id, which is the unambiguous pairing key.
            suffix = '-pbx' if side == 'pbx' else ''
            fname = (f"{SOURCE_ID or 'unknown'}-{safe(self.client_ip)}-{safe(caller)}-"
                     f"{safe(num)}-{int(time.time())}-{self.id}{suffix}.rtp")
            dump = _RtpDump(os.path.join(PBX_RTP_DUMP_DIR, fname), PBX_RTP_DUMP_MAX_PACKETS)
            trace(self.id, 'rtp_dump_armed', file=fname, side=side)
            return dump
        except Exception as e:
            trace(self.id, 'rtp_dump_open_failed', err=str(e), side=side)
            return None

    def _register(self):
        call_id = _header_first(self.inbound_req.get('headers'), 'call-id') or self.id
        with _bridges_lock:
            _bridges[(self.client_ip, call_id)] = self

    def _unregister(self):
        call_id = _header_first(self.inbound_req.get('headers'), 'call-id') or self.id
        with _bridges_lock:
            if _bridges.get((self.client_ip, call_id)) is self:
                _bridges.pop((self.client_ip, call_id), None)

    def close(self, reason='unspecified'):
        if self.closed:
            return
        self.closed = True
        # Centralised teardown: on ANY close path (cancel, bye, timeout, abandon,
        # glare, error) cleanly end an answered PBX dialog — ACK the 2xx then BYE.
        # A bare CANCEL is ignored post-answer, and just dropping our sockets leaves
        # the PBX leg up playing silence to nobody (the zombie recording).
        if self.pbx_answered and not self.pbx_byed:
            try:
                self._teardown_answered_pbx()
            except Exception:
                pass
        self._unregister()
        if self.rtp_dump is not None:
            self.rtp_dump.close()
        if self.pbx_rtp_dump is not None:
            self.pbx_rtp_dump.close()
        # Answered (billed) but the callee never sent a single audio packet: classic
        # false-answer-supervision / dead-air-billing fingerprint. The lazily-opened
        # pbx dump leaves no file in this case, so flag it in the trace instead.
        if (PBX_RTP_DUMP_DIR and self.live_permit and self.pbx_answered
                and (self.pbx_rtp_dump is None or not self.pbx_rtp_dump.opened())):
            trace(self.id, 'pbx_no_media_after_answer',
                  billed=round(time.time() - self.answered_at, 3) if self.answered_at else None)
        for sock in (self.pbx_sock, self.attacker_rtp_sock, self.pbx_rtp_sock):
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        if self.attacker_rtp_port:
            _release_port(self.attacker_rtp_port)
        if self.pbx_rtp_port:
            _release_port(self.pbx_rtp_port)
        if self.live_permit:
            try:
                sip_live_permit.release_active_lock(_live_permit_redis, self.id)
            except Exception:
                pass
        trace(self.id, 'closed', reason=reason, age=round(time.time() - self.created_at, 3))

    def _timeout_loop(self):
        while not self.closed:
            now = time.time()
            if now - self.created_at > self.max_call_seconds:
                trace(self.id, 'timeout', cap=self.max_call_seconds)
                self.close('b2bua_timeout')
                return
            # Zombie bridge: the PBX never sent ANY response (not even 100 Trying) —
            # the INVITE was dropped (e.g. Asterisk overloaded under a pump). Reap it
            # fast to free the RTP relay ports instead of squatting to the call cap.
            if (PBX_NO_RESPONSE_SECONDS > 0 and not self.pbx_responded
                    and now - self.created_at > PBX_NO_RESPONSE_SECONDS):
                trace(self.id, 'pbx_no_response', age=round(now - self.created_at, 3))
                self.close('pbx_no_response')
                return
            # Silent-abandon prober: PBX answered but the attacker never ACKed
            # (INVITE, see 200, vanish). Tear down fast instead of holding to the cap.
            if (PBX_ABANDON_SECONDS > 0 and self.answered_at is not None
                    and not self.attacker_ack_seen
                    and now - self.answered_at > PBX_ABANDON_SECONDS):
                trace(self.id, 'attacker_no_ack', age=round(now - self.created_at, 3))
                self.close('attacker_no_ack')
                return
            time.sleep(0.5)

    def _drain_rtp_errq(self):
        """Non-blocking read of the attacker socket's error queue. When we relay a
        callee/bait packet to a port the bot isn't listening on, its host returns an
        ICMP port-unreachable that the kernel queues here (IP_RECVERR). The first one
        means our audio is landing on a closed port — the bot is NOT receiving it.
        Logged once per bridge; the relay path is never connected, so normal RTP recv
        and symmetric-RTP latching are unaffected."""
        if self.rtp_unreachable_seen or not _ERRQ_OK:
            return
        try:
            _data, anc, _flags, _addr = self.attacker_rtp_sock.recvmsg(
                0, 512, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return
        for lvl, typ, cdata in anc:
            if lvl == socket.IPPROTO_IP and typ == _IP_RECVERR and len(cdata) >= 8:
                # struct sock_extended_err: ee_errno(u32) ee_origin/type/code(u8)...
                ee_errno, ee_origin, ee_type, ee_code = struct.unpack_from('=IBBB', cdata, 0)
                self.rtp_unreachable_seen = True
                dest = (f'{self.attacker_rtp_addr[0]}:{self.attacker_rtp_addr[1]}'
                        if self.attacker_rtp_addr else '-')
                trace(self.id, 'rtp_unreachable', dest=dest,
                      errno=ee_errno, icmp=f'{ee_type}/{ee_code}', origin=ee_origin)
                return

    def _rtp_loop(self, sock, side):
        while not self.closed:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                if side == 'attacker':
                    self._drain_rtp_errq()
                continue
            except Exception:
                if not self.closed:
                    time.sleep(0.01)
                continue
            if side == 'attacker':
                self.attacker_rtp_addr = addr
                self.last_attacker_rtp = time.time()
                if self.rtp_dump is not None:
                    try:
                        self.rtp_dump.write(data)
                    except Exception:
                        pass
                if self.pbx_rtp_addr:
                    try:
                        self.pbx_rtp_sock.sendto(data, self.pbx_rtp_addr)
                    except Exception:
                        pass
            else:
                self.pbx_rtp_addr = addr
                self.pbx_rtp_count += 1
                if self.pbx_rtp_dump is not None:
                    try:
                        self.pbx_rtp_dump.write(data)
                    except Exception:
                        pass
                if self.attacker_rtp_addr:
                    try:
                        self.attacker_rtp_sock.sendto(data, self.attacker_rtp_addr)
                    except Exception:
                        pass

    def _silence_loop(self):
        """Keep Asterisk's inbound media path alive on live (permit) calls. Asterisk
        will not pump/record the bridge for a leg it never hears RTP from, and these
        silent-abandon bots send none — so we act like a normal media endpoint and
        stream ~50 pps of codec silence to the PBX once answered, until the call
        closes. We yield whenever the bot is itself sending audio (its verbatim relay
        carries the uplink then), so a talkative bot is never doubled on the wire."""
        payloads = self.attacker_media.get('payloads') or []
        try:
            pt = int(payloads[0]) if payloads else 0
        except (ValueError, TypeError):
            pt = 0
        silence = bytes([0xD5 if pt == 8 else 0xFF]) * 160  # a-law/mu-law silence, 20 ms @ 8 kHz
        ssrc = random.getrandbits(32)
        seq = random.getrandbits(16)
        ts = random.getrandbits(32)
        stop_after = PBX_SILENCE_STOP_AFTER_CALLEE
        while not self.closed:
            # Experimental footprint reduction: once the callee leg is confirmed
            # flowing (latch took + Asterisk is pumping it to us), stop injecting
            # silence so nothing carries into the callee's voicemail record phase.
            # 0 = never stop (proven continuous mode).
            if stop_after > 0 and self.pbx_rtp_count >= stop_after:
                trace(self.id, 'silence_stop', after_callee_pkts=self.pbx_rtp_count)
                return
            if (self.pbx_rtp_addr and self.pbx_answered
                    and time.time() - self.last_attacker_rtp > 0.12):
                pkt = struct.pack('>BBHII', 0x80, pt & 0x7F, seq & 0xFFFF,
                                  ts & 0xFFFFFFFF, ssrc) + silence
                try:
                    self.pbx_rtp_sock.sendto(pkt, self.pbx_rtp_addr)
                except Exception:
                    pass
                seq = (seq + 1) & 0xFFFF
                ts = (ts + 160) & 0xFFFFFFFF
            time.sleep(0.02)

    def _sip_loop(self):
        while not self.closed:
            try:
                data, _addr = self.pbx_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                if not self.closed:
                    trace(self.id, 'pbx_recv_error')
                return
            resp = _parse_response(data)
            if resp:
                self._handle_pbx_response(resp)
                continue
            req = _parse_request(data)
            if req:
                self._handle_pbx_request(req)

    def _send_to_pbx(self, payload):
        self.pbx_sock.sendto(payload, (PBX_HOST, PBX_PORT))

    def _send_invite_to_pbx(self):
        target_user = (self.dial_number or 's').lstrip('+') or 's'
        sdp = build_sdp(self.public_ip, self.pbx_rtp_port, self.attacker_media.get('payloads'))
        body = sdp.encode()
        from_h = _header_first(self.inbound_req.get('headers'), 'from') or '<sip:unknown@unknown>'
        caller = _extract_display_user(from_h) or self.client_ip
        self.out_from_header = f'<sip:{caller}@{self.public_ip}>;tag={self.out_from_tag}'
        self.out_contact_header = f'<sip:{caller}@{self.public_ip}>'
        lines = [
            f'INVITE sip:{target_user}@{PBX_HOST} SIP/2.0',
            f'Via: SIP/2.0/UDP {self.public_ip};branch={self.invite_branch}',
            'Max-Forwards: 70',
            f'From: {self.out_from_header}',
            f'To: <sip:{target_user}@{PBX_HOST}>',
            f'Call-ID: {self.out_call_id}',
            f'CSeq: {self.out_cseq} INVITE',
            f'Contact: {self.out_contact_header}',
            f'X-Bridge-ID: {self.id}',
            f'X-Source-IP: {self.client_ip}',
            f'X-Source-ID: {SOURCE_ID or "unknown"}',
            # Authoritative per-bridge cap so Asterisk's TIMEOUT(absolute) backstop
            # tracks the B2BUA cap (B2BUA leads teardown). Sent on every bridge.
            f'X-Bridge-Max-Seconds: {int(self.max_call_seconds)}',
        ]
        if self.live_permit:
            permit_id = str(self.live_permit.get('permit_id') or '')
            lines.append('X-Live-Outbound: 1')
            if permit_id:
                lines.append(f'X-Live-Permit-ID: {permit_id}')
        lines.extend([
            'Content-Type: application/sdp',
            f'Content-Length: {len(body)}',
        ])
        self._send_to_pbx(('\r\n'.join(lines) + '\r\n\r\n').encode() + body)

    def _handle_pbx_response(self, resp):
        code = int(resp.get('code') or 0)
        self.pbx_responded = True   # any response (incl 100) ⇒ Asterisk is processing
        if code == 100:
            trace(self.id, 'pbx_response_suppressed', code=code)
            return
        self.pbx_response_headers = resp.get('headers') or {}
        if 200 <= code < 300:
            self.pbx_answered = True
            if self.answered_at is None:
                self.answered_at = time.time()
            # Glare: the attacker tore down before this answer arrived. Don't bridge
            # a departed attacker — close() ends the PBX dialog (ACK+BYE).
            if self.attacker_gone:
                self.close('attacker_gone_pre_answer')
                return
            # Confirm OUR leg (B2BUA->PBX) by ACKing the 2xx ourselves, decoupled from
            # whether the attacker ever ACKs us. Asterisk will not pump the callee's
            # media (recording / pbx dump) to an unconfirmed dialog, and these bots are
            # silent-abandon probers that never ACK. Re-sent on each 2xx retransmit per
            # RFC 3261 13.2.2.4. Live (permit) calls only — non-permit playback calls
            # already get media via the dialplan's Answer() and we don't touch that
            # high-volume path. attacker_ack_seen is deliberately NOT set here, so the
            # PBX_ABANDON_SECONDS teardown still fires and caps the recording window.
            if self.live_permit:
                first_ack = not self.pbx_acked
                self._send_to_pbx(self._build_outbound_request('ACK', include_body=False))
                self.pbx_acked = True
                if first_ack:
                    trace(self.id, 'pbx_early_ack', age=round(time.time() - self.created_at, 3))
        body = resp.get('body') or ''
        out_body = None
        if body:
            pbx_media = parse_sdp(body)
            if pbx_media.get('audio_port'):
                ip = pbx_media.get('connection_ip') or PBX_HOST
                self.pbx_rtp_addr = (ip, pbx_media['audio_port'])
            out_body = build_sdp(self.public_ip, self.attacker_rtp_port, pbx_media.get('payloads'))
        inbound_response = _build_inbound_response(self.inbound_req, resp, out_body)
        self.last_inbound_response = inbound_response
        self.send_to_attacker(inbound_response)
        trace(self.id, 'pbx_response', code=code)
        if code >= 300:
            self.close(f'pbx_final_response_{code}')

    def _handle_pbx_request(self, req):
        """Handle an in-dialog request from the PBX. The important case is the PBX
        hanging up first — the far/Telnyx callee dropping, or the Asterisk
        TIMEOUT(absolute) backstop firing — which sends us a BYE. The old
        response-only loop dropped it, so the bridge held its lock/ports until
        PBX_CALL_TIMEOUT. Now we 200 it and tear down promptly."""
        method = req.get('method')
        if method in ('BYE', 'CANCEL'):
            try:
                self._send_to_pbx(self._build_pbx_request_response(req, 200, 'OK'))
            except Exception:
                pass
            trace(self.id, f'pbx_{method.lower()}', age=round(time.time() - self.created_at, 3))
            # The PBX already ended its dialog, so suppress our own ACK+BYE in
            # close() — nothing left to tear down on that leg.
            self.pbx_byed = True
            self.close(f'pbx_{method.lower()}')
        elif method == 'OPTIONS':
            try:
                self._send_to_pbx(self._build_pbx_request_response(req, 200, 'OK'))
            except Exception:
                pass

    def _build_pbx_request_response(self, req, code, reason):
        headers = req.get('headers') or {}
        via = _header_first(headers, 'via') or f'SIP/2.0/UDP {self.public_ip}'
        from_h = _header_first(headers, 'from') or self.out_from_header or '<sip:unknown@unknown>'
        to_h = _header_first(headers, 'to') or '<sip:unknown@unknown>'
        call_id = _header_first(headers, 'call-id') or self.out_call_id
        cseq = _header_first(headers, 'cseq') or '1 BYE'
        lines = [
            f'SIP/2.0 {code} {reason}',
            f'Via: {via}',
            f'From: {from_h}',
            f'To: {to_h}',
            f'Call-ID: {call_id}',
            f'CSeq: {cseq}',
            'Content-Length: 0',
        ]
        return ('\r\n'.join(lines) + '\r\n\r\n').encode()

    def _teardown_answered_pbx(self):
        """Cleanly end an answered PBX dialog: ACK the 2xx (once) so the dialog is
        confirmed, then BYE. A bare CANCEL is ignored by Asterisk after answer — the
        bug that left zombie calls recording silence to a departed attacker."""
        if not self.pbx_acked:
            self._send_to_pbx(self._build_outbound_request('ACK', include_body=False))
            self.pbx_acked = True
        self.out_cseq += 1
        self._send_to_pbx(self._build_outbound_request('BYE', include_body=False))
        self.pbx_byed = True
        trace(self.id, 'pbx_teardown', via='ACK+BYE', age=round(time.time() - self.created_at, 3))

    def forward_in_dialog(self, req):
        method = req.get('method')
        if method == 'INVITE':
            self.send_to_attacker(self.last_inbound_response or _build_simple_response(req, 100, 'Trying'))
            return True
        if method == 'ACK':
            if not self.attacker_ack_seen:
                self.attacker_ack_seen = True
                trace(self.id, 'attacker_ack', age=round(time.time() - self.created_at, 3))
            # Guard against a double ACK: a live permit call may already have early-ACKed
            # the PBX in _handle_pbx_response, decoupled from this attacker ACK.
            if not self.pbx_acked:
                self._send_to_pbx(self._build_outbound_request('ACK', include_body=False))
                self.pbx_acked = True
            return True
        if method == 'BYE':
            trace(self.id, 'attacker_bye', age=round(time.time() - self.created_at, 3))
            self.send_to_attacker(_build_simple_response(req, 200, 'OK'))
            if not self.pbx_answered:
                self._send_to_pbx(self._build_outbound_request('CANCEL', include_body=False))
            self.close('attacker_bye')          # close() does ACK+BYE if answered
            return True
        if method == 'CANCEL':
            trace(self.id, 'attacker_cancel', age=round(time.time() - self.created_at, 3))
            self.send_to_attacker(_build_simple_response(req, 200, 'OK'))
            if self.pbx_answered:
                # Post-answer CANCEL (observed bot behavior): invalid on an answered
                # dialog — Asterisk ignores it. close() does the ACK+BYE teardown.
                self.close('attacker_cancel')
            else:
                # Genuine pre-answer CANCEL: forward it, but keep the PBX leg alive so
                # a 2xx racing the CANCEL (glare) gets ACK+BYE in _handle_pbx_response.
                self._send_to_pbx(self._build_outbound_request('CANCEL', include_body=False))
                self.attacker_gone = True
            return True
        if method == 'INFO':
            # Attackers may answer the bait IVR with DTMF carried in SIP INFO
            # (application/dtmf-relay "Signal=N", or application/dtmf with the
            # digit as the body). That is signaling, not RTP, so it never shows
            # up in the RTP dump — trace it so an IVR-navigating bot's keypresses
            # aren't lost. Reply 200 so the dialog stays alive and we keep
            # looking like a real UA.
            raw = req.get('raw') or ''
            parts = re.split(r'\r\n\r\n|\n\n', raw, maxsplit=1)
            body = parts[1] if len(parts) > 1 else ''
            ct = (_header_first(req.get('headers') or {}, 'content-type') or '').lower()
            m = re.search(r'Signal\s*=\s*([0-9A-Da-d*#])', body)
            digit = m.group(1) if m else (body.strip()[:8] if 'dtmf' in ct else None)
            trace(self.id, 'attacker_info',
                  age=round(time.time() - self.created_at, 3), digit=digit, ct=ct)
            self.send_to_attacker(_build_simple_response(req, 200, 'OK'))
            return True
        # Any other in-dialog request (NOTIFY, OPTIONS, MESSAGE, UPDATE, …):
        # trace it so unexpected attacker behaviour isn't dropped silently.
        trace(self.id, 'attacker_in_dialog', method=method,
              age=round(time.time() - self.created_at, 3))
        return False

    def _build_outbound_request(self, method, include_body=False):
        target_user = (self.dial_number or 's').lstrip('+') or 's'
        # A CANCEL must match the INVITE it cancels: same Via branch and same
        # (tag-less) To. ACK/BYE are new transactions in the answered dialog, so
        # they get a fresh branch and the answered To-tag from the PBX response.
        if method == 'CANCEL':
            branch = self.invite_branch
            to_h = f'<sip:{target_user}@{PBX_HOST}>'
        else:
            branch = f'z9hG4bK{_token(12)}'
            to_h = _header_first(self.pbx_response_headers, 'to') or f'<sip:{target_user}@{PBX_HOST}>'
        body = b''
        lines = [
            f'{method} sip:{target_user}@{PBX_HOST} SIP/2.0',
            f'Via: SIP/2.0/UDP {self.public_ip};branch={branch}',
            'Max-Forwards: 70',
            f'From: {self.out_from_header or f"<sip:{self.client_ip}@{self.public_ip}>;tag={self.out_from_tag}"}',
            f'To: {to_h}',
            f'Call-ID: {self.out_call_id}',
            f'CSeq: {self.out_cseq} {method}',
            f'Contact: {self.out_contact_header or f"<sip:{self.client_ip}@{self.public_ip}>"}',
            f'Content-Length: {len(body)}',
        ]
        return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def _extract_display_user(header_value):
    if not header_value:
        return None
    m = re.search(r'sips?:([^@>;]+)', header_value, flags=re.IGNORECASE)
    if m:
        return re.sub(r'[^A-Za-z0-9_.+-]', '', m.group(1))[:64] or None
    return None


def _extract_tag(header_value):
    if not header_value:
        return None
    m = re.search(r'(?:^|;)\s*tag=([^;\s]+)', header_value, flags=re.IGNORECASE)
    return m.group(1) if m else None


def _build_inbound_response(inbound_req, pbx_resp, body=None):
    headers = inbound_req.get('headers') or {}
    resp_headers = pbx_resp.get('headers') or {}
    via = _header_first(headers, 'via') or 'SIP/2.0/UDP 0.0.0.0;branch=z9hG4bKmissing'
    from_h = _header_first(headers, 'from') or '<sip:unknown@unknown>'
    to_h = _header_first(headers, 'to') or '<sip:unknown@unknown>'
    pbx_to = _header_first(resp_headers, 'to')
    tag = _extract_tag(pbx_to) or _extract_tag(to_h) or _token(10)
    if not _extract_tag(to_h):
        to_h = f'{to_h};tag={tag}'
    call_id = _header_first(headers, 'call-id') or _token(12)
    cseq = _header_first(headers, 'cseq') or '1 INVITE'
    reason = pbx_resp.get('reason') or _default_reason(pbx_resp.get('code'))
    body_bytes = body.encode() if body else b''
    lines = [
        f"SIP/2.0 {pbx_resp.get('code')} {reason}",
        f'Via: {via}',
        f'From: {from_h}',
        f'To: {to_h}',
        f'Call-ID: {call_id}',
        f'CSeq: {cseq}',
        'Server: Asterisk PBX 18.0.0',
    ]
    if body:
        lines.append('Content-Type: application/sdp')
    lines.append(f'Content-Length: {len(body_bytes)}')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body_bytes


def _build_simple_response(req, code, reason):
    return _build_inbound_response(req, {'code': code, 'reason': reason, 'headers': {}}, None)


def _default_reason(code):
    return {
        100: 'Trying',
        180: 'Ringing',
        183: 'Session Progress',
        200: 'OK',
        404: 'Not Found',
        480: 'Temporarily Unavailable',
        486: 'Busy Here',
        487: 'Request Terminated',
        500: 'Server Internal Error',
    }.get(int(code or 0), '')


def maybe_start_bridge(
    req,
    client_ip,
    client_addr,
    send_to_attacker,
    dial_number=None,
    dial_country=None,
    bridge_id=None,
    force=False,
    live_permit=None,
):
    reload_config()
    if not PBX_HOST or (not force and not _policy_matches(dial_number, dial_country)):
        return None
    # Per-IP concurrent-bridge cap: don't let one bursting IP swamp the shared Asterisk
    # leg / RTP pool. Active count is derived from the registry (keyed (client_ip,call_id)).
    # Over cap → return None; the honeypot answers the INVITE normally (no 486 tell).
    # live_permit calls are exempt (deliberate, low-volume bait dials).
    if PBX_MAX_BRIDGES_PER_IP > 0 and not live_permit:
        with _bridges_lock:
            active = sum(1 for ip, _ in _bridges if ip == client_ip)
        if active >= PBX_MAX_BRIDGES_PER_IP:
            # Direct print (not trace()) so it's visible without PBX_TRACE, like setup_failed.
            print(f'SIPTRACE component=b2bua stage=rejected reason=per_ip_cap '
                  f'ip={client_ip!r} active={active} cap={PBX_MAX_BRIDGES_PER_IP}',
                  file=sys.stderr, flush=True)
            return None
    try:
        return Bridge(
            req,
            client_ip,
            client_addr,
            send_to_attacker,
            dial_number,
            dial_country,
            bridge_id=bridge_id,
            live_permit=live_permit,
        ).start()
    except Exception as e:
        if live_permit:
            try:
                sip_live_permit.release_active_lock(_live_permit_redis, bridge_id)
            except Exception:
                pass
        # Use a SIPTRACE-prefixed direct print (not trace(), so it's NOT gated by
        # PBX_TRACE) — monitor.py only forwards non-JSON lines matching ^...TRACE,
        # so this is how a setup failure (e.g. RTP pool exhausted) reaches the log.
        print(f'SIPTRACE component=b2bua stage=setup_failed ip={client_ip!r} err={str(e)!r}',
              file=sys.stderr, flush=True)
        return None


def _policy_matches(dial_number=None, dial_country=None):
    policy = (PBX_DIAL_POLICY or '').strip()
    if not policy or policy.lower() == 'none':
        return False
    if policy.lower() == 'all':
        return bool(dial_number)
    for raw_token in policy.split(','):
        token = raw_token.strip()
        if not token:
            continue
        if len(token) == 2 and token.isalpha():
            if (dial_country or '').upper() == token.upper():
                return True
        elif dial_number and (dial_number == token or dial_number.startswith(token)):
            return True
    return False


def handle_in_dialog(req, client_ip, send_to_attacker):
    call_id = _header_first(req.get('headers'), 'call-id') or ''
    if not call_id:
        return False
    with _bridges_lock:
        bridge = _bridges.get((client_ip, call_id))
    if not bridge:
        return False
    bridge.send_to_attacker = send_to_attacker
    return bridge.forward_in_dialog(req)

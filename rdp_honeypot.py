#!/root/knock-knock/.venv/bin/python
"""
RDP honeypot - NLA level using impacket.
Captures username (and domain) from NTLM AUTHENTICATE message.
Falls back to X.224 cookie parsing for older non-NLA clients.
"""
import socket
import ssl
import threading
import json
import os
import time
import struct
import subprocess
import sys
import random
import string
import uuid
import redis

from impacket import ntlm

# Randomised Windows 10-style computer name, generated once at startup
_COMPUTER_NAME = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))

CERT_FILE = os.environ.get('DB_DIR', 'data') + '/rdp.crt'
KEY_FILE  = os.environ.get('DB_DIR', 'data') + '/rdp.key'

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)
TRACE_ENABLED = os.environ.get('RDP_TRACE', '1').lower() not in ('0', 'false', 'no')
TRACE_IP = os.environ.get('RDP_TRACE_IP', '').strip()
TLS_MIN_VERSION = os.environ.get('RDP_TLS_MIN', '1.0').strip()
TLS_CIPHERS = os.environ.get('RDP_TLS_CIPHERS', 'ALL:@SECLEVEL=0').strip()
CERT_DIGEST = os.environ.get('RDP_CERT_DIGEST', 'sha1').strip().lower()
MAX_NLA_ATTEMPTS = max(1, int(os.environ.get('RDP_MAX_NLA_ATTEMPTS', '3')))

def trace(session_id, client_ip, stage, **fields):
    """Emit structured, grep-friendly stage logs for RDP sessions."""
    if not TRACE_ENABLED:
        return
    if TRACE_IP and client_ip != TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    base = f"RDPTRACE sid={session_id} ip={client_ip} stage={stage}"
    print(f"{base} {suffix}".rstrip(), flush=True)

def classify_socket_error(exc):
    """Normalize common socket/TLS errors to stable labels for summaries."""
    if isinstance(exc, ConnectionResetError):
        return 'peer_reset'
    if isinstance(exc, BrokenPipeError):
        return 'broken_pipe'
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return 'timeout'
    if isinstance(exc, ssl.SSLEOFError):
        return 'tls_eof'
    if isinstance(exc, OSError):
        if exc.errno in (9,):
            return 'local_bad_fd'
        if exc.errno in (32,):
            return 'broken_pipe'
        if exc.errno in (104, 54):
            return 'peer_reset'
        if exc.errno in (110, 60):
            return 'timeout'
    return type(exc).__name__

def resolve_min_tls_version():
    v = TLS_MIN_VERSION.lower()
    if v in ('1.0', 'tls1.0', 'tls1'):
        return ssl.TLSVersion.TLSv1
    if v in ('1.1', 'tls1.1'):
        return ssl.TLSVersion.TLSv1_1
    if v in ('1.2', 'tls1.2'):
        return ssl.TLSVersion.TLSv1_2
    if v in ('1.3', 'tls1.3'):
        return ssl.TLSVersion.TLSv1_3
    return ssl.TLSVersion.TLSv1

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

def ensure_cert():
    """Generate a self-signed cert for TLS if not already present."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    digest_flag = '-sha1' if CERT_DIGEST == 'sha1' else '-sha256'
    subprocess.run([
        'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
        digest_flag,
        '-keyout', KEY_FILE, '-x509', '-days', '3650',
        '-out', CERT_FILE,
        '-subj', '/CN=DESKTOP-RDP/O=Microsoft/C=US'
    ], capture_output=True)

# --- X.224 / TPKT helpers ---

# X.224 Connection Confirm with NLA/CredSSP (PROTOCOL_HYBRID = 0x00000002) selected
X224_CC_SSL = bytes([
    0x03, 0x00, 0x00, 0x13,   # TPKT: version=3, length=19
    0x0E,                      # LI=14
    0xD0,                      # X.224 Connection Confirm
    0x00, 0x00,                # dst-ref
    0x00, 0x00,                # src-ref
    0x00,                      # class
    0x02,                      # RDP_NEG_RSP
    0x00,                      # flags
    0x08, 0x00,                # length=8
    0x02, 0x00, 0x00, 0x00,   # selectedProtocol=PROTOCOL_HYBRID (NLA/CredSSP)
])

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf

def read_x224_packet(sock, timeout=10):
    """Read one TPKT/X.224 packet. Returns raw bytes or b'' on error."""
    sock.settimeout(timeout)
    try:
        hdr = recv_exact(sock, 4)
        if hdr[0] != 0x03:
            return hdr  # not a valid TPKT — return what we have
        pkt_len = struct.unpack('>H', hdr[2:4])[0]
        body = recv_exact(sock, min(pkt_len - 4, 4092))
        return hdr + body
    except Exception:
        return b''

# --- RDP_NEG_REQ parser ---

def parse_req_protocols(data):
    """
    Extract requestedProtocols from X.224 CR RDP_NEG_REQ.
    Variable data starts at byte 11 (4-byte TPKT + 7-byte X.224 fixed header).
    Optional cookie (Cookie: mstshash=...\\r\\n) precedes RDP_NEG_REQ.
    RDP_NEG_REQ structure: type(1) + flags(1) + length(2) + requestedProtocols(4)
    """
    try:
        var = data[11:]
        # Skip cookie if present
        crlf = var.find(b'\r\n')
        if crlf >= 0:
            var = var[crlf + 2:]
        # Expect RDP_NEG_REQ: type=0x01, length=8
        if len(var) >= 8 and var[0] == 0x01:
            return struct.unpack_from('<I', var, 4)[0]
    except Exception:
        pass
    return 0

# --- Cookie (old-style) username extraction ---

def extract_cookie_username(data):
    """
    Extract username from X.224 CR cookie. Two formats:
      Standard:   Cookie: mstshash=username\\r\\n
      TS Gateway: mstshvcookie: msts=DOMAIN\\username\\r\\n
    Returns (username, domain) or (None, None).
    """
    try:
        text = data.decode('ascii', errors='replace')

        # Standard Windows RDP client cookie (most common)
        marker = 'Cookie: mstshash='
        if marker in text:
            start = text.index(marker) + len(marker)
            end = text.find('\r\n', start)
            if end == -1:
                end = start + 128
            username = text[start:end].strip()
            return (username, '') if username else (None, None)

        # TS Gateway redirect token (domain\username)
        marker = 'mstshvcookie: msts='
        if marker in text:
            start = text.index(marker) + len(marker)
            end = text.find('\r\n', start)
            if end == -1:
                end = start + 128
            value = text[start:end].strip()
            if '\\' in value:
                domain, username = value.split('\\', 1)
                return username, domain
            return value, ''

        return None, None
    except Exception:
        return None, None

# --- ASN.1 helpers for CredSSP TSRequest ---

def asn1_len(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def asn1_seq(data):
    return b'\x30' + asn1_len(len(data)) + data

def asn1_ctx(tag, data):
    return bytes([0xA0 | tag]) + asn1_len(len(data)) + data

def asn1_int(n):
    return b'\x02\x01' + bytes([n])

def asn1_octet(data):
    return b'\x04' + asn1_len(len(data)) + data

def build_tsrequest(ntlm_token, version=6):
    """Wrap an NTLM token in a CredSSP TSRequest ASN.1 structure."""
    token    = asn1_ctx(0, asn1_octet(ntlm_token))   # [0] negoToken OCTET STRING
    sequence = asn1_seq(asn1_seq(token))              # SEQUENCE OF SEQUENCE
    nego     = asn1_ctx(1, sequence)                  # [1] negoTokens
    ver      = asn1_ctx(0, asn1_int(version))         # [0] version
    return asn1_seq(ver + nego)

def find_ntlmssp(data):
    """Find and return NTLMSSP message bytes from raw data."""
    idx = data.find(b'NTLMSSP\x00')
    return data[idx:] if idx >= 0 else None

def build_tsrequest_error(ntstatus=0xC000006D, version=6):
    """Build a CredSSP TSRequest conveying NLA auth failure (STATUS_LOGON_FAILURE)."""
    ver   = asn1_ctx(0, asn1_int(version))
    # NTSTATUS as 4-byte big-endian; high bit set means negative in DER — correct for 0xC*
    err   = b'\x02\x04' + struct.pack('>I', ntstatus)
    error = asn1_ctx(4, err)
    return asn1_seq(ver + error)

# --- NTLM challenge (Type 2) builder ---

def build_ntlm_challenge():
    """Build a realistic NTLMSSP CHALLENGE (Type 2) message matching Windows 10."""
    domain   = 'WORKGROUP'.encode('utf-16-le')
    computer = _COMPUTER_NAME.encode('utf-16-le')

    def av(av_id, value):
        return struct.pack('<HH', av_id, len(value)) + value

    # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
    filetime = int((time.time() + 11644473600) * 10_000_000)

    target_info  = av(1, computer)                           # MsvAvNbComputerName
    target_info += av(2, domain)                             # MsvAvNbDomainName
    target_info += av(3, computer)                           # MsvAvDnsComputerName
    target_info += av(4, domain)                             # MsvAvDnsDomainName
    target_info += av(7, struct.pack('<Q', filetime))        # MsvAvTimestamp
    target_info += struct.pack('<HH', 0, 0)                  # MsvAvEOL

    flags = (
        0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
        0x00000004 |  # NTLMSSP_REQUEST_TARGET
        0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
        0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0x00010000 |  # NTLMSSP_TARGET_TYPE_SERVER (standalone/workgroup)
        0x00080000 |  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x00800000 |  # NTLMSSP_NEGOTIATE_TARGET_INFO
        0x02000000 |  # NTLMSSP_NEGOTIATE_VERSION
        0x20000000 |  # NTLMSSP_NEGOTIATE_128
        0x40000000 |  # NTLMSSP_NEGOTIATE_KEY_EXCH
        0x80000000    # NTLMSSP_NEGOTIATE_56
    )

    # With version field, header is 56 bytes (48 fixed + 8 version)
    domain_offset      = 56
    target_info_offset = domain_offset + len(domain)

    # Version: Windows 10.0, build 19041, NTLM revision 15
    version = struct.pack('<BBH', 10, 0, 19041) + b'\x00\x00\x00\x0f'

    msg  = b'NTLMSSP\x00'
    msg += struct.pack('<I', 2)
    msg += struct.pack('<HHI', len(domain), len(domain), domain_offset)
    msg += struct.pack('<I', flags)
    msg += os.urandom(8)                                               # ServerChallenge
    msg += b'\x00' * 8                                                 # Reserved
    msg += struct.pack('<HHI', len(target_info), len(target_info), target_info_offset)
    msg += version
    msg += domain
    msg += target_info
    return msg

# --- NTLM AUTHENTICATE (Type 3) parser ---

def parse_ntlm_authenticate(data):
    """
    Parse NTLM AUTHENTICATE (Type 3) message using impacket.
    Returns (username, domain) strings, or (None, None) on failure.
    """
    try:
        resp = ntlm.NTLMAuthChallengeResponse()
        resp.fromString(data)
        username = resp['user_name']
        domain   = resp['domain_name']
        if isinstance(username, bytes):
            username = username.decode('utf-16-le', errors='replace').strip('\x00')
        if isinstance(domain, bytes):
            domain = domain.decode('utf-16-le', errors='replace').strip('\x00')
        return username or None, domain or None
    except Exception:
        return None, None

# --- NLA handshake ---

def do_nla(raw_sock, client_ip, session_id='-'):
    """
    Complete the NLA/CredSSP handshake and return (username, domain).
    Returns (None, None) if handshake fails or no credentials captured.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ctx.minimum_version = resolve_min_tls_version()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    try:
        ctx.set_ciphers(TLS_CIPHERS)
    except Exception:
        pass

    tls = None
    try:
        tls = ctx.wrap_socket(raw_sock, server_side=True)
        trace(session_id, client_ip, 'tls_handshake_ok')
    except Exception as e:
        reason = classify_socket_error(e)
        trace(session_id, client_ip, 'tls_handshake_fail', error=type(e).__name__, reason=reason, detail=str(e))
        print(f"🔍 RDP {client_ip} TLS failed: {e}", flush=True)
        return [], f'tls_handshake_fail:{reason}'

    try:
        tls.settimeout(15)
        captures = []
        for attempt in range(1, MAX_NLA_ATTEMPTS + 1):
            # Step 1: receive TSRequest with NTLM NEGOTIATE (Type 1)
            try:
                data = tls.recv(4096)
            except socket.timeout:
                if attempt == 1:
                    return [], 'nla_timeout_waiting_step1'
                return captures, f'nla_attempts:{len(captures)}'

            ntlm_step1 = find_ntlmssp(data)
            trace(session_id, client_ip, 'nla_step1_recv', attempt=attempt, bytes=len(data), ntlm_found=bool(ntlm_step1))
            if not ntlm_step1:
                print(f"🔍 RDP NLA: no NTLMSSP in step 1 ({len(data)} bytes: {data[:32].hex()})", flush=True)
                if attempt == 1:
                    return [], 'nla_no_ntlm_step1'
                return captures, f'nla_attempts:{len(captures)}'

            # Step 2: send TSRequest with NTLM CHALLENGE (Type 2)
            challenge_bytes = build_ntlm_challenge()
            tls.sendall(build_tsrequest(challenge_bytes))
            trace(session_id, client_ip, 'nla_step2_challenge_sent', attempt=attempt, bytes=len(challenge_bytes))

            # Step 3: receive TSRequest with NTLM AUTHENTICATE (Type 3)
            data = tls.recv(4096)
            ntlm_auth = find_ntlmssp(data)
            trace(session_id, client_ip, 'nla_step3_recv', attempt=attempt, bytes=len(data), ntlm_found=bool(ntlm_auth))
            if not ntlm_auth:
                if attempt == 1:
                    return [], 'nla_no_ntlm_step3'
                return captures, f'nla_attempts:{len(captures)}'

            username, domain = parse_ntlm_authenticate(ntlm_auth)
            trace(session_id, client_ip, 'nla_step3_parsed', attempt=attempt, user=username, domain=domain)
            if username:
                captures.append((username, domain))

            # Step 4: send STATUS_LOGON_FAILURE
            try:
                tls.sendall(build_tsrequest_error())
                trace(session_id, client_ip, 'nla_step4_logon_failure_sent', attempt=attempt)
            except Exception as e:
                reason = classify_socket_error(e)
                trace(session_id, client_ip, 'nla_step4_logon_failure_send_failed', attempt=attempt, error=type(e).__name__, reason=reason)
                return captures, f'nla_logon_failure_send_failed:{reason}'

            # After first round, use shorter timeout for possible retry attempts.
            tls.settimeout(3)

        return captures, f'nla_attempts:{len(captures)}'

    except Exception as e:
        reason = classify_socket_error(e)
        trace(session_id, client_ip, 'nla_exception', error=type(e).__name__, reason=reason, detail=str(e))
        return [], f'nla_error:{reason}'
    finally:
        if tls is not None:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

# --- Connection handler ---

def handle_connection(client_sock, client_ip):
    session_id = uuid.uuid4().hex[:8]
    started_at = time.time()
    final_stage = 'unknown'
    creds_captured = False
    try:
        trace(session_id, client_ip, 'connect')
        print(f"🔌 RDP connect {client_ip}", flush=True)

        # Read X.224 Connection Request
        data = read_x224_packet(client_sock)
        if not data:
            final_stage = 'x224_empty'
            trace(session_id, client_ip, 'x224_empty')
            return
        trace(session_id, client_ip, 'x224_recv', bytes=len(data))

        # Extract cookie username if present — but don't return, fall through to NLA
        cookie_user, cookie_domain = extract_cookie_username(data)
        trace(session_id, client_ip, 'cookie_parsed', user=cookie_user, domain=cookie_domain)

        # Check if client requested SSL/TLS or NLA/CredSSP
        # 0x01=PROTOCOL_SSL, 0x02=PROTOCOL_HYBRID (NLA/CredSSP)
        req_protocols = parse_req_protocols(data)
        trace(session_id, client_ip, 'req_protocols', value=f'0x{req_protocols:08x}')
        print(f"🔍 RDP {client_ip} req_protocols=0x{req_protocols:08x} cookie={cookie_user!r}", flush=True)
        if not (req_protocols & 0x03):
                # Client doesn't want SSL — emit cookie knock if we have one, then done
                if cookie_user:
                    trace(session_id, client_ip, 'emit_cookie_knock')
                    knock = {"type": "KNOCK", "proto": "RDP",
                             "ip": client_ip, "user": cookie_user, "pass": cookie_domain or ''}
                    print(json.dumps(knock), flush=True)
                    final_stage = 'cookie_knock_emitted_non_ssl'
                else:
                    trace(session_id, client_ip, 'non_ssl_no_cookie')
                    final_stage = 'non_ssl_no_cookie'
                return

        # Try NLA — if sendall or handshake fails, fall back to cookie
        captures, nla_status = [], None
        try:
            client_sock.sendall(X224_CC_SSL)
            trace(session_id, client_ip, 'x224_cc_ssl_sent')
            print(f"🔍 RDP {client_ip} sent X224_CC_SSL, starting NLA", flush=True)
            captures, nla_status = do_nla(client_sock, client_ip, session_id=session_id)
            if captures:
                print(f"🔍 RDP {client_ip} NLA result: captures={captures!r}", flush=True)
            else:
                print(f"🔍 RDP {client_ip} NLA result: captures=[]", flush=True)
            final_stage = nla_status or 'nla_completed'
        except Exception as e:
            reason = classify_socket_error(e)
            trace(session_id, client_ip, 'nla_outer_exception', error=type(e).__name__, reason=reason, detail=str(e))
            print(f"🔍 RDP {client_ip} NLA outer exception: {type(e).__name__}: {e}", flush=True)
            final_stage = f'nla_outer_exception:{reason}'

        if captures:
            for i, (username, domain) in enumerate(captures, start=1):
                trace(session_id, client_ip, 'emit_nla_knock', attempt=i, user=username, domain=domain)
                knock = {"type": "KNOCK", "proto": "RDP",
                         "ip": client_ip, "user": username, "pass": domain or ''}
                print(json.dumps(knock), flush=True)
            final_stage = f'nla_knocks_emitted:{len(captures)}'
            creds_captured = True
        elif cookie_user:
            trace(session_id, client_ip, 'emit_cookie_fallback_knock')
            knock = {"type": "KNOCK", "proto": "RDP",
                     "ip": client_ip, "user": cookie_user, "pass": cookie_domain or ''}
            print(json.dumps(knock), flush=True)
            if nla_status:
                final_stage = f'cookie_fallback_after:{nla_status}'
            else:
                final_stage = 'cookie_fallback_knock_emitted'
        else:
            trace(session_id, client_ip, 'no_credentials_captured')
            if final_stage == 'nla_completed':
                final_stage = 'nla_no_credentials'

    except Exception as e:
        trace(session_id, client_ip, 'handler_exception', error=type(e).__name__, detail=str(e))
        final_stage = f'handler_exception:{type(e).__name__}'
    finally:
        try:
            client_sock.close()
            trace(session_id, client_ip, 'socket_closed')
        except Exception:
            pass
        duration_ms = int((time.time() - started_at) * 1000)
        trace(
            session_id,
            client_ip,
            'session_summary',
            duration_ms=duration_ms,
            final_stage=final_stage,
            creds_captured=creds_captured,
        )

def normalize_ip(ip):
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def start_honeypot():
    ensure_cert()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 3389))
    sock.listen(100)
    print("🚀 RDP Honeypot Active on Port 3389 (NLA/NTLM). Collecting radiation...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

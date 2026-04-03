#!/usr/bin/env python3
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
import random
import string
import uuid
from common import (
    create_dualstack_tcp_listener,
    ensure_self_signed_server_cert,
    get_redis_client,
    is_blocked,
    normalize_ip,
)

from impacket import ntlm

# Randomised Windows 10-style computer name, generated once at startup
_COMPUTER_NAME = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))

CERT_FILE = os.environ.get('DB_DIR', 'data') + '/rdp.crt'
KEY_FILE  = os.environ.get('DB_DIR', 'data') + '/rdp.key'

_r = get_redis_client()
TRACE_ENABLED = os.environ.get('RDP_TRACE', '1').lower() not in ('0', 'false', 'no')
TRACE_IP = os.environ.get('RDP_TRACE_IP', '').strip()
# Compatibility-first TLS policy for honeypot capture fidelity.
TLS_MIN_VERSION = '1.0'
TLS_CIPHERS = 'ALL:@SECLEVEL=0'
CERT_DIGEST = 'sha1'
MAX_NLA_ATTEMPTS = max(1, int(os.environ.get('RDP_MAX_NLA_ATTEMPTS', '3')))
NLA_STEP1_EXTRA_READS = max(0, int(os.environ.get('RDP_NLA_STEP1_EXTRA_READS', '2')))
NLA_STEP1_EXTRA_TIMEOUT = max(0.1, float(os.environ.get('RDP_NLA_STEP1_EXTRA_TIMEOUT', '0.6')))
NLA_STEP3_EXTRA_READS = max(0, int(os.environ.get('RDP_NLA_STEP3_EXTRA_READS', '2')))
NLA_STEP3_EXTRA_TIMEOUT = max(0.1, float(os.environ.get('RDP_NLA_STEP3_EXTRA_TIMEOUT', '0.6')))
RDP_CLASSIC_CAPTURE = os.environ.get('RDP_CLASSIC_CAPTURE', '0').lower() in ('1', 'true', 'yes', 'on')
# Targeted experiment: for IPs with repeated NLA parse failures, force classic
# on subsequent attempts to probe for plaintext credential flows.
RDP_FORCE_CLASSIC_EXPERIMENT = True
RDP_FORCE_CLASSIC_TTL_SEC = 1800
RDP_FORCE_CLASSIC_FAILS_THRESHOLD = 2

_classic_import_error = None
if RDP_CLASSIC_CAPTURE:
    try:
        from rdp_classic_security import do_classic_rdp_security, X224_CC_RDP
    except Exception as e:
        _classic_import_error = str(e)

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

def _force_classic_key(ip):
    return f"rdp:force_classic:{ip}"

def _nla_fail_key(ip):
    return f"rdp:nla_parse_fail:{ip}"

def should_force_classic(ip):
    if not RDP_FORCE_CLASSIC_EXPERIMENT:
        return False
    try:
        return bool(_r.exists(_force_classic_key(ip)))
    except Exception:
        return False

def clear_force_classic(ip):
    try:
        _r.delete(_force_classic_key(ip))
        _r.delete(_nla_fail_key(ip))
    except Exception:
        pass

def normalize_knock_username(username):
    if username is None:
        return None
    if not isinstance(username, str):
        username = str(username)
    return username.lower()

def note_nla_parse_failure(ip, nla_status):
    """
    Track NLA failures likely caused by parse/handshake incompleteness and
    enable temporary classic forcing for that IP after repeated failures.
    Returns (fail_count, forced_enabled).
    """
    if not RDP_FORCE_CLASSIC_EXPERIMENT:
        return 0, False
    if not nla_status:
        return 0, False
    interesting = (
        nla_status in ('nla_no_ntlm_step1', 'nla_no_ntlm_step3') or
        nla_status.startswith('nla_attempts:0')
    )
    if not interesting:
        return 0, False
    try:
        count = int(_r.incr(_nla_fail_key(ip)))
        _r.expire(_nla_fail_key(ip), RDP_FORCE_CLASSIC_TTL_SEC)
        forced = False
        if count >= RDP_FORCE_CLASSIC_FAILS_THRESHOLD:
            _r.setex(_force_classic_key(ip), RDP_FORCE_CLASSIC_TTL_SEC, '1')
            forced = True
        return count, forced
    except Exception:
        return 0, False

def ensure_cert():
    """Generate a self-signed cert for TLS if not already present."""
    # Preserve existing broad client compatibility defaults for this endpoint.
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    ensure_self_signed_server_cert(
        cert_path=CERT_FILE,
        key_path=KEY_FILE,
        subject='/CN=DESKTOP-RDP/O=Microsoft/C=US',
        san_dns=None,
        days=3650,
        digest=CERT_DIGEST,
    )

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
    Returns (username, domain, workstation) strings, or (None, None, None) on failure.
    """
    def _read_secbuf(buf, off):
        if len(buf) < off + 8:
            return None
        length = struct.unpack_from('<H', buf, off)[0]
        # max_length = struct.unpack_from('<H', buf, off + 2)[0]
        offset = struct.unpack_from('<I', buf, off + 4)[0]
        if length <= 0:
            return b''
        if offset < 0 or offset + length > len(buf):
            return None
        return buf[offset:offset + length]

    def _decode_ntlm_text(raw, flags):
        if raw is None:
            return None
        if not raw:
            return ''
        # NTLMSSP_NEGOTIATE_UNICODE
        if flags & 0x00000001:
            return raw.decode('utf-16-le', errors='replace').strip('\x00')
        return raw.decode('latin-1', errors='replace').strip('\x00')

    try:
        resp = ntlm.NTLMAuthChallengeResponse()
        resp.fromString(data)
        username = resp['user_name']
        domain   = resp['domain_name']
        if isinstance(username, bytes):
            username = username.decode('utf-16-le', errors='replace').strip('\x00')
        if isinstance(domain, bytes):
            domain = domain.decode('utf-16-le', errors='replace').strip('\x00')
        # impacket may expose host_name / workstation
        workstation = resp.fields.get('host_name') or resp.fields.get('workstation')
        if isinstance(workstation, bytes):
            workstation = workstation.decode('utf-16-le', errors='replace').strip('\x00')
        workstation = workstation or None
        username = username or None
        domain = domain or None
        if username:
            return username, domain, workstation
    except Exception:
        pass

    # Fallback parser for Type-3 variants impacket doesn't decode cleanly.
    # AUTH message layout: secbuf(domain @28), secbuf(user @36), secbuf(workstation @44), flags @60.
    try:
        if len(data) < 64 or not data.startswith(b'NTLMSSP\x00'):
            return None, None, None
        msg_type = struct.unpack_from('<I', data, 8)[0]
        if msg_type != 3:
            return None, None, None
        flags = struct.unpack_from('<I', data, 60)[0]
        domain_raw = _read_secbuf(data, 28)
        user_raw = _read_secbuf(data, 36)
        workstation_raw = _read_secbuf(data, 44)
        username = _decode_ntlm_text(user_raw, flags)
        domain = _decode_ntlm_text(domain_raw, flags)
        workstation = _decode_ntlm_text(workstation_raw, flags)
        return username or None, domain or None, workstation or None
    except Exception:
        return None, None, None

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
            total_bytes = len(data)
            extra_reads = 0
            if not ntlm_step1 and data:
                # Some clients split TSRequest/NTLMSSP across multiple TLS records.
                original_timeout = tls.gettimeout()
                tls.settimeout(NLA_STEP1_EXTRA_TIMEOUT)
                try:
                    for _ in range(NLA_STEP1_EXTRA_READS):
                        more = tls.recv(4096)
                        if not more:
                            break
                        extra_reads += 1
                        total_bytes += len(more)
                        data += more
                        ntlm_step1 = find_ntlmssp(data)
                        if ntlm_step1:
                            break
                except (socket.timeout, TimeoutError):
                    pass
                finally:
                    tls.settimeout(original_timeout)

            trace(
                session_id,
                client_ip,
                'nla_step1_recv',
                attempt=attempt,
                bytes=total_bytes,
                ntlm_found=bool(ntlm_step1),
                extra_reads=extra_reads,
            )
            if not ntlm_step1:
                print(f"🔍 RDP NLA: no NTLMSSP in step 1 ({total_bytes} bytes: {data[:32].hex()})", flush=True)
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
            total_step3_bytes = len(data)
            step3_extra_reads = 0
            if not ntlm_auth and data:
                original_timeout = tls.gettimeout()
                tls.settimeout(NLA_STEP3_EXTRA_TIMEOUT)
                try:
                    for _ in range(NLA_STEP3_EXTRA_READS):
                        more = tls.recv(4096)
                        if not more:
                            break
                        step3_extra_reads += 1
                        total_step3_bytes += len(more)
                        data += more
                        ntlm_auth = find_ntlmssp(data)
                        if ntlm_auth:
                            break
                except (socket.timeout, TimeoutError):
                    pass
                finally:
                    tls.settimeout(original_timeout)
            trace(
                session_id,
                client_ip,
                'nla_step3_recv',
                attempt=attempt,
                bytes=total_step3_bytes,
                ntlm_found=bool(ntlm_auth),
                extra_reads=step3_extra_reads,
            )
            if not ntlm_auth:
                if attempt == 1:
                    return [], 'nla_no_ntlm_step3'
                return captures, f'nla_attempts:{len(captures)}'

            username, domain, workstation = parse_ntlm_authenticate(ntlm_auth)
            if not username and data:
                # Some clients deliver fragmented/auth-variant payloads.
                original_timeout = tls.gettimeout()
                tls.settimeout(NLA_STEP3_EXTRA_TIMEOUT)
                try:
                    for _ in range(NLA_STEP3_EXTRA_READS):
                        more = tls.recv(4096)
                        if not more:
                            break
                        step3_extra_reads += 1
                        total_step3_bytes += len(more)
                        data += more
                        ntlm_auth = find_ntlmssp(data)
                        if not ntlm_auth:
                            continue
                        username, domain, workstation = parse_ntlm_authenticate(ntlm_auth)
                        if username:
                            break
                except (socket.timeout, TimeoutError):
                    pass
                finally:
                    tls.settimeout(original_timeout)
            trace(session_id, client_ip, 'nla_step3_parsed', attempt=attempt, user=username, domain=domain, workstation=workstation)
            if username:
                captures.append((username, domain, workstation))

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
        def try_classic_path(path_reason):
            nonlocal final_stage, creds_captured
            if not (RDP_CLASSIC_CAPTURE and _classic_import_error is None):
                if RDP_CLASSIC_CAPTURE and _classic_import_error is not None:
                    trace(session_id, client_ip, 'classic_unavailable', error=_classic_import_error)
                else:
                    trace(session_id, client_ip, 'classic_disabled_non_ssl')
                return False
            trace(session_id, client_ip, 'classic_security_path', reason=path_reason)
            try:
                client_sock.sendall(X224_CC_RDP)
                trace(session_id, client_ip, 'x224_cc_rdp_sent')
                username, password, domain, classic_status = do_classic_rdp_security(
                    client_sock,
                    client_ip,
                    trace_fn=trace,
                    session_id=session_id,
                )
                final_stage = classic_status
                if username:
                    emit_user = normalize_knock_username(username)
                    knock = {"type": "KNOCK", "proto": "RDP",
                             "ip": client_ip, "user": emit_user, "rdp_source": "classic"}
                    if domain:
                        knock["domain"] = domain
                    print(json.dumps(knock), flush=True)
                    trace(session_id, client_ip, 'emit_classic_knock',
                          user=username, has_password=bool(password), domain=domain)
                    final_stage = 'classic_knock_emitted'
                    creds_captured = True
                    clear_force_classic(client_ip)
                    return True
                if cookie_user:
                    emit_user = normalize_knock_username(cookie_user)
                    trace(session_id, client_ip, 'emit_cookie_fallback_classic')
                    knock = {"type": "KNOCK", "proto": "RDP",
                             "ip": client_ip, "user": emit_user, "rdp_source": "cookie"}
                    if cookie_domain:
                        knock["domain"] = cookie_domain
                    print(json.dumps(knock), flush=True)
                    final_stage = f'cookie_fallback_after_classic:{classic_status}'
                    return True
            except Exception as e:
                reason = classify_socket_error(e)
                trace(session_id, client_ip, 'classic_outer_exception',
                      error=type(e).__name__, reason=reason, detail=str(e))
                final_stage = f'classic_outer_exception:{reason}'
            return False

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
        force_classic = should_force_classic(client_ip)
        trace(session_id, client_ip, 'req_protocols', value=f'0x{req_protocols:08x}')
        trace(session_id, client_ip, 'force_classic_check', enabled=force_classic)
        print(f"🔍 RDP {client_ip} req_protocols=0x{req_protocols:08x} cookie={cookie_user!r}", flush=True)
        if force_classic and RDP_CLASSIC_CAPTURE and _classic_import_error is None:
            if try_classic_path('forced_after_nla_failures'):
                return
            # Don't attempt NLA after having already emitted classic confirm on this socket.
            if cookie_user:
                emit_user = normalize_knock_username(cookie_user)
                trace(session_id, client_ip, 'emit_cookie_knock_after_forced_classic')
                knock = {"type": "KNOCK", "proto": "RDP",
                         "ip": client_ip, "user": emit_user, "rdp_source": "cookie"}
                if cookie_domain:
                    knock["domain"] = cookie_domain
                print(json.dumps(knock), flush=True)
                final_stage = f'{final_stage}|cookie_knock_after_forced_classic'
            else:
                final_stage = f'{final_stage}|forced_classic_no_credentials'
            return

        if not (req_protocols & 0x03):
                if try_classic_path('client_non_ssl'):
                    return

                # Client doesn't want SSL — emit cookie knock if we have one, then done
                if cookie_user:
                    emit_user = normalize_knock_username(cookie_user)
                    trace(session_id, client_ip, 'emit_cookie_knock')
                    knock = {"type": "KNOCK", "proto": "RDP",
                             "ip": client_ip, "user": emit_user, "rdp_source": "cookie"}
                    if cookie_domain:
                        knock["domain"] = cookie_domain
                    print(json.dumps(knock), flush=True)
                    if final_stage.startswith('classic_'):
                        final_stage = f'{final_stage}|cookie_knock_emitted_non_ssl'
                    else:
                        final_stage = 'cookie_knock_emitted_non_ssl'
                else:
                    trace(session_id, client_ip, 'non_ssl_no_cookie')
                    if final_stage.startswith('classic_'):
                        final_stage = f'{final_stage}|non_ssl_no_cookie'
                    else:
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
            for i, (username, domain, workstation) in enumerate(captures, start=1):
                emit_user = normalize_knock_username(username)
                trace(session_id, client_ip, 'emit_nla_knock', attempt=i, user=username, domain=domain, workstation=workstation)
                knock = {"type": "KNOCK", "proto": "RDP",
                         "ip": client_ip, "user": emit_user, "rdp_source": "nla"}
                if domain:
                    knock["domain"] = domain
                if workstation:
                    knock["rdp_workstation"] = workstation
                print(json.dumps(knock), flush=True)
            final_stage = f'nla_knocks_emitted:{len(captures)}'
            creds_captured = True
            clear_force_classic(client_ip)
        else:
            fail_count, forced = note_nla_parse_failure(client_ip, nla_status or '')
            if fail_count:
                trace(session_id, client_ip, 'nla_parse_failure_recorded',
                      count=fail_count, force_classic_enabled=forced, status=nla_status)
        if (not captures) and cookie_user:
            emit_user = normalize_knock_username(cookie_user)
            trace(session_id, client_ip, 'emit_cookie_fallback_knock')
            knock = {"type": "KNOCK", "proto": "RDP",
                     "ip": client_ip, "user": emit_user, "rdp_source": "cookie"}
            if cookie_domain:
                knock["domain"] = cookie_domain
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

def start_honeypot():
    ensure_cert()
    if RDP_CLASSIC_CAPTURE:
        if _classic_import_error is None:
            print("🧪 RDP classic capture enabled (RDP_CLASSIC_CAPTURE=1)", flush=True)
        else:
            print(f"⚠️ RDP classic capture enabled but unavailable: {_classic_import_error}", flush=True)
    else:
        print("🧪 RDP classic capture disabled (set RDP_CLASSIC_CAPTURE=1 to enable)", flush=True)
    sock = create_dualstack_tcp_listener(3389, backlog=100)
    print("🚀 RDP Honeypot Active on Port 3389 (NLA/NTLM). Collecting knocks...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

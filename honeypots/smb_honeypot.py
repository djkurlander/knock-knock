#!/usr/bin/env python3
"""
SMB honeypot — minimal raw-socket implementation.
Handles SMB1/2/3 NEGOTIATE → SESSION_SETUP (NTLM 3-way) → TREE_CONNECT.
Zero filesystem backing: responds to TREE_CONNECT with STATUS_ACCESS_DENIED and closes.

Stage 1: foundation — all helpers, header parsers/builders, dedup, knock emission.
         handle_connection() is a stub that identifies SMB1 vs SMB2 and closes.
"""
import json
import os
import struct
import threading
import time

from impacket import ntlm
from common import create_dualstack_tcp_listener, is_blocked, normalize_ip

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SMB_PORT              = int(os.environ.get('SMB_PORT', '445'))
TRACE_ENABLED         = os.environ.get('SMB_TRACE', '0').lower() not in ('0', 'false', 'no')
TRACE_IP              = os.environ.get('SMB_TRACE_IP', '').strip()
EMIT_DEDUP_WINDOW_SEC = max(1, int(os.environ.get('SMB_DEDUP_WINDOW_SEC', '60')))
SMB_SERVER_NAME       = (os.environ.get('SMB_SERVER_NAME', '').strip()
                         or 'Windows Server 2019 Standard 10.0')
SMB_SERVER_DOMAIN     = (os.environ.get('SMB_SERVER_DOMAIN', '').strip()
                         or 'WORKGROUP')

# Decoy shares: loaded at startup from SMB_DECOY_DIR folder (or hardcoded default).
# Structure: dict[share_name_upper -> dict[filename -> bytes]]
# Zero filesystem access after _load_decoys() returns.
_DEFAULT_DECOY_CONTENT = (
    b'# Network Credentials\r\n'
    b'# This file is highly confidential - do not distribute\r\n'
    b'\r\n'
    b'[Default]\r\n'
    b'admin:admin123\r\n'
    b'administrator:Password1!\r\n'
    b'root:toor\r\n'
    b'\r\n'
    b'[Services]\r\n'
    b'backup:Backup#2024\r\n'
    b'fileserver:fs@2024!\r\n'
    b'mailserver:M@1lS3rv3r\r\n'
    b'\r\n'
    b'[Database]\r\n'
    b'sa:SQLAdmin2024\r\n'
    b'postgres:pgAdmin!\r\n'
)


def _load_decoys() -> dict:
    """Load decoy shares from SMB_DECOY_DIR (e.g. honeypots/decoys/PUBLIC/passwords.txt).
    Defaults to a 'decoys/' folder next to this script if env var is unset.
    Falls back to hardcoded default if the directory is missing or empty.
    Returns dict[share_name_upper -> dict[filename -> bytes]]."""
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    decoy_dir = (os.environ.get('SMB_DECOY_DIR', '').strip()
                 or os.path.join(_script_dir, 'decoys'))
    decoys: dict = {}
    if decoy_dir and os.path.isdir(decoy_dir):
        try:
            for share_entry in os.scandir(decoy_dir):
                if not share_entry.is_dir():
                    continue
                share_name = share_entry.name.upper()
                files: dict = {}
                for file_entry in os.scandir(share_entry.path):
                    if file_entry.is_file():
                        try:
                            with open(file_entry.path, 'rb') as fh:
                                files[file_entry.name] = fh.read()
                        except Exception:
                            pass
                if files:
                    decoys[share_name] = files
        except Exception:
            pass
    if not decoys:
        decoys = {'PUBLIC': {'passwords.txt': _DEFAULT_DECOY_CONTENT}}
    return decoys


_DECOYS: dict = _load_decoys()  # share_name_upper -> {filename -> bytes}

_MAX_MSG      = 20       # per-connection message cap (prevents runaway state machine)
_SOCK_TIMEOUT = 15       # seconds per recv
_NBSS_MAX     = 262144   # 256 KB NBSS payload cap (prevents memory exhaustion)

_dedup_lock = threading.Lock()
_dedup_seen: dict = {}

# ---------------------------------------------------------------------------
# ASN.1 helpers (copied from rdp_honeypot.py)
# ---------------------------------------------------------------------------

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

def asn1_octet(data):
    return b'\x04' + asn1_len(len(data)) + data

# ---------------------------------------------------------------------------
# SPNEGO constants (built once at module load using the asn1_* helpers above)
# ---------------------------------------------------------------------------

# NegTokenInit — GSSAPI initial token advertising NTLMSSP as the only mechanism.
#
# Correct GSSAPI structure (RFC 4178 §4.2 + RFC 2743 §3.1):
#   Application[0] {
#     OID(SPNEGO: 1.3.6.1.5.5.2)          ← thisMech — identifies SPNEGO itself
#     [0] NegTokenInit {                   ← innerContextToken
#       SEQUENCE {
#         [0] mechTypes { SEQUENCE { OID(NTLMSSP: 1.3.6.1.4.1.311.2.2.10) } }
#       }
#     }
#   }
_SPNEGO_OID  = b'\x06\x06\x2b\x06\x01\x05\x05\x02'              # OID 1.3.6.1.5.5.2
_NTLMSSP_OID = b'\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # OID 1.3.6.1.4.1.311.2.2.10
_neg_token_init = asn1_ctx(0, asn1_seq(asn1_ctx(0, asn1_seq(_NTLMSSP_OID))))
_spnego_body = _SPNEGO_OID + _neg_token_init
_SPNEGO_NEGTOKENINIT = b'\x60' + asn1_len(len(_spnego_body)) + _spnego_body

# NegTokenResp accept-completed — sent in SESSION_SETUP round-2 response.
# Structure: [1] NegTokenResp { SEQUENCE { [0] negState ENUMERATED { accept-completed(0) } } }
_SPNEGO_ACCEPT_COMPLETE = asn1_ctx(1, asn1_seq(asn1_ctx(0, b'\x0a\x01\x00')))

# ---------------------------------------------------------------------------
# SPNEGO builders
# ---------------------------------------------------------------------------

def build_spnego_challenge(ntlm_token):
    """Wrap NTLM Type 2 (challenge) bytes in a SPNEGO NegTokenResp (accept-incomplete)."""
    # [1] NegTokenResp { SEQUENCE { [0] accept-incomplete(1), [2] responseToken { OCTET STRING } } }
    inner = asn1_seq(
        asn1_ctx(0, b'\x0a\x01\x01') +          # negState = accept-incomplete
        asn1_ctx(2, asn1_octet(ntlm_token))       # responseToken
    )
    return asn1_ctx(1, inner)

# ---------------------------------------------------------------------------
# NTLM helpers (copied/adapted from rdp_honeypot.py)
# ---------------------------------------------------------------------------

def find_ntlmssp(data):
    """Find and return NTLMSSP message bytes starting from the NTLMSSP\x00 signature."""
    idx = data.find(b'NTLMSSP\x00')
    return data[idx:] if idx >= 0 else None


def build_ntlm_challenge(domain=None, computer=None):
    """
    Build a realistic NTLMSSP CHALLENGE (Type 2) message.
    Adapted from rdp_honeypot.py: accepts domain/computer kwargs (defaults to env vars)
    instead of using module-level constants.
    """
    domain_enc   = (domain   or SMB_SERVER_DOMAIN).encode('utf-16-le')
    computer_enc = (computer or SMB_SERVER_NAME  ).encode('utf-16-le')

    def av(av_id, value):
        return struct.pack('<HH', av_id, len(value)) + value

    # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
    filetime = int((time.time() + 11644473600) * 10_000_000)

    target_info  = av(1, computer_enc)                         # MsvAvNbComputerName
    target_info += av(2, domain_enc)                           # MsvAvNbDomainName
    target_info += av(3, computer_enc)                         # MsvAvDnsComputerName
    target_info += av(4, domain_enc)                           # MsvAvDnsDomainName
    target_info += av(7, struct.pack('<Q', filetime))          # MsvAvTimestamp
    target_info += struct.pack('<HH', 0, 0)                    # MsvAvEOL

    flags = (
        0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
        0x00000004 |  # NTLMSSP_REQUEST_TARGET
        0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
        0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0x00010000 |  # NTLMSSP_TARGET_TYPE_SERVER
        0x00080000 |  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x00800000 |  # NTLMSSP_NEGOTIATE_TARGET_INFO
        0x02000000 |  # NTLMSSP_NEGOTIATE_VERSION
        0x20000000 |  # NTLMSSP_NEGOTIATE_128
        0x40000000 |  # NTLMSSP_NEGOTIATE_KEY_EXCH
        0x80000000    # NTLMSSP_NEGOTIATE_56
    )

    # With version field, fixed header is 56 bytes
    domain_offset      = 56
    target_info_offset = domain_offset + len(domain_enc)
    # Version: Windows 10.0 build 17763 (Server 2019), NTLM revision 15
    version = struct.pack('<BBH', 10, 0, 17763) + b'\x00\x00\x00\x0f'

    msg  = b'NTLMSSP\x00'
    msg += struct.pack('<I', 2)                                                       # MessageType
    msg += struct.pack('<HHI', len(domain_enc), len(domain_enc), domain_offset)       # TargetNameFields
    msg += struct.pack('<I', flags)                                                   # NegotiateFlags
    msg += os.urandom(8)                                                              # ServerChallenge
    msg += b'\x00' * 8                                                                # Reserved
    msg += struct.pack('<HHI', len(target_info), len(target_info), target_info_offset) # TargetInfoFields
    msg += version
    msg += domain_enc
    msg += target_info
    return msg


def parse_ntlm_authenticate(data):
    """
    Parse NTLM AUTHENTICATE (Type 3) message.
    Returns (username, domain, workstation) — any may be None on failure.
    Copied verbatim from rdp_honeypot.py.
    """
    def _read_secbuf(buf, off):
        if len(buf) < off + 8:
            return None
        length = struct.unpack_from('<H', buf, off)[0]
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
        if flags & 0x00000001:  # NTLMSSP_NEGOTIATE_UNICODE
            return raw.decode('utf-16-le', errors='replace').strip('\x00')
        return raw.decode('latin-1', errors='replace').strip('\x00')

    # Primary path: impacket NTLMAuthChallengeResponse
    try:
        resp = ntlm.NTLMAuthChallengeResponse()
        resp.fromString(data)
        username    = resp['user_name']
        domain      = resp['domain_name']
        if isinstance(username, bytes):
            username = username.decode('utf-16-le', errors='replace').strip('\x00')
        if isinstance(domain, bytes):
            domain = domain.decode('utf-16-le', errors='replace').strip('\x00')
        workstation = resp.fields.get('host_name') or resp.fields.get('workstation')
        if isinstance(workstation, bytes):
            workstation = workstation.decode('utf-16-le', errors='replace').strip('\x00')
        if username:
            return username or None, domain or None, workstation or None
    except Exception:
        pass

    # Fallback: manual struct parser for Type-3 variants impacket doesn't decode cleanly
    try:
        if len(data) < 64 or not data.startswith(b'NTLMSSP\x00'):
            return None, None, None
        if struct.unpack_from('<I', data, 8)[0] != 3:
            return None, None, None
        flags       = struct.unpack_from('<I', data, 60)[0]
        username    = _decode_ntlm_text(_read_secbuf(data, 36), flags)
        domain      = _decode_ntlm_text(_read_secbuf(data, 28), flags)
        workstation = _decode_ntlm_text(_read_secbuf(data, 44), flags)
        return username or None, domain or None, workstation or None
    except Exception:
        return None, None, None

# ---------------------------------------------------------------------------
# NBSS framing (NetBIOS Session Service over TCP — all SMB/TCP uses this)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def recv_nbss(sock):
    """Read one NBSS-framed message. Returns the payload (without the 4-byte header)."""
    hdr    = _recv_exact(sock, 4)
    length = int.from_bytes(hdr[1:4], 'big')
    if length > _NBSS_MAX:
        raise ValueError(f'NBSS payload too large: {length}')
    return _recv_exact(sock, length)


def send_nbss(sock, data):
    """Send data wrapped in a 4-byte NBSS SESSION_MESSAGE header."""
    sock.sendall(b'\x00' + len(data).to_bytes(3, 'big') + data)

# ---------------------------------------------------------------------------
# SMB2 header (64 bytes)
# ---------------------------------------------------------------------------

_SMB2_MAGIC          = b'\xfeSMB'
_SMB2_FLAGS_RESPONSE = 0x00000001

# SMB2 command codes
SMB2_NEGOTIATE       = 0x0000
SMB2_SESSION_SETUP   = 0x0001
SMB2_LOGOFF          = 0x0002
SMB2_TREE_CONNECT    = 0x0003
SMB2_TREE_DISCONNECT = 0x0004
SMB2_CREATE          = 0x0005
SMB2_CLOSE           = 0x0006
SMB2_READ            = 0x0008
SMB2_WRITE           = 0x0009
SMB2_IOCTL           = 0x000B
SMB2_QUERY_DIRECTORY = 0x000E
SMB2_QUERY_INFO      = 0x0010

# NT Status codes
STATUS_SUCCESS               = 0x00000000
STATUS_MORE_PROCESSING       = 0xC0000016
STATUS_ACCESS_DENIED         = 0xC0000022
STATUS_LOGON_FAILURE         = 0xC000006D
STATUS_NO_MORE_FILES         = 0x80000006
STATUS_END_OF_FILE           = 0xC0000011
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_NOT_SUPPORTED         = 0xC00000BB
STATUS_BAD_NETWORK_NAME      = 0xC00000CC


def parse_smb2_header(data):
    """Parse 64-byte SMB2 header. Returns a dict or None if data is too short/wrong magic."""
    if len(data) < 64 or data[:4] != _SMB2_MAGIC:
        return None
    return {
        'command':    struct.unpack_from('<H', data, 12)[0],
        'status':     struct.unpack_from('<I', data,  8)[0],
        'flags':      struct.unpack_from('<I', data, 16)[0],
        'message_id': struct.unpack_from('<Q', data, 24)[0],
        'tree_id':    struct.unpack_from('<I', data, 36)[0],
        'session_id': struct.unpack_from('<Q', data, 40)[0],
    }


def build_smb2_response_header(command, status, message_id, session_id=0, tree_id=0):
    """Build a 64-byte SMB2 response header."""
    return (
        _SMB2_MAGIC
        + struct.pack('<H', 64)                   # StructureSize = 64
        + struct.pack('<H', 0)                    # CreditCharge
        + struct.pack('<I', status)               # Status
        + struct.pack('<H', command)              # Command
        + struct.pack('<H', 1)                    # CreditsGranted
        + struct.pack('<I', _SMB2_FLAGS_RESPONSE) # Flags
        + struct.pack('<I', 0)                    # NextCommand
        + struct.pack('<Q', message_id)           # MessageId
        + struct.pack('<I', 0)                    # ProcessId
        + struct.pack('<I', tree_id)              # TreeId
        + struct.pack('<Q', session_id)           # SessionId
        + b'\x00' * 16                            # Signature
    )

# ---------------------------------------------------------------------------
# SMB1 header (32 bytes)
# ---------------------------------------------------------------------------

_SMB1_MAGIC = b'\xffSMB'

# SMB1 command codes
SMB1_COM_CLOSE          = 0x04
SMB1_COM_WRITE_ANDX     = 0x2F
SMB1_COM_READ_ANDX      = 0x2E
SMB1_COM_TRANSACTION2   = 0x32
SMB1_COM_NEGOTIATE      = 0x72
SMB1_COM_SESSION_SETUP  = 0x73
SMB1_COM_TREE_CONNECT   = 0x75
SMB1_COM_NT_CREATE_ANDX = 0xA2
_SMB1_TRANS2_FIND_FIRST2 = 0x0001   # TRANS2 sub-command
_SMB2_CREATE_DISP_FILE_OPEN = 0x00000001  # open existing only — no write intent

# SMB1 Flags2 bits
SMB1_FLAGS2_EXTENDED_SEC = 0x0800
SMB1_FLAGS2_UNICODE      = 0x8000


def parse_smb1_header(data):
    """Parse 32-byte SMB1 header. Returns a dict or None if data is too short/wrong magic."""
    if len(data) < 32 or data[:4] != _SMB1_MAGIC:
        return None
    return {
        'command': data[4],
        'status':  struct.unpack_from('<I', data,  5)[0],
        'flags2':  struct.unpack_from('<H', data, 10)[0],
        'tid':     struct.unpack_from('<H', data, 24)[0],
        'uid':     struct.unpack_from('<H', data, 28)[0],
        'mid':     struct.unpack_from('<H', data, 30)[0],
    }


def build_smb1_response_header(command, status, flags2, uid=0, tid=0, mid=0):
    """Build a 32-byte SMB1 response header."""
    return (
        _SMB1_MAGIC
        + bytes([command])
        + struct.pack('<I', status)
        + bytes([0x98])                           # Flags: REPLY | CANONICALIZED | CASE_INSENSITIVE
        + struct.pack('<H', flags2 | SMB1_FLAGS2_UNICODE)
        + struct.pack('<H', 0)                    # PIDHigh
        + b'\x00' * 8                             # SecurityFeatures
        + struct.pack('<H', 0)                    # Reserved
        + struct.pack('<H', tid)
        + struct.pack('<H', 0)                    # PIDLow
        + struct.pack('<H', uid)
        + struct.pack('<H', mid)
    )

# ---------------------------------------------------------------------------
# Dedup (copied from old smb_honeypot.py)
# ---------------------------------------------------------------------------

def should_emit(ip, user, domain, host, version, share=None):
    now = time.time()
    key = (ip or '', user or '', domain or '', host or '', version or '', share or '')
    with _dedup_lock:
        cutoff = now - EMIT_DEDUP_WINDOW_SEC
        stale  = [k for k, ts in _dedup_seen.items() if ts < cutoff]
        for k in stale:
            _dedup_seen.pop(k, None)
        if key in _dedup_seen:
            return False
        _dedup_seen[key] = now
        return True

# ---------------------------------------------------------------------------
# Knock emission + trace
# ---------------------------------------------------------------------------

def trace(client_ip, stage, **fields):
    if not TRACE_ENABLED:
        return
    if TRACE_IP and client_ip != TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    print(f'SMBTRACE ip={client_ip} stage={stage} {suffix}'.rstrip(), flush=True)


def _emit_knock(ip, user=None, smb_share=None, smb_version=None,
                smb_domain=None, smb_host=None,
                smb_file=None, smb_action=None, trace_stage='knock'):
    knock = {'type': 'KNOCK', 'proto': 'SMB', 'ip': ip}
    if user:        knock['user']        = user.lower()
    if smb_share:   knock['smb_share']   = smb_share
    if smb_file:    knock['smb_file']    = smb_file
    if smb_action:  knock['smb_action']  = smb_action
    if smb_version: knock['smb_version'] = smb_version
    if smb_domain:  knock['smb_domain']  = smb_domain
    if smb_host:    knock['smb_host']    = smb_host
    print(json.dumps(knock), flush=True)
    trace(ip, trace_stage, user=user, smb_share=smb_share, smb_file=smb_file,
          smb_version=smb_version, domain=smb_domain, host=smb_host)

# ---------------------------------------------------------------------------
# SMB2 packet builders
# ---------------------------------------------------------------------------

def _smb2_negotiate_dialects(payload):
    """
    Parse the dialect list from an SMB2 NEGOTIATE request body (starts at offset 64).
    Returns (dialects, smb_version_str, selected_dialect).
    Caps at 0x0300: SMB 3.1.1 (0x0311) requires NegotiateContexts we don't implement.
    """
    body = payload[64:]
    try:
        dialect_count = struct.unpack_from('<H', body, 2)[0]
        # Dialect list starts at offset 36 within the body (after 36-byte fixed fields)
        if dialect_count == 0 or 36 + dialect_count * 2 > len(body):
            return [], 'SMB2', 0x0210
        dialects = [struct.unpack_from('<H', body, 36 + i * 2)[0] for i in range(dialect_count)]
    except Exception:
        return [], 'SMB2', 0x0210

    if any(d in {0x0300, 0x0302, 0x0311} for d in dialects):
        return dialects, 'SMB3', 0x0300
    return dialects, 'SMB2', 0x0210


def build_smb2_negotiate_response(hdr, smb_version, selected_dialect):
    """
    Build an SMB2/3 NEGOTIATE response.
    Security buffer = SPNEGO NegTokenInit advertising NTLMSSP.
    SecurityBufferOffset = 64 (header) + 64 (fixed body) = 128.
    """
    filetime = int((time.time() + 11644473600) * 10_000_000)
    sec_buf = _SPNEGO_NEGTOKENINIT
    sec_buf_offset = 128   # 64-byte header + 64-byte fixed response body

    body = (
        struct.pack('<H',  65)               # StructureSize (spec-mandated value)
        + struct.pack('<H', 0x0001)          # SecurityMode: NEGOTIATE_SIGNING_ENABLED
        + struct.pack('<H', selected_dialect)
        + struct.pack('<H', 0)               # Reserved / NegotiateContextCount
        + os.urandom(16)                     # ServerGuid
        + struct.pack('<I', 0x7F)            # Capabilities (DFS|LEASING|LARGE_MTU|...)
        + struct.pack('<I', 0x00100000)      # MaxTransactSize (1 MB)
        + struct.pack('<I', 0x00100000)      # MaxReadSize
        + struct.pack('<I', 0x00100000)      # MaxWriteSize
        + struct.pack('<Q', filetime)        # SystemTime (Windows FILETIME)
        + struct.pack('<Q', 0)               # ServerStartTime
        + struct.pack('<H', sec_buf_offset)
        + struct.pack('<H', len(sec_buf))
        + struct.pack('<I', 0)               # Reserved2 / NegotiateContextOffset
        + sec_buf
    )
    return build_smb2_response_header(SMB2_NEGOTIATE, STATUS_SUCCESS, hdr['message_id']) + body


def _smb2_session_setup_secbuf(payload):
    """
    Extract the raw security buffer bytes from an SMB2 SESSION_SETUP request.
    SecurityBufferOffset is from the start of the SMB2 header (= start of payload).
    """
    body_offset = 64
    if len(payload) < body_offset + 16:
        return b''
    sec_buf_offset = struct.unpack_from('<H', payload, body_offset + 12)[0]
    sec_buf_length = struct.unpack_from('<H', payload, body_offset + 14)[0]
    if not sec_buf_offset or not sec_buf_length:
        return b''
    end = sec_buf_offset + sec_buf_length
    return payload[sec_buf_offset:end] if end <= len(payload) else b''


def _build_smb2_session_setup_response(hdr, status, sec_buf, session_id=0):
    """
    Build an SMB2 SESSION_SETUP response.
    SecurityBufferOffset = 64 (header) + 8 (fixed body) = 72.
    """
    body = (
        struct.pack('<H', 9)               # StructureSize
        + struct.pack('<H', 0)             # SessionFlags
        + struct.pack('<H', 72)            # SecurityBufferOffset
        + struct.pack('<H', len(sec_buf))
        + sec_buf
    )
    return build_smb2_response_header(
        SMB2_SESSION_SETUP, status, hdr['message_id'], session_id=session_id
    ) + body


def build_smb2_session_setup_r1_response(hdr):
    """Round 1: NTLM Type 1 received → send Type 2 challenge (STATUS_MORE_PROCESSING)."""
    return _build_smb2_session_setup_response(
        hdr, STATUS_MORE_PROCESSING,
        build_spnego_challenge(build_ntlm_challenge()),
    )


def build_smb2_session_setup_r2_response(hdr, session_id):
    """Round 2: NTLM Type 3 received → send accept-complete (STATUS_SUCCESS)."""
    return _build_smb2_session_setup_response(
        hdr, STATUS_SUCCESS, _SPNEGO_ACCEPT_COMPLETE, session_id=session_id,
    )


def _extract_share_smb2(payload):
    """
    Extract the share name from an SMB2 TREE_CONNECT request.
    PathOffset is from the start of the SMB2 header; path is UTF-16LE UNC (\\\\server\\share).
    """
    body_offset = 64
    if len(payload) < body_offset + 8:
        return None
    path_offset = struct.unpack_from('<H', payload, body_offset + 4)[0]
    path_length = struct.unpack_from('<H', payload, body_offset + 6)[0]
    if not path_offset or not path_length or path_offset + path_length > len(payload):
        return None
    try:
        path  = payload[path_offset:path_offset + path_length].decode('utf-16-le', errors='replace')
        parts = [p.strip() for p in path.replace('/', '\\').split('\\') if p.strip()]
        # UNC \\server\share → parts[0]=server, parts[1]=share
        return parts[1] if len(parts) >= 2 else (parts[0] if parts else None)
    except Exception:
        return None


def build_smb2_error_response(hdr, session_id, tree_id, status, command):
    """Generic SMB2 error response (StructureSize=9, ByteCount=0)."""
    body = struct.pack('<HHI', 9, 0, 0)
    return build_smb2_response_header(
        command, status, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def _smb2_filetime(t=None):
    """Convert Unix timestamp to Windows FILETIME (100-ns intervals since 1601-01-01)."""
    return int(((t or time.time()) + 11644473600) * 10_000_000)


def build_smb2_tree_connect_response_ok(hdr, session_id, tree_id, share_type):
    """
    Grant access to a share.
    share_type: 0x01=DISK, 0x02=PIPE (IPC$), 0x03=PRINT
    """
    max_access = 0x001f00a9 if share_type == 0x02 else 0x001f01ff
    body = (
        struct.pack('<H', 16)            # StructureSize
        + struct.pack('<B', share_type)  # ShareType
        + struct.pack('<B', 0)           # Reserved
        + struct.pack('<I', 0)           # ShareFlags
        + struct.pack('<I', 0)           # Capabilities
        + struct.pack('<I', max_access)  # MaximalAccess
    )
    return build_smb2_response_header(
        SMB2_TREE_CONNECT, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_create_response(hdr, session_id, tree_id, fid_p, fid_v, is_dir, file_size=0):
    """Fake CREATE success — opens root dir or a decoy file."""
    ft_old = _smb2_filetime(time.time() - 86400 * 30)   # 30 days ago
    ft_now = _smb2_filetime()
    alloc  = 0 if is_dir else ((file_size + 4095) & ~4095)
    attrs     = 0x10 if is_dir else 0x20   # DIRECTORY or NORMAL
    body = (
        struct.pack('<H', 89)            # StructureSize
        + struct.pack('<B', 0)           # OplockLevel = NONE
        + struct.pack('<B', 0)           # Flags
        + struct.pack('<I', 1)           # CreateAction = FILE_OPENED
        + struct.pack('<Q', ft_old)      # CreationTime
        + struct.pack('<Q', ft_now)      # LastAccessTime
        + struct.pack('<Q', ft_old)      # LastWriteTime
        + struct.pack('<Q', ft_old)      # ChangeTime
        + struct.pack('<Q', alloc)       # AllocationSize
        + struct.pack('<Q', file_size)   # EndOfFile
        + struct.pack('<I', attrs)       # FileAttributes
        + struct.pack('<I', 0)           # Reserved2
        + struct.pack('<QQ', fid_p, fid_v)  # FileId: persistent + volatile
        + struct.pack('<II', 0, 0)       # CreateContextsOffset + Length
    )
    return build_smb2_response_header(
        SMB2_CREATE, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_query_directory_response(hdr, session_id, tree_id, files):
    """Return a fake directory listing for the given list of (filename, size) pairs."""
    if not files:
        return build_smb2_error_response(
            hdr, session_id, tree_id, STATUS_NO_MORE_FILES, SMB2_QUERY_DIRECTORY)
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()

    # FILE_BOTH_DIRECTORY_INFORMATION entries; NextEntryOffset stitched up after.
    entries = []
    for fname, size in files:
        name  = fname.encode('utf-16-le')
        alloc = (size + 4095) & ~4095
        raw = bytearray(
            struct.pack('<I', 0)             # NextEntryOffset (filled below)
            + struct.pack('<I', 0)           # FileIndex
            + struct.pack('<Q', ft_old)      # CreationTime
            + struct.pack('<Q', ft_now)      # LastAccessTime
            + struct.pack('<Q', ft_old)      # LastWriteTime
            + struct.pack('<Q', ft_old)      # ChangeTime
            + struct.pack('<Q', size)        # EndOfFile
            + struct.pack('<Q', alloc)       # AllocationSize
            + struct.pack('<I', 0x20)        # FileAttributes = NORMAL
            + struct.pack('<I', len(name))   # FileNameLength
            + struct.pack('<I', 0)           # EaSize
            + struct.pack('<B', 0)           # ShortNameLength
            + struct.pack('<B', 0)           # Reserved1
            + b'\x00' * 24                   # ShortName[24]
            + name
        )
        if len(raw) % 8:
            raw += b'\x00' * (8 - len(raw) % 8)
        entries.append(raw)

    # Wire up NextEntryOffset: each points to the next entry; last stays 0.
    for i in range(len(entries) - 1):
        struct.pack_into('<I', entries[i], 0, len(entries[i]))

    buf = b''.join(entries)
    buf_offset = 72   # 64 header + 8 fixed response body
    body = (
        struct.pack('<H', 9)
        + struct.pack('<H', buf_offset)
        + struct.pack('<I', len(buf))
        + buf
    )
    return build_smb2_response_header(
        SMB2_QUERY_DIRECTORY, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_query_info_response(hdr, session_id, tree_id, info_type, file_info_class,
                                   is_dir, file_size=0, share_label=''):
    """Return file/filesystem attributes for a decoy share/file. Falls back to NOT_SUPPORTED."""
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()
    size   = 0 if is_dir else file_size
    alloc  = 0 if is_dir else ((size + 4095) & ~4095)
    attrs  = 0x10 if is_dir else 0x20

    output = None
    if info_type == 1:    # SMB2_0_INFO_FILE
        if file_info_class == 4:    # FileBasicInformation
            output = (struct.pack('<Q', ft_old) + struct.pack('<Q', ft_now)
                      + struct.pack('<Q', ft_old) + struct.pack('<Q', ft_old)
                      + struct.pack('<I', attrs) + struct.pack('<I', 0))
        elif file_info_class == 5:  # FileStandardInformation
            output = (struct.pack('<Q', alloc) + struct.pack('<Q', size)
                      + struct.pack('<I', 1)                       # NumberOfLinks
                      + struct.pack('<BB', 0, 1 if is_dir else 0)  # DeletePending, Directory
                      + struct.pack('<H', 0))                      # Reserved
        elif file_info_class == 6:  # FileInternalInformation
            output = struct.pack('<Q', 0xBADC0FFEE0DDF00D)
        elif file_info_class == 8:  # FileEaInformation
            output = struct.pack('<I', 0)
        elif file_info_class == 9:  # FileAccessInformation
            output = struct.pack('<I', 0x001f01ff)
        elif file_info_class in (14, 55):  # FilePositionInformation
            output = struct.pack('<Q', 0)
        elif file_info_class == 16:  # FileModeInformation
            output = struct.pack('<I', 0)
        elif file_info_class == 22:  # FileAlignmentInformation
            output = struct.pack('<I', 0)
    elif info_type == 2:  # SMB2_0_INFO_FILESYSTEM
        if file_info_class == 1:    # FileFsVolumeInformation
            label = (share_label or 'SHARE').encode('utf-16-le')
            output = (struct.pack('<Q', ft_old)
                      + struct.pack('<I', 0xCAFEBABE)   # VolumeSerialNumber
                      + struct.pack('<I', len(label))
                      + struct.pack('<BB', 0, 0)          # SupportsObjects, Reserved
                      + label)
        elif file_info_class == 3:  # FileFsSizeInformation
            output = (struct.pack('<Q', 0x40000)    # TotalAllocationUnits
                      + struct.pack('<Q', 0x20000)  # AvailableAllocationUnits
                      + struct.pack('<I', 8)        # SectorsPerAllocationUnit
                      + struct.pack('<I', 512))     # BytesPerSector
        elif file_info_class == 5:  # FileFsAttributeInformation
            fsname = b'N\x00T\x00F\x00S\x00'
            output = (struct.pack('<I', 0x00030006)
                      + struct.pack('<i', 255)
                      + struct.pack('<I', len(fsname)) + fsname)

    if output is None:
        return build_smb2_error_response(
            hdr, session_id, tree_id, STATUS_NOT_SUPPORTED, SMB2_QUERY_INFO)

    buf_offset = 72   # 64 header + 8 fixed body
    body = (
        struct.pack('<H', 9)
        + struct.pack('<H', buf_offset)
        + struct.pack('<I', len(output))
        + output
    )
    return build_smb2_response_header(
        SMB2_QUERY_INFO, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_read_response(hdr, session_id, tree_id, data):
    """Return a chunk of fake file content."""
    # DataOffset = 64 (header) + 16 (fixed body) = 80
    body = (
        struct.pack('<H', 17)            # StructureSize
        + struct.pack('<B', 80)          # DataOffset
        + struct.pack('<B', 0)           # Reserved
        + struct.pack('<I', len(data))   # DataLength
        + struct.pack('<I', 0)           # DataRemaining
        + struct.pack('<I', 0)           # Reserved2
        + data
    )
    return build_smb2_response_header(
        SMB2_READ, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_close_response(hdr, session_id, tree_id):
    """Acknowledge a CLOSE request."""
    ft = _smb2_filetime()
    body = (
        struct.pack('<H', 60)            # StructureSize
        + struct.pack('<H', 0)           # Flags
        + struct.pack('<I', 0)           # Reserved
        + struct.pack('<Q', ft)          # CreationTime
        + struct.pack('<Q', ft)          # LastAccessTime
        + struct.pack('<Q', ft)          # LastWriteTime
        + struct.pack('<Q', ft)          # ChangeTime
        + struct.pack('<Q', 0)           # AllocationSize
        + struct.pack('<Q', 0)           # EndOfFile
        + struct.pack('<I', 0)           # FileAttributes
    )
    return build_smb2_response_header(
        SMB2_CLOSE, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


# ---------------------------------------------------------------------------
# DCERPC / SRVSVC helpers — NetrShareEnum over \\PIPE\\srvsvc on IPC$
# ---------------------------------------------------------------------------

_DCERPC_BIND            = 0x0B
_DCERPC_BIND_ACK        = 0x0C
_DCERPC_REQUEST         = 0x00
_DCERPC_RESPONSE        = 0x02
_SRVSVC_NETR_SHARE_ENUM = 15         # opnum for NetrShareEnum
_FSCTL_PIPE_TRANSCEIVE  = 0x0011C017 # SMB2 IOCTL code for named-pipe transact

# NDR transfer syntax: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2 (little-endian)
_NDR_TRANSFER_SYNTAX = (
    b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11'
    b'\x9f\xe8\x08\x00\x2b\x10\x48\x60'
    + struct.pack('<I', 2)
)


def _dcerpc_hdr(pdu_type, call_id, body_len, flags=0x03):
    """16-byte DCERPC PDU header (PFC_FIRST_FRAG|PFC_LAST_FRAG by default)."""
    frag_len = 16 + body_len
    return (
        bytes([5, 0, pdu_type, flags])  # version=5, minor=0
        + b'\x10\x00\x00\x00'          # little-endian data representation
        + struct.pack('<HHI', frag_len, 0, call_id)
    )


def _dcerpc_bind_ack(call_id, ctx_id=0):
    """DCERPC BIND_ACK accepting the SRVSVC interface with NDR transfer syntax."""
    sec_addr_str = b'\\PIPE\\srvsvc\x00'  # 13 bytes (null-terminated ASCII path)
    body_pre = (
        struct.pack('<HHI', 4280, 4280, 1)       # max_xmit, max_recv, assoc_group_id
        + struct.pack('<H', len(sec_addr_str))    # sec_addr length
        + sec_addr_str
    )
    pad_len = (4 - len(body_pre) % 4) % 4        # align to 4-byte boundary
    results = (
        struct.pack('<H', 1)                      # num_results
        + struct.pack('<H', 0)                    # pad
        + struct.pack('<HH', 0, 0)                # result=accept, reason=none
        + _NDR_TRANSFER_SYNTAX                    # 20 bytes
    )
    body = body_pre + b'\x00' * pad_len + results
    return _dcerpc_hdr(_DCERPC_BIND_ACK, call_id, len(body)) + body


def _ndr_wstring(s):
    """NDR conformant varying Unicode string: max_count+offset+actual_count+data+pad."""
    encoded    = (s + '\x00').encode('utf-16-le')
    char_count = len(s) + 1
    hdr        = struct.pack('<III', char_count, 0, char_count)
    pad_len    = (4 - len(encoded) % 4) % 4
    return hdr + encoded + b'\x00' * pad_len


def _srvsvc_netr_share_enum_response(call_id, ctx_id, shares):
    """
    Build DCERPC response for NetrShareEnum level 1.
    shares: list of (name: str, share_type: int, remark: str)
    Encodes as NDR SHARE_INFO_1_CONTAINER with deferred string referents.
    """
    n   = len(shares)
    ref = 0x00020000  # base referent ID for unique pointers

    def next_ref():
        nonlocal ref; r = ref; ref += 4; return r

    container_ref = next_ref()
    array_ref     = next_ref()
    name_refs     = [next_ref() for _ in shares]
    remark_refs   = [next_ref() for _ in shares]

    stub = b''
    # InfoStruct: Level(4) + switch_value(4) + container_ptr(4)
    stub += struct.pack('<III', 1, 1, container_ref)
    # SHARE_INFO_1_CONTAINER: Count(4) + Buffer_ptr(4)
    stub += struct.pack('<II', n, array_ref)
    # Conformant array max_count
    stub += struct.pack('<I', n)
    # Array elements: [netname_ptr(4) + type(4) + remark_ptr(4)] × n
    for i, (name, stype, remark) in enumerate(shares):
        stub += struct.pack('<III', name_refs[i], stype, remark_refs[i])
    # Deferred string data in declaration order: name[0], remark[0], name[1], remark[1], ...
    for name, _, remark in shares:
        stub += _ndr_wstring(name)
        stub += _ndr_wstring(remark)
    # TotalEntries(4) + ResumeHandle null ptr(4) + ReturnCode(4)=ERROR_SUCCESS
    stub += struct.pack('<III', n, 0, 0)

    dcerpc_body = (
        struct.pack('<I', len(stub))       # alloc_hint
        + struct.pack('<HH', ctx_id, 0)    # p_cont_id, cancel_count/reserved
        + stub
    )
    return _dcerpc_hdr(_DCERPC_RESPONSE, call_id, len(dcerpc_body)) + dcerpc_body


def _parse_netr_share_enum_level(stub):
    """Extract the requested info level from a NetrShareEnum stub (best-effort)."""
    if len(stub) < 8:
        return 1
    server_name_ptr = struct.unpack_from('<I', stub, 0)[0]
    off = 4
    if server_name_ptr != 0:
        # Skip NDR conformant varying string for ServerName
        if off + 12 > len(stub):
            return 1
        actual_count = struct.unpack_from('<I', stub, off + 8)[0]
        off += 12 + actual_count * 2
        off = (off + 3) & ~3   # 4-byte align
    if off + 4 > len(stub):
        return 1
    return struct.unpack_from('<I', stub, off)[0]


def _handle_dcerpc(data, client_ip):
    """
    Parse an incoming DCERPC PDU and return the response bytes, or None if unhandled.
    BIND → BIND_ACK.  REQUEST opnum 15 (NetrShareEnum) level 1 → share list response.
    Other opnums and levels are traced and return None (caller sends NOT_SUPPORTED).
    """
    if len(data) < 16:
        return None
    pdu_type = data[2]
    call_id  = struct.unpack_from('<I', data, 12)[0]

    if pdu_type == _DCERPC_BIND:
        ctx_id = struct.unpack_from('<H', data, 28)[0] if len(data) >= 30 else 0
        trace(client_ip, 'srvsvc_bind', call_id=call_id, ctx_id=ctx_id)
        return _dcerpc_bind_ack(call_id, ctx_id)

    if pdu_type == _DCERPC_REQUEST:
        if len(data) < 24:
            return None
        ctx_id = struct.unpack_from('<H', data, 20)[0]
        opnum  = struct.unpack_from('<H', data, 22)[0]
        stub   = data[24:]
        if opnum == _SRVSVC_NETR_SHARE_ENUM:
            level = _parse_netr_share_enum_level(stub)
            trace(client_ip, 'srvsvc_netr_share_enum', call_id=call_id, level=level)
            if level == 1:
                shares = [(name, 0, '') for name in _DECOYS]
                return _srvsvc_netr_share_enum_response(call_id, ctx_id, shares)
            trace(client_ip, 'srvsvc_unsupported_level', opnum=opnum, level=level)
            return None
        trace(client_ip, 'srvsvc_unsupported_opnum', opnum=opnum)
        return None

    return None


def build_smb2_ioctl_pipe_response(hdr, session_id, tree_id, ctl_code, fid_pair, output_data):
    """SMB2 IOCTL success response for FSCTL_PIPE_TRANSCEIVE."""
    fid_p, fid_v = fid_pair
    buf_offset   = 64 + 48   # SMB2 header(64) + fixed IOCTL response body(48) = 112
    body = (
        struct.pack('<H', 49)             # StructureSize
        + struct.pack('<H', 0)            # Reserved
        + struct.pack('<I', ctl_code)     # CtlCode
        + struct.pack('<QQ', fid_p, fid_v)   # FileId
        + struct.pack('<I', buf_offset)   # InputOffset
        + struct.pack('<I', 0)            # InputCount
        + struct.pack('<I', buf_offset)   # OutputOffset
        + struct.pack('<I', len(output_data))  # OutputCount
        + struct.pack('<I', 0)            # Flags
        + struct.pack('<I', 0)            # Reserved2
        + output_data
    )
    return build_smb2_response_header(
        SMB2_IOCTL, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


# ---------------------------------------------------------------------------
# SMB2 request parsing helpers (fake-share commands)
# ---------------------------------------------------------------------------

def _extract_name_smb2_create(payload):
    """Extract the file/path name from an SMB2 CREATE request body (starts at offset 64)."""
    # NameOffset at body+44, NameLength at body+46
    if len(payload) < 64 + 48:
        return ''
    name_offset = struct.unpack_from('<H', payload, 64 + 44)[0]
    name_length = struct.unpack_from('<H', payload, 64 + 46)[0]
    if not name_length or name_offset + name_length > len(payload):
        return ''
    return payload[name_offset: name_offset + name_length].decode('utf-16-le', errors='replace')


def _parse_file_id_at(payload, abs_offset):
    """Parse a 16-byte FileId (persistent, volatile) at abs_offset in the packet."""
    if len(payload) < abs_offset + 16:
        return (0, 0)
    p = struct.unpack_from('<Q', payload, abs_offset)[0]
    v = struct.unpack_from('<Q', payload, abs_offset + 8)[0]
    return (p, v)


def _parse_read_params(payload):
    """
    Parse Length, Offset, FileId from an SMB2 READ request.
    Body layout (from offset 64): StructureSize(2)+Padding(1)+Reserved(1)+
      Length(4)@68 + Offset(8)@72 + FileId(16)@80
    """
    if len(payload) < 96:
        return 0, 65536, (0, 0)
    length = struct.unpack_from('<I', payload, 68)[0]
    offset = struct.unpack_from('<Q', payload, 72)[0]
    fid    = _parse_file_id_at(payload, 80)
    return int(offset), min(length, 65536), fid


def _parse_query_info_params(payload):
    """
    Parse InfoType, FileInfoClass, FileId from an SMB2 QUERY_INFO request.
    Body layout: StructureSize(2)+InfoType(1)@66+FileInfoClass(1)@67+...+FileId(16)@88
    """
    if len(payload) < 104:
        return 1, 0, (0, 0)
    info_type       = payload[66]
    file_info_class = payload[67]
    fid             = _parse_file_id_at(payload, 88)
    return info_type, file_info_class, fid


# ---------------------------------------------------------------------------
# SMB2/3 session state machine
# ---------------------------------------------------------------------------

def _smb2_post_negotiate(client_sock, client_ip, smb_version):
    """
    SMB2 session loop after NEGOTIATE response has already been sent.
    Handles SESSION_SETUP × 2 → TREE_CONNECT(s) → fake PUBLIC share → close.
    Factored out so the SMB1→SMB2 upgrade path can reuse it.

    IPC$ (and any other share) gets STATUS_ACCESS_DENIED but keeps the connection
    alive so the client can try the PUBLIC share next.
    PUBLIC is granted: the client then sees a directory containing _FAKE_FILENAME.
    Knocks are emitted on:
      1. Successful auth (SESSION_SETUP round 2, always)
      2. TREE_CONNECT to any share (dedup-gated)
      3. READ on _FAKE_FILENAME (always — high-value event)
    """
    session_id   = 0
    user         = None
    domain       = None
    host         = None
    setup_round  = 0
    decoy_trees  = {}    # {tree_id: share_name_upper} for decoy shares
    ipc_tree_ids = set() # TreeIds for IPC$ or other non-decoy shares
    # open_files: {(persistent, volatile): {'share': str, 'filename': str|None, 'listed': bool}}
    open_files   = {}
    # pipe_fids: {(persistent, volatile): {'pending': bytes|None}} for \\PIPE\\srvsvc handles
    pipe_fids    = {}
    next_fid     = 1     # monotonic counter for allocating unique FileId values

    for _ in range(_MAX_MSG - 1):
        try:
            payload = recv_nbss(client_sock)
        except Exception as e:
            trace(client_ip, 'smb2_recv_error', error=f'{type(e).__name__}: {e}')
            return
        hdr = parse_smb2_header(payload)
        if not hdr:
            trace(client_ip, 'smb2_bad_header')
            break

        cmd = hdr['command']

        # ── SESSION_SETUP ────────────────────────────────────────────────────
        if cmd == SMB2_SESSION_SETUP:
            setup_round += 1
            sec_buf = _smb2_session_setup_secbuf(payload)

            if setup_round == 1:
                trace(client_ip, 'smb2_session_setup_r1',
                      has_ntlm=find_ntlmssp(sec_buf) is not None, sec_buf_len=len(sec_buf))
                send_nbss(client_sock, build_smb2_session_setup_r1_response(hdr))

            elif setup_round == 2:
                ntlm3 = find_ntlmssp(sec_buf)
                if ntlm3:
                    user, domain, host = parse_ntlm_authenticate(ntlm3)
                trace(client_ip, 'smb2_session_setup_r2',
                      user=user, domain=domain, host=host, has_ntlm=ntlm3 is not None)

                if user:
                    _emit_knock(client_ip, user, None, smb_version, domain, host,
                                trace_stage='knock_emitted_auth')
                else:
                    trace(client_ip, 'smb2_session_anon')

                session_id = int.from_bytes(os.urandom(8), 'little') & 0x7FFFFFFFFFFFFFFF
                send_nbss(client_sock, build_smb2_session_setup_r2_response(hdr, session_id))

            else:
                trace(client_ip, 'smb2_extra_session_setup', round=setup_round)
                break

        # ── TREE_CONNECT ─────────────────────────────────────────────────────
        elif cmd == SMB2_TREE_CONNECT:
            share = _extract_share_smb2(payload)
            new_tree_id = (int.from_bytes(os.urandom(4), 'little') & 0x7FFFFFFF) or 1
            share_upper = (share or '').upper()
            if share_upper in _DECOYS:
                # Grant full access to the decoy share (DISK type)
                decoy_trees[new_tree_id] = share_upper
                trace(client_ip, 'smb2_tree_connect', share=share,
                      tid=hex(new_tree_id), type='decoy')
                if user:
                    if should_emit(client_ip, user, domain, host, smb_version, share):
                        _emit_knock(client_ip, user, share, smb_version, domain, host,
                                    trace_stage='knock_emitted_tree')
                    else:
                        trace(client_ip, 'knock_dedup', user=user, share=share,
                              smb_version=smb_version)
                send_nbss(client_sock, build_smb2_tree_connect_response_ok(
                    hdr, session_id, new_tree_id, 0x01))   # DISK
            else:
                # IPC$ or unknown: grant access but stub all requests with NOT_SUPPORTED.
                # Granting (rather than denying) lets clients proceed past IPC$ and try
                # connecting to a decoy share.
                ipc_tree_ids.add(new_tree_id)
                tree_type = 'ipc' if share_upper == 'IPC$' else 'unknown'
                trace(client_ip, 'smb2_tree_connect', share=share,
                      tid=hex(new_tree_id), type=tree_type)
                if user:
                    if should_emit(client_ip, user, domain, host, smb_version, share):
                        _emit_knock(client_ip, user, share, smb_version, domain, host,
                                    trace_stage='knock_emitted_tree')
                    else:
                        trace(client_ip, 'knock_dedup', user=user, share=share,
                              smb_version=smb_version)
                share_type = 0x02 if share_upper == 'IPC$' else 0x01
                send_nbss(client_sock, build_smb2_tree_connect_response_ok(
                    hdr, session_id, new_tree_id, share_type))

        # ── CREATE ── before IPC$ catch-all so \\PIPE\\srvsvc opens work ───────
        elif cmd == SMB2_CREATE:
            tree_id = hdr['tree_id']
            name    = _extract_name_smb2_create(payload)
            clean   = (name or '').lstrip('\\').strip()
            if tree_id in ipc_tree_ids:
                # Only service the srvsvc named pipe; reject everything else on IPC$
                pipe_name = clean.split('\\')[-1].upper()
                if pipe_name == 'SRVSVC':
                    fid_p = fid_v = next_fid; next_fid += 1
                    pipe_fids[(fid_p, fid_v)] = {'pending': None}
                    trace(client_ip, 'srvsvc_pipe_open', fid=fid_p)
                    send_nbss(client_sock, build_smb2_create_response(
                        hdr, session_id, tree_id, fid_p, fid_v, False))
                else:
                    trace(client_ip, 'smb2_ipc_create_unknown', name=clean)
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_OBJECT_NAME_NOT_FOUND, SMB2_CREATE))
                continue
            share_upper = decoy_trees.get(tree_id)
            if share_upper is None:
                trace(client_ip, 'smb2_create_denied', tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_CREATE))
                continue
            share_files = _DECOYS[share_upper]
            if not clean:
                # Root directory open
                fid_p = fid_v = next_fid; next_fid += 1
                open_files[(fid_p, fid_v)] = {'share': share_upper, 'filename': None, 'listed': False}
                trace(client_ip, 'smb2_create', name='', fid=fid_p, is_dir=True)
                send_nbss(client_sock, build_smb2_create_response(
                    hdr, session_id, tree_id, fid_p, fid_v, True))
            else:
                # Case-insensitive filename lookup
                match = next((fn for fn in share_files if fn.lower() == clean.lower()), None)
                if match:
                    fid_p = fid_v = next_fid; next_fid += 1
                    open_files[(fid_p, fid_v)] = {'share': share_upper, 'filename': match, 'listed': False}
                    trace(client_ip, 'smb2_create', name=clean, fid=fid_p, is_dir=False)
                    send_nbss(client_sock, build_smb2_create_response(
                        hdr, session_id, tree_id, fid_p, fid_v, False,
                        file_size=len(share_files[match])))
                else:
                    # CreateDisposition at body+36 = payload[100]
                    disposition = (struct.unpack_from('<I', payload, 100)[0]
                                   if len(payload) >= 104 else _SMB2_CREATE_DISP_FILE_OPEN)
                    if disposition != _SMB2_CREATE_DISP_FILE_OPEN:
                        # Bot is trying to create/overwrite a new file (ransomware, dropper, etc.)
                        trace(client_ip, 'smb2_create', name=clean, result='write_denied')
                        _emit_knock(client_ip, user, share_upper, smb_version, domain, host,
                                    smb_file=clean, smb_action='CREATE',
                                    trace_stage='knock_emitted_create')
                        send_nbss(client_sock, build_smb2_error_response(
                            hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_CREATE))
                    else:
                        trace(client_ip, 'smb2_create', name=clean, result='not_found')
                        send_nbss(client_sock, build_smb2_error_response(
                            hdr, session_id, tree_id, STATUS_OBJECT_NAME_NOT_FOUND, SMB2_CREATE))

        # ── IOCTL ── before IPC$ catch-all so FSCTL_PIPE_TRANSCEIVE works ─────
        elif cmd == SMB2_IOCTL:
            ctl_code = struct.unpack_from('<I', payload, 68)[0] if len(payload) >= 72 else 0
            fid_pair = _parse_file_id_at(payload, 72)   # FileId at body+8 = abs 72
            if ctl_code == _FSCTL_PIPE_TRANSCEIVE and fid_pair in pipe_fids:
                in_off  = struct.unpack_from('<I', payload, 88)[0] if len(payload) >= 92 else 0
                in_cnt  = struct.unpack_from('<I', payload, 92)[0] if len(payload) >= 96 else 0
                dcerpc  = payload[in_off:in_off + in_cnt]
                trace(client_ip, 'smb2_pipe_transceive',
                      fid=fid_pair[0], data_len=len(dcerpc))
                rpc_resp = _handle_dcerpc(dcerpc, client_ip)
                if rpc_resp:
                    send_nbss(client_sock, build_smb2_ioctl_pipe_response(
                        hdr, session_id, hdr['tree_id'], ctl_code, fid_pair, rpc_resp))
                else:
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))
            else:
                trace(client_ip, 'smb2_ioctl',
                      ctl_code=hex(ctl_code), tree_id=hex(hdr['tree_id']))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))

        # ── Stub: remaining commands on IPC$ or other non-decoy trees ────────
        elif hdr['tree_id'] in ipc_tree_ids:
            trace(client_ip, 'smb2_ipc_stub', cmd=hex(cmd), tree_id=hex(hdr['tree_id']))
            send_nbss(client_sock, build_smb2_error_response(
                hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, cmd))

        # ── Commands on decoy trees ───────────────────────────────────────────

        elif cmd == SMB2_QUERY_DIRECTORY:
            tree_id     = hdr['tree_id']
            share_upper = decoy_trees.get(tree_id)
            if share_upper is None:
                trace(client_ip, 'smb2_query_dir_denied', tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_QUERY_DIRECTORY))
                continue
            flags    = payload[65] if len(payload) > 65 else 0
            fid_pair = _parse_file_id_at(payload, 72)   # FileId at body+8 = abs 72
            fh       = open_files.get(fid_pair)
            restart  = bool(flags & 0x12)               # REOPEN(0x10) or RESTART_SCANS(0x02)
            if restart and fh:
                fh['listed'] = False
            dir_listed = fh['listed'] if fh else False
            trace(client_ip, 'smb2_query_dir', listed=dir_listed, flags=hex(flags))
            if dir_listed:
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_NO_MORE_FILES, SMB2_QUERY_DIRECTORY))
            else:
                if fh:
                    fh['listed'] = True
                file_list = [(fn, len(content)) for fn, content in _DECOYS[share_upper].items()]
                trace(client_ip, 'smb2_query_dir_result',
                      files=[fn for fn, _ in file_list])
                send_nbss(client_sock, build_smb2_query_directory_response(
                    hdr, session_id, tree_id, file_list))

        elif cmd == SMB2_QUERY_INFO:
            tree_id     = hdr['tree_id']
            share_upper = decoy_trees.get(tree_id)
            if share_upper is None:
                trace(client_ip, 'smb2_query_info_denied', tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_QUERY_INFO))
                continue
            info_type, file_info_class, fid_pair = _parse_query_info_params(payload)
            fh       = open_files.get(fid_pair)
            is_dir   = fh is None or fh['filename'] is None
            fsize    = 0 if is_dir else len(_DECOYS[fh['share']].get(fh['filename'], b''))
            trace(client_ip, 'smb2_query_info',
                  info_type=info_type, file_info_class=file_info_class,
                  is_dir=is_dir, file=None if is_dir else fh['filename'])
            send_nbss(client_sock, build_smb2_query_info_response(
                hdr, session_id, tree_id, info_type, file_info_class, is_dir,
                file_size=fsize, share_label=share_upper))

        elif cmd == SMB2_READ:
            tree_id     = hdr['tree_id']
            share_upper = decoy_trees.get(tree_id)
            if share_upper is None:
                trace(client_ip, 'smb2_read_denied', tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_READ))
                continue
            offset, length, fid_pair = _parse_read_params(payload)
            fh     = open_files.get(fid_pair)
            is_dir = fh is None or fh['filename'] is None
            trace(client_ip, 'smb2_read', offset=offset, length=length, is_dir=is_dir)
            if is_dir:
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_READ))
            else:
                content = _DECOYS[fh['share']].get(fh['filename'], b'')
                chunk   = content[offset: offset + length]
                if not chunk:
                    trace(client_ip, 'smb2_read_eof', file=fh['filename'], offset=offset)
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_END_OF_FILE, SMB2_READ))
                else:
                    # Always emit — reading a bait file is a high-value event
                    _emit_knock(client_ip, user, fh['share'], smb_version, domain, host,
                                smb_file=fh['filename'], smb_action='READ',
                                trace_stage='knock_emitted_read')
                    trace(client_ip, 'smb2_read_ok',
                          file=fh['filename'], offset=offset, bytes_returned=len(chunk))
                    send_nbss(client_sock, build_smb2_read_response(
                        hdr, session_id, tree_id, chunk))

        elif cmd == SMB2_WRITE:
            tree_id     = hdr['tree_id']
            share_upper = decoy_trees.get(tree_id)
            # FileId at body+16 = payload[80]
            fid_pair    = _parse_file_id_at(payload, 80) if len(payload) >= 96 else (0, 0)
            fh          = open_files.get(fid_pair)
            fname       = fh['filename'] if fh else None
            write_share = share_upper or (fh['share'] if fh else None)
            trace(client_ip, 'smb2_write',
                  tree_id=hex(tree_id), fid=fid_pair[0],
                  file=fname, on_decoy=share_upper is not None)
            _emit_knock(client_ip, user, write_share, smb_version, domain, host,
                        smb_file=fname, smb_action='WRITE',
                        trace_stage='knock_emitted_write')
            send_nbss(client_sock, build_smb2_error_response(
                hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_WRITE))

        elif cmd == SMB2_CLOSE:
            fid_pair = _parse_file_id_at(payload, 72)   # CLOSE: FileId at body+8 = abs 72
            if fid_pair in pipe_fids:
                pipe_fids.pop(fid_pair)
                trace(client_ip, 'smb2_pipe_close', fid=fid_pair[0])
            else:
                closed_fh = open_files.pop(fid_pair, None)
                trace(client_ip, 'smb2_close',
                      fid=fid_pair[0], had_handle=closed_fh is not None,
                      file=closed_fh['filename'] if closed_fh else None)
            send_nbss(client_sock, build_smb2_close_response(hdr, session_id, hdr['tree_id']))

        elif cmd == SMB2_IOCTL:
            ctl_code = struct.unpack_from('<I', payload, 68)[0] if len(payload) >= 72 else 0
            trace(client_ip, 'smb2_ioctl',
                  ctl_code=hex(ctl_code), tree_id=hex(hdr['tree_id']))
            send_nbss(client_sock, build_smb2_error_response(
                hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))

        elif cmd in (SMB2_LOGOFF, SMB2_TREE_DISCONNECT):
            trace(client_ip, 'smb2_logoff_or_disconnect', cmd=hex(cmd))
            break

        else:
            trace(client_ip, 'smb2_unexpected_cmd',
                  command=hex(cmd), setup_round=setup_round)
            break


def handle_smb2(client_sock, client_ip, first_payload):
    """SMB2/3 entry: parse NEGOTIATE, send response, enter session loop."""
    hdr = parse_smb2_header(first_payload)
    if not hdr or hdr['command'] != SMB2_NEGOTIATE:
        trace(client_ip, 'smb2_bad_first_cmd',
              command=hex(hdr['command']) if hdr else None)
        return

    dialects, smb_version, selected_dialect = _smb2_negotiate_dialects(first_payload)
    trace(client_ip, 'smb2_negotiate',
          smb_version=smb_version, selected=hex(selected_dialect),
          dialects=','.join(hex(d) for d in dialects))
    send_nbss(client_sock, build_smb2_negotiate_response(hdr, smb_version, selected_dialect))
    _smb2_post_negotiate(client_sock, client_ip, smb_version)


# ---------------------------------------------------------------------------
# SMB1 packet builders
# ---------------------------------------------------------------------------

# SMB1 Capabilities flags
_SMB1_CAPS = (
    0x00000004 |   # CAP_UNICODE
    0x00000008 |   # CAP_LARGE_FILES
    0x00000010 |   # CAP_NT_SMBS
    0x00000020 |   # CAP_RPC_REMOTE_APIS
    0x00000040 |   # CAP_STATUS32
    0x00000080 |   # CAP_LEVEL_II_OPLOCKS
    0x00000100 |   # CAP_LOCK_AND_READ
    0x00000200 |   # CAP_NT_FIND
    0x00004000 |   # CAP_LARGE_READX
    0x80000000     # CAP_EXTENDED_SECURITY (required for SPNEGO path)
)


def _smb1_parse_negotiate(data):
    """
    Parse dialect strings from an SMB1 NEGOTIATE request.
    Returns (nt_lm_index, wants_smb2_upgrade).
    Dialect list begins at offset 35 (32-byte header + WordCount + ByteCount).
    """
    if len(data) < 35:
        return -1, False
    byte_count    = struct.unpack_from('<H', data, 33)[0]   # header(32) + WordCount(1)
    dialect_data  = data[35: 35 + byte_count]

    dialects: list[str] = []
    pos = 0
    while pos < len(dialect_data):
        if dialect_data[pos] != 0x02:
            break
        pos += 1
        end = dialect_data.find(b'\x00', pos)
        if end == -1:
            dialects.append(dialect_data[pos:].decode('ascii', errors='replace'))
            break
        dialects.append(dialect_data[pos:end].decode('ascii', errors='replace'))
        pos = end + 1

    wants_smb2    = any(d in ('SMB 2.002', 'SMB 2.???') for d in dialects)
    nt_lm_index   = next((i for i, d in enumerate(dialects) if d == 'NT LM 0.12'), -1)
    return nt_lm_index, wants_smb2


def build_smb1_negotiate_response(hdr, dialect_index):
    """
    Build an SMB1 NEGOTIATE response selecting NT LM 0.12 with extended security.

    Parameters (WordCount=17, 34 bytes total):
      DialectIndex(2) SecurityMode(1) MaxMpxCount(2) MaxNumberVcs(2)
      MaxBufferSize(4) MaxRawSize(4) SessionKey(4) Capabilities(4)
      SystemTime(8) ServerTimeZone(2) ChallengeLength(1)
    Then: ByteCount(2) + ServerGuid(16) + SecurityBlob(SPNEGO NegTokenInit)
    """
    filetime = int((time.time() + 11644473600) * 10_000_000)
    sec_buf  = _SPNEGO_NEGTOKENINIT

    params = (
        struct.pack('<H', dialect_index)   # DialectIndex
        + struct.pack('<B', 0x03)          # SecurityMode: USER_SECURITY | ENCRYPT_PASSWORDS
        + struct.pack('<H', 50)            # MaxMpxCount
        + struct.pack('<H', 1)             # MaxNumberVcs
        + struct.pack('<I', 0x00010000)    # MaxBufferSize (64 KB)
        + struct.pack('<I', 0x00010000)    # MaxRawSize
        + struct.pack('<I', 0)             # SessionKey
        + struct.pack('<I', _SMB1_CAPS)    # Capabilities
        + struct.pack('<Q', filetime)      # SystemTime (FILETIME)
        + struct.pack('<H', 0)             # ServerTimeZone (UTC)
        + struct.pack('<B', 0)             # ChallengeLength = 0 (extended security)
    )   # 34 bytes = 17 words ✓

    body = (
        struct.pack('<B', 17)              # WordCount
        + params
        + struct.pack('<H', 16 + len(sec_buf))   # ByteCount
        + os.urandom(16)                   # ServerGuid
        + sec_buf
    )
    flags2 = hdr['flags2'] | SMB1_FLAGS2_EXTENDED_SEC | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_NEGOTIATE, STATUS_SUCCESS, flags2, mid=hdr['mid'],
    ) + body


def _smb1_session_setup_secbuf(data):
    """
    Extract the SPNEGO security blob from an SMB1 SESSION_SETUP_ANDX request
    (extended security, WordCount=12).

    Layout after the 32-byte header:
      [32] WordCount=12  [33] AndXCmd  [34] AndXRsvd  [35-36] AndXOff
      [37-38] MaxBufSize  [39-40] MaxMpx  [41-42] VcNumber
      [43-46] SessionKey  [47-48] SecurityBlobLength
      [49-52] Reserved  [53-56] Capabilities
      [57-58] ByteCount  [59+] SecurityBlob
    """
    if len(data) < 60:
        return b''
    try:
        if data[32] != 12:          # WordCount must be 12 for extended-security path
            return b''
        sec_len = struct.unpack_from('<H', data, 47)[0]
        if not sec_len or 59 + sec_len > len(data):
            return b''
        return data[59: 59 + sec_len]
    except Exception:
        return b''


def _build_smb1_session_setup_response(hdr, status, sec_buf, uid=0):
    """
    Build an SMB1 SESSION_SETUP_ANDX response (WordCount=4).

    Parameters (4 words = 8 bytes):
      AndXCommand(1) AndXReserved(1) AndXOffset(2) Action(2) SecurityBlobLength(2)
    Then: ByteCount(2) + SecurityBlob + NativeOS + NativeLanMan
    """
    params = (
        struct.pack('<B', 0xFF)            # AndXCommand = no chaining
        + struct.pack('<B', 0)             # AndXReserved
        + struct.pack('<H', 0)             # AndXOffset
        + struct.pack('<H', 0)             # Action = 0 (not guest)
        + struct.pack('<H', len(sec_buf))  # SecurityBlobLength
    )
    # Minimal native strings (UTF-16LE null-terminated) to satisfy strict clients
    native = b'\x00\x00\x00\x00'   # NativeOS='' + NativeLanMan='' (each = one UTF-16LE NUL)
    body = (
        struct.pack('<B', 4)               # WordCount
        + params
        + struct.pack('<H', len(sec_buf) + len(native))   # ByteCount
        + sec_buf
        + native
    )
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_SESSION_SETUP, status, flags2, uid=uid, mid=hdr['mid'],
    ) + body


def build_smb1_session_setup_r1_response(hdr):
    """Round 1: NTLM Type 1 received → send Type 2 challenge (STATUS_MORE_PROCESSING)."""
    return _build_smb1_session_setup_response(
        hdr, STATUS_MORE_PROCESSING,
        build_spnego_challenge(build_ntlm_challenge()),
    )


def build_smb1_session_setup_r2_response(hdr, uid):
    """Round 2: NTLM Type 3 received → send accept-complete (STATUS_SUCCESS), assign UID."""
    return _build_smb1_session_setup_response(
        hdr, STATUS_SUCCESS, _SPNEGO_ACCEPT_COMPLETE, uid=uid,
    )


def _extract_share_smb1(data, flags2):
    """
    Extract the share name from an SMB1 TREE_CONNECT_ANDX request.

    Layout after the 32-byte header:
      [32] WordCount=4  [33] AndXCmd  [34] AndXRsvd  [35-36] AndXOff
      [37-38] Flags  [39-40] PasswordLength
      [41-42] ByteCount  [43+] Password + Path (null-terminated)

    Path is UTF-16LE if Flags2 & SMB1_FLAGS2_UNICODE, else ASCII.
    Unicode paths are aligned to a 2-byte boundary from the packet start (offset 0).
    """
    if len(data) < 43:
        return None
    try:
        password_len = struct.unpack_from('<H', data, 39)[0]
        path_start   = 43 + password_len

        if flags2 & SMB1_FLAGS2_UNICODE:
            if path_start % 2 != 0:   # align to 2-byte boundary from packet start
                path_start += 1
            end = path_start
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            path = data[path_start:end].decode('utf-16-le', errors='replace')
        else:
            nul  = data.find(b'\x00', path_start)
            path = data[path_start: nul if nul != -1 else len(data)].decode('ascii', errors='replace')

        parts = [p.strip() for p in path.replace('/', '\\').split('\\') if p.strip()]
        return parts[1] if len(parts) >= 2 else (parts[0] if parts else None)
    except Exception:
        return None


def _smb1_session_setup_nonext(data, flags2):
    """
    Parse username and domain from a non-extended-security SESSION_SETUP_ANDX
    (WordCount=10 or 13). Returns (username, domain) — either may be None.
    """
    if len(data) < 61:
        return None, None
    wc = data[32]
    if wc not in (10, 13):
        return None, None
    ci_len = struct.unpack_from('<H', data, 47)[0]   # LM response bytes
    cs_len = struct.unpack_from('<H', data, 49)[0]   # NT response bytes
    # ByteCount: at offset 32+1+wc*2 → 59 (wc=13) or 51 (wc=10)
    bc_off = 59 if wc == 13 else 51
    if len(data) < bc_off + 2:
        return None, None
    user_start = bc_off + 2 + ci_len + cs_len   # skip ByteCount + passwords
    if user_start >= len(data):
        return None, None
    if flags2 & SMB1_FLAGS2_UNICODE:
        if user_start % 2 != 0:
            user_start += 1          # align to even offset from packet start
        end = user_start
        while end + 1 < len(data) and not (data[end] == 0 and data[end + 1] == 0):
            end += 2
        username  = data[user_start:end].decode('utf-16-le', errors='replace').strip('\x00') or None
        dom_start = end + 2
        if dom_start + 1 < len(data):
            end2 = dom_start
            while end2 + 1 < len(data) and not (data[end2] == 0 and data[end2 + 1] == 0):
                end2 += 2
            domain = data[dom_start:end2].decode('utf-16-le', errors='replace').strip('\x00') or None
        else:
            domain = None
    else:
        nul      = data.find(b'\x00', user_start)
        username = data[user_start:nul if nul != -1 else len(data)].decode('latin-1', errors='replace').strip('\x00') or None
        dom_start = (nul + 1) if nul != -1 else len(data)
        nul2   = data.find(b'\x00', dom_start)
        domain = data[dom_start:nul2 if nul2 != -1 else len(data)].decode('latin-1', errors='replace').strip('\x00') or None
    return username, domain


def _build_smb1_session_setup_nonext_response(hdr, uid):
    """Non-extended-security SESSION_SETUP_ANDX success response (WordCount=3)."""
    params = (struct.pack('<B', 0xFF)   # AndXCommand = no chaining
              + struct.pack('<B', 0)    # AndXReserved
              + struct.pack('<H', 0)    # AndXOffset
              + struct.pack('<H', 0))   # Action = 0 (not guest)
    body   = struct.pack('<B', 3) + params + struct.pack('<H', 0)   # WC=3, 3×2-byte params, BC=0
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_SESSION_SETUP, STATUS_SUCCESS, flags2, uid=uid, mid=hdr['mid'],
    ) + body


def build_smb1_error_response(hdr, uid, tid, status, command):
    """Generic SMB1 error response (WordCount=0, ByteCount=0)."""
    body   = struct.pack('<B', 0) + struct.pack('<H', 0)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        command, status, flags2, uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def build_smb1_tree_connect_ok_response(hdr, new_tid, share_upper):
    """
    TREE_CONNECT_ANDX success response (WordCount=3).
    ServiceType: 'IPC' for IPC$, 'A:' for disk shares.
    """
    is_ipc    = (share_upper == 'IPC$')
    service   = b'IPC\x00' if is_ipc else b'A:\x00'
    native_fs = b'' if is_ipc else 'NTFS'.encode('utf-16-le') + b'\x00\x00'
    params = (struct.pack('<B', 0xFF)    # AndXCommand = no chaining
              + struct.pack('<B', 0)     # AndXReserved
              + struct.pack('<H', 0)     # AndXOffset
              + struct.pack('<H', 1))    # OptionalSupport = SMB_SUPPORT_SEARCH_BITS
    body   = (struct.pack('<B', 3) + params
              + struct.pack('<H', len(service) + len(native_fs))
              + service + native_fs)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_TREE_CONNECT, STATUS_SUCCESS, flags2,
        uid=hdr['uid'], tid=new_tid, mid=hdr['mid'],
    ) + body


def _smb1_parse_nt_create(data, flags2):
    """Extract filename from an NT_CREATE_ANDX request (WordCount=24)."""
    # Layout: 32(hdr)+1(WC)+48(24 words)+2(BC)=83; data at 83.
    # Offset 83 is odd → Unicode strings padded to 84.
    if len(data) < 84 or data[32] != 24:
        return ''
    name_len = struct.unpack_from('<H', data, 38)[0]
    if not name_len:
        return ''
    if flags2 & SMB1_FLAGS2_UNICODE:
        fname = data[84:84 + name_len].decode('utf-16-le', errors='replace').strip('\x00')
    else:
        fname = data[83:83 + name_len].decode('latin-1', errors='replace').strip('\x00')
    return fname.lstrip('\\').strip()


def build_smb1_nt_create_response(hdr, uid, tid, fid, is_dir, file_size):
    """NT_CREATE_ANDX success response (WordCount=34)."""
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()
    alloc  = 0 if is_dir else ((file_size + 4095) & ~4095)
    attrs  = 0x10 if is_dir else 0x20
    params = (
        struct.pack('<B',  0xFF)                    # AndXCommand = no chaining
        + struct.pack('<B',  0)                     # AndXReserved
        + struct.pack('<H',  0)                     # AndXOffset
        + struct.pack('<B',  0)                     # OplockLevel = NONE
        + struct.pack('<H',  fid)                   # FID (2 bytes)
        + struct.pack('<I',  1)                     # CreateAction = FILE_OPENED
        + struct.pack('<Q',  ft_old)                # CreationTime
        + struct.pack('<Q',  ft_now)                # LastAccessTime
        + struct.pack('<Q',  ft_old)                # LastWriteTime
        + struct.pack('<Q',  ft_old)                # ChangeTime
        + struct.pack('<I',  attrs)                 # FileAttributes
        + struct.pack('<Q',  alloc)                 # AllocationSize
        + struct.pack('<Q',  file_size)             # EndOfFile
        + struct.pack('<H',  0)                     # FileType = disk
        + struct.pack('<H',  0)                     # DeviceState
        + struct.pack('<B',  1 if is_dir else 0)    # Directory
    )   # 4+1+2+4+8+8+8+8+4+8+8+2+2+1 = 68 bytes = 34 words ✓
    body   = struct.pack('<B', 34) + params + struct.pack('<H', 0)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_NT_CREATE_ANDX, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def build_smb1_trans2_response(hdr, uid, tid, files):
    """TRANS2 FIND_FIRST2 response listing the given (filename, size) pairs."""
    if not files:
        return build_smb1_error_response(
            hdr, uid, tid, STATUS_NO_MORE_FILES, SMB1_COM_TRANSACTION2)
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()

    # FILE_BOTH_DIRECTORY_INFORMATION entries (same format as SMB2 QUERY_DIRECTORY)
    entries = []
    for fname, size in files:
        name  = fname.encode('utf-16-le')
        alloc = (size + 4095) & ~4095
        raw   = bytearray(
            struct.pack('<I', 0)              # NextEntryOffset (filled below)
            + struct.pack('<I', 0)            # FileIndex
            + struct.pack('<Q', ft_old)       # CreationTime
            + struct.pack('<Q', ft_now)       # LastAccessTime
            + struct.pack('<Q', ft_old)       # LastWriteTime
            + struct.pack('<Q', ft_old)       # ChangeTime
            + struct.pack('<Q', size)         # EndOfFile
            + struct.pack('<Q', alloc)        # AllocationSize
            + struct.pack('<I', 0x20)         # FileAttributes = NORMAL
            + struct.pack('<I', len(name))    # FileNameLength
            + struct.pack('<I', 0)            # EaSize
            + struct.pack('<B', 0)            # ShortNameLength
            + struct.pack('<B', 0)            # Reserved
            + b'\x00' * 24                    # ShortName[24]
            + name
        )
        if len(raw) % 8:
            raw += b'\x00' * (8 - len(raw) % 8)
        entries.append(raw)
    for i in range(len(entries) - 1):
        struct.pack_into('<I', entries[i], 0, len(entries[i]))
    data_buf = b''.join(entries)

    # FIND_FIRST2 response parameters (12 bytes)
    sid    = (int.from_bytes(os.urandom(2), 'little') or 1)
    params = (struct.pack('<H', sid)              # SearchHandle
              + struct.pack('<H', len(files))     # SearchCount
              + struct.pack('<H', 1)              # EndOfSearch = 1
              + struct.pack('<H', 0)              # EaErrorOffset
              + struct.pack('<I', 0))             # LastNameOffset

    # Fixed response: 32(hdr)+1(WC)+20(10 words)+2(BC) = 55 bytes.
    # One pad byte → params at offset 56, data at 56+12 = 68.
    param_off  = 56
    data_off   = param_off + len(params)   # 68
    byte_count = 1 + len(params) + len(data_buf)

    words = (
        struct.pack('<H', len(params))     # TotalParameterCount
        + struct.pack('<H', len(data_buf)) # TotalDataCount
        + struct.pack('<H', 0)             # Reserved
        + struct.pack('<H', len(params))   # ParameterCount
        + struct.pack('<H', param_off)     # ParameterOffset
        + struct.pack('<H', 0)             # ParameterDisplacement
        + struct.pack('<H', len(data_buf)) # DataCount
        + struct.pack('<H', data_off)      # DataOffset
        + struct.pack('<H', 0)             # DataDisplacement
        + struct.pack('<BB', 0, 0)         # SetupCount, Reserved
    )   # 20 bytes = 10 words ✓
    body   = (struct.pack('<B', 10) + words
              + struct.pack('<H', byte_count)
              + b'\x00'               # alignment pad
              + params + data_buf)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_TRANSACTION2, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def _smb1_parse_read_andx(data):
    """Extract (fid, offset, max_count) from a READ_ANDX request."""
    if len(data) < 55:
        return 0, 0, 65535
    wc      = data[32]
    fid     = struct.unpack_from('<H', data, 37)[0]
    off_lo  = struct.unpack_from('<I', data, 39)[0]
    max_cnt = struct.unpack_from('<H', data, 43)[0] or 65535
    if wc == 12:   # 64-bit offset variant
        off_hi = struct.unpack_from('<I', data, 53)[0]
        offset = (off_hi << 32) | off_lo
    else:
        offset = off_lo
    return fid, offset, max_cnt


def build_smb1_read_andx_response(hdr, uid, tid, chunk):
    """READ_ANDX success response (WordCount=12)."""
    # DataOffset from SMB header start: 32(hdr)+1(WC)+24(12 words)+2(BC) = 59
    data_offset = 59
    params = (
        struct.pack('<B',  0xFF)             # AndXCommand = no chaining
        + struct.pack('<B',  0)              # AndXReserved
        + struct.pack('<H',  0)              # AndXOffset
        + struct.pack('<H',  0xFFFF)         # Available (-1 = unknown)
        + struct.pack('<H',  0)              # DataCompactionMode
        + struct.pack('<H',  0)              # Reserved1
        + struct.pack('<H',  len(chunk))     # DataLength
        + struct.pack('<H',  data_offset)    # DataOffset
        + struct.pack('<I',  0)              # DataLengthHigh (4 bytes)
        + struct.pack('<HHH', 0, 0, 0)       # Reserved2
    )   # 2+2+2+2+2+2+4+6 = 24 bytes = 12 words ✓
    body   = struct.pack('<B', 12) + params + struct.pack('<H', len(chunk)) + chunk
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_READ_ANDX, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def _smb1_parse_close(data):
    """Extract FID from a COM_CLOSE request (FID at offset 33)."""
    if len(data) < 35:
        return 0
    return struct.unpack_from('<H', data, 33)[0]


def build_smb1_close_response(hdr, uid, tid):
    """COM_CLOSE success response (WordCount=0)."""
    body   = struct.pack('<B', 0) + struct.pack('<H', 0)   # WC=0, BC=0
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_CLOSE, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


# ---------------------------------------------------------------------------
# SMB1 session state machine
# ---------------------------------------------------------------------------

def handle_smb1(client_sock, client_ip, first_payload):
    """
    SMB1 flow: NEGOTIATE → SESSION_SETUP → TREE_CONNECT → decoy share ops.

    Two authentication paths:
      Extended security (Flags2 & 0x0800): NTLM 3-way via SPNEGO (2 rounds).
      Non-extended security: plain/empty password in a single SESSION_SETUP round.
        Used by older bots that skip NTLM and rely on guest or weak-password access.

    Both paths proceed to full decoy share serving:
      NT_CREATE_ANDX → TRANSACTION2 FIND_FIRST2 → READ_ANDX → COM_CLOSE.

    Clients offering 'SMB 2.002'/'SMB 2.???' are upgraded to SMB2 before auth.
    """
    hdr = parse_smb1_header(first_payload)
    if not hdr or hdr['command'] != SMB1_COM_NEGOTIATE:
        trace(client_ip, 'smb1_bad_first_cmd',
              command=hex(hdr['command']) if hdr else None)
        return

    nt_lm_index, wants_smb2 = _smb1_parse_negotiate(first_payload)

    if wants_smb2:
        trace(client_ip, 'smb1_upgrade_to_smb2')
        fake_hdr = {'message_id': 0}
        send_nbss(client_sock, build_smb2_negotiate_response(fake_hdr, 'SMB2', 0x0210))
        _smb2_post_negotiate(client_sock, client_ip, 'SMB2')
        return

    if nt_lm_index < 0:
        trace(client_ip, 'smb1_no_nt_lm_dialect')
        body = struct.pack('<B', 1) + struct.pack('<H', 0xFFFF) + struct.pack('<H', 0)
        send_nbss(client_sock,
                  build_smb1_response_header(SMB1_COM_NEGOTIATE, STATUS_SUCCESS, hdr['flags2'])
                  + body)
        return

    trace(client_ip, 'smb1_negotiate',
          dialect_index=nt_lm_index, flags2=hex(hdr['flags2']),
          extended_sec=bool(hdr['flags2'] & SMB1_FLAGS2_EXTENDED_SEC))
    send_nbss(client_sock, build_smb1_negotiate_response(hdr, nt_lm_index))

    uid          = 0
    user         = None
    domain       = None
    host         = None
    setup_round  = 0
    decoy_trees  = {}    # {tid: share_name_upper}
    ipc_tree_ids = set() # TIDs for IPC$ or other non-decoy shares
    open_files   = {}    # {fid(int): {'share': str, 'filename': str|None}}
    pipe_fids    = {}    # {fid(int): {'pending': bytes|None}} for \\PIPE\\srvsvc handles
    next_fid     = 1

    for _ in range(_MAX_MSG - 1):
        try:
            payload = recv_nbss(client_sock)
        except Exception as e:
            trace(client_ip, 'smb1_recv_error', error=f'{type(e).__name__}: {e}')
            return
        hdr = parse_smb1_header(payload)
        if not hdr:
            trace(client_ip, 'smb1_bad_header')
            break

        cmd    = hdr['command']
        flags2 = hdr['flags2']

        # ── SESSION_SETUP ────────────────────────────────────────────────────
        if cmd == SMB1_COM_SESSION_SETUP:
            setup_round += 1
            if flags2 & SMB1_FLAGS2_EXTENDED_SEC:
                # Extended path: NTLM 3-way via SPNEGO (2 rounds)
                sec_buf = _smb1_session_setup_secbuf(payload)
                if setup_round == 1:
                    trace(client_ip, 'smb1_session_setup_r1',
                          has_ntlm=find_ntlmssp(sec_buf) is not None,
                          sec_buf_len=len(sec_buf))
                    send_nbss(client_sock, build_smb1_session_setup_r1_response(hdr))
                elif setup_round == 2:
                    ntlm3 = find_ntlmssp(sec_buf)
                    if ntlm3:
                        user, domain, host = parse_ntlm_authenticate(ntlm3)
                    trace(client_ip, 'smb1_session_setup_r2',
                          user=user, domain=domain, host=host,
                          has_ntlm=ntlm3 is not None)
                    if user:
                        _emit_knock(client_ip, user, None, 'SMB1', domain, host,
                                    trace_stage='knock_emitted_auth')
                    uid = (int.from_bytes(os.urandom(2), 'little') or 1)
                    send_nbss(client_sock, build_smb1_session_setup_r2_response(hdr, uid))
                else:
                    trace(client_ip, 'smb1_extra_session_setup', round=setup_round)
                    break
            else:
                # Non-extended path: plain/empty password, single round
                user, domain = _smb1_session_setup_nonext(payload, flags2)
                trace(client_ip, 'smb1_session_setup_nonext',
                      user=user, domain=domain)
                if user:
                    _emit_knock(client_ip, user, None, 'SMB1', domain, None,
                                trace_stage='knock_emitted_auth')
                uid = (int.from_bytes(os.urandom(2), 'little') or 1)
                send_nbss(client_sock, _build_smb1_session_setup_nonext_response(hdr, uid))

        # ── TREE_CONNECT ─────────────────────────────────────────────────────
        elif cmd == SMB1_COM_TREE_CONNECT:
            share       = _extract_share_smb1(payload, flags2)
            share_upper = (share or '').upper()
            new_tid     = (int.from_bytes(os.urandom(2), 'little') or 1)
            if share_upper in _DECOYS:
                decoy_trees[new_tid] = share_upper
                trace(client_ip, 'smb1_tree_connect', share=share,
                      tid=hex(new_tid), type='decoy')
            else:
                ipc_tree_ids.add(new_tid)
                tree_type = 'ipc' if share_upper == 'IPC$' else 'unknown'
                trace(client_ip, 'smb1_tree_connect', share=share,
                      tid=hex(new_tid), type=tree_type)
            if user:
                if should_emit(client_ip, user, domain, host, 'SMB1', share):
                    _emit_knock(client_ip, user, share, 'SMB1', domain, host,
                                trace_stage='knock_emitted_tree')
                else:
                    trace(client_ip, 'knock_dedup', user=user, share=share,
                          smb_version='SMB1')
            send_nbss(client_sock, build_smb1_tree_connect_ok_response(hdr, new_tid, share_upper))

        # ── IPC$ and other non-decoy trees ───────────────────────────────────
        elif hdr['tid'] in ipc_tree_ids:
            tid = hdr['tid']
            if cmd == SMB1_COM_NT_CREATE_ANDX:
                # Open \\PIPE\\srvsvc; reject everything else on IPC$
                name      = _smb1_parse_nt_create(payload, flags2)
                pipe_name = (name or '').split('\\')[-1].upper()
                if pipe_name == 'SRVSVC':
                    fid = next_fid; next_fid += 1
                    pipe_fids[fid] = {'pending': None}
                    trace(client_ip, 'srvsvc_pipe_open', fid=fid)
                    send_nbss(client_sock, build_smb1_nt_create_response(
                        hdr, uid, tid, fid, False, 0))
                else:
                    trace(client_ip, 'smb1_ipc_create_unknown',
                          name=(name or '').split('\\')[-1])
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_OBJECT_NAME_NOT_FOUND, SMB1_COM_NT_CREATE_ANDX))
            elif cmd == SMB1_COM_WRITE_ANDX:
                # DCERPC write on pipe — process and cache response for next READ
                fid = struct.unpack_from('<H', payload, 37)[0] if len(payload) >= 39 else 0
                if fid in pipe_fids:
                    # Data offset/count at params[6]/[12]: payload[39]/[45]
                    data_off = struct.unpack_from('<H', payload, 45)[0] if len(payload) >= 47 else 0
                    data_cnt = struct.unpack_from('<H', payload, 43)[0] if len(payload) >= 45 else 0
                    dcerpc   = payload[data_off:data_off + data_cnt]
                    trace(client_ip, 'smb1_pipe_write', fid=fid, data_len=len(dcerpc))
                    pipe_fids[fid]['pending'] = _handle_dcerpc(dcerpc, client_ip)
                    # Acknowledge the write
                    ack_body = (struct.pack('<B', 6)        # WC=6
                                + struct.pack('<B', 0xFF)   # AndXCmd=none
                                + struct.pack('<B', 0)      # AndXRsvd
                                + struct.pack('<H', 0)      # AndXOff
                                + struct.pack('<H', data_cnt)  # Count
                                + struct.pack('<H', 0)      # Remaining
                                + struct.pack('<I', 0)      # CountHigh
                                + struct.pack('<H', 0))     # ByteCount
                    send_nbss(client_sock,
                              build_smb1_response_header(SMB1_COM_WRITE_ANDX, STATUS_SUCCESS,
                                                         flags2, uid=uid, tid=tid)
                              + ack_body)
                else:
                    trace(client_ip, 'smb1_ipc_stub', cmd=hex(cmd))
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_NOT_SUPPORTED, cmd))
            elif cmd == SMB1_COM_READ_ANDX:
                # Return pending DCERPC response (set by previous WRITE)
                fid = struct.unpack_from('<H', payload, 37)[0] if len(payload) >= 39 else 0
                if fid in pipe_fids and pipe_fids[fid]['pending']:
                    rpc_resp = pipe_fids[fid]['pending']
                    pipe_fids[fid]['pending'] = None
                    trace(client_ip, 'smb1_pipe_read', fid=fid, data_len=len(rpc_resp))
                    send_nbss(client_sock, build_smb1_read_andx_response(
                        hdr, uid, tid, rpc_resp))
                else:
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_END_OF_FILE, SMB1_COM_READ_ANDX))
            elif cmd == SMB1_COM_CLOSE:
                fid = _smb1_parse_close(payload)
                pipe_fids.pop(fid, None)
                trace(client_ip, 'smb1_pipe_close', fid=fid)
                send_nbss(client_sock, build_smb1_close_response(hdr, uid, tid))
            else:
                trace(client_ip, 'smb1_ipc_stub', cmd=hex(cmd))
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_SUPPORTED, cmd))

        # ── NT_CREATE_ANDX ────────────────────────────────────────────────────
        elif cmd == SMB1_COM_NT_CREATE_ANDX:
            tid         = hdr['tid']
            share_upper = decoy_trees.get(tid)
            if share_upper is None:
                trace(client_ip, 'smb1_create_denied', tid=hex(tid))
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_NT_CREATE_ANDX))
                continue
            name  = _smb1_parse_nt_create(payload, flags2)
            clean = (name or '').lstrip('\\').strip()
            share_files = _DECOYS[share_upper]
            if not clean:
                fid = next_fid; next_fid += 1
                open_files[fid] = {'share': share_upper, 'filename': None}
                trace(client_ip, 'smb1_create', name='', fid=fid, is_dir=True)
                send_nbss(client_sock, build_smb1_nt_create_response(
                    hdr, uid, tid, fid, True, 0))
            else:
                match = next((fn for fn in share_files if fn.lower() == clean.lower()), None)
                if match:
                    fid = next_fid; next_fid += 1
                    open_files[fid] = {'share': share_upper, 'filename': match}
                    trace(client_ip, 'smb1_create', name=clean, fid=fid, is_dir=False)
                    send_nbss(client_sock, build_smb1_nt_create_response(
                        hdr, uid, tid, fid, False, len(share_files[match])))
                else:
                    # CreateDisposition at params[35] = payload[68]
                    disposition = (struct.unpack_from('<I', payload, 68)[0]
                                   if len(payload) >= 72 else _SMB2_CREATE_DISP_FILE_OPEN)
                    if disposition != _SMB2_CREATE_DISP_FILE_OPEN:
                        trace(client_ip, 'smb1_create', name=clean, result='write_denied')
                        _emit_knock(client_ip, user, share_upper, 'SMB1', domain, host,
                                    smb_file=clean, smb_action='CREATE',
                                    trace_stage='knock_emitted_create')
                        send_nbss(client_sock, build_smb1_error_response(
                            hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_NT_CREATE_ANDX))
                    else:
                        trace(client_ip, 'smb1_create', name=clean, result='not_found')
                        send_nbss(client_sock, build_smb1_error_response(
                            hdr, uid, tid, STATUS_OBJECT_NAME_NOT_FOUND,
                            SMB1_COM_NT_CREATE_ANDX))

        # ── TRANSACTION2 (FIND_FIRST2) ────────────────────────────────────────
        elif cmd == SMB1_COM_TRANSACTION2:
            tid         = hdr['tid']
            share_upper = decoy_trees.get(tid)
            if share_upper is None or len(payload) < 65:
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_SUPPORTED, SMB1_COM_TRANSACTION2))
                continue
            subcommand = struct.unpack_from('<H', payload, 61)[0]
            if subcommand != _SMB1_TRANS2_FIND_FIRST2:
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_SUPPORTED, SMB1_COM_TRANSACTION2))
                continue
            file_list = [(fn, len(content)) for fn, content in _DECOYS[share_upper].items()]
            trace(client_ip, 'smb1_trans2_find_first2',
                  share=share_upper, count=len(file_list),
                  files=[fn for fn, _ in file_list])
            send_nbss(client_sock, build_smb1_trans2_response(hdr, uid, tid, file_list))

        # ── READ_ANDX ─────────────────────────────────────────────────────────
        elif cmd == SMB1_COM_READ_ANDX:
            tid         = hdr['tid']
            share_upper = decoy_trees.get(tid)
            if share_upper is None:
                trace(client_ip, 'smb1_read_denied', tid=hex(tid))
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_READ_ANDX))
                continue
            fid, offset, max_cnt = _smb1_parse_read_andx(payload)
            fh     = open_files.get(fid)
            is_dir = fh is None or fh['filename'] is None
            trace(client_ip, 'smb1_read', fid=fid, offset=offset,
                  length=max_cnt, is_dir=is_dir,
                  file=None if is_dir else fh['filename'])
            if is_dir:
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_READ_ANDX))
            else:
                content = _DECOYS[fh['share']].get(fh['filename'], b'')
                chunk   = content[offset:offset + max_cnt]
                if not chunk:
                    trace(client_ip, 'smb1_read_eof',
                          file=fh['filename'], offset=offset)
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_END_OF_FILE, SMB1_COM_READ_ANDX))
                else:
                    _emit_knock(client_ip, user, fh['share'], 'SMB1', domain, host,
                                smb_file=fh['filename'], smb_action='READ',
                                trace_stage='knock_emitted_read')
                    trace(client_ip, 'smb1_read_ok',
                          file=fh['filename'], offset=offset,
                          bytes_returned=len(chunk))
                    send_nbss(client_sock, build_smb1_read_andx_response(
                        hdr, uid, tid, chunk))

        # ── WRITE_ANDX ────────────────────────────────────────────────────────
        elif cmd == SMB1_COM_WRITE_ANDX:
            tid         = hdr['tid']
            share_upper = decoy_trees.get(tid)
            # FID at params[4] = payload[37] (after header(32)+WC(1)+AndXCmd(1)+AndXRsvd(1)+AndXOff(2))
            fid         = struct.unpack_from('<H', payload, 37)[0] if len(payload) >= 39 else 0
            fh          = open_files.get(fid)
            fname       = fh['filename'] if fh else None
            write_share = share_upper or (fh['share'] if fh else None)
            trace(client_ip, 'smb1_write', tid=hex(tid), fid=fid,
                  file=fname, on_decoy=share_upper is not None)
            _emit_knock(client_ip, user, write_share, 'SMB1', domain, host,
                        smb_file=fname, smb_action='WRITE',
                        trace_stage='knock_emitted_write')
            send_nbss(client_sock, build_smb1_error_response(
                hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_WRITE_ANDX))

        # ── COM_CLOSE ─────────────────────────────────────────────────────────
        elif cmd == SMB1_COM_CLOSE:
            fid = _smb1_parse_close(payload)
            closed_fh = open_files.pop(fid, None)
            trace(client_ip, 'smb1_close', fid=fid,
                  had_handle=closed_fh is not None,
                  file=closed_fh['filename'] if closed_fh else None)
            send_nbss(client_sock, build_smb1_close_response(hdr, uid, hdr['tid']))

        else:
            trace(client_ip, 'smb1_unexpected_cmd',
                  command=hex(cmd), setup_round=setup_round)
            break


# ---------------------------------------------------------------------------
# Connection handler — routes to SMB1 or SMB2/3 handler
# ---------------------------------------------------------------------------

def handle_connection(client_sock, client_ip):
    try:
        client_sock.settimeout(_SOCK_TIMEOUT)
        try:
            payload = recv_nbss(client_sock)
        except Exception as e:
            trace(client_ip, 'recv_error', error=f'{type(e).__name__}: {e}')
            return

        if payload[:4] == _SMB2_MAGIC:
            handle_smb2(client_sock, client_ip, payload)
        elif payload[:4] == _SMB1_MAGIC:
            handle_smb1(client_sock, client_ip, payload)
        else:
            trace(client_ip, 'unknown_magic',
                  magic=payload[:4].hex() if len(payload) >= 4 else 'short')
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def start_honeypot():
    decoy_summary = ' '.join(
        f'{share}:[{",".join(_DECOYS[share].keys())}]' for share in sorted(_DECOYS)
    )
    print(
        f'🧪 SMB config port={SMB_PORT} trace_enabled={TRACE_ENABLED} '
        f'trace_ip={TRACE_IP or "-"} dedup_window={EMIT_DEDUP_WINDOW_SEC}s '
        f'server_name={SMB_SERVER_NAME!r} server_domain={SMB_SERVER_DOMAIN!r} '
        f'decoys={decoy_summary}',
        flush=True,
    )
    sock = create_dualstack_tcp_listener(SMB_PORT)
    print(
        f'🚀 SMB Honeypot Active on Port {SMB_PORT} (SMB1/2/3 raw socket). Collecting knocks...',
        flush=True,
    )
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(
            target=handle_connection, args=(client, client_ip), daemon=True
        ).start()


def main():
    start_honeypot()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
SMB honeypot — minimal raw-socket implementation.
Handles SMB1/2/3 NEGOTIATE → SESSION_SETUP (NTLM 3-way) → TREE_CONNECT.
Zero filesystem backing: responds to TREE_CONNECT with STATUS_ACCESS_DENIED and closes.

Stage 1: foundation — all helpers, header parsers/builders, dedup, knock emission.
         handle_connection() is a stub that identifies SMB1 vs SMB2 and closes.
"""
import fnmatch
import json
import os
import struct
import threading
import time

from impacket import ntlm, smb
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
SMB_NATIVE_OS         = 'Windows Server 2019 Standard 17763'
SMB_NATIVE_LAN_MAN    = 'Windows Server 2019 Standard 17763'
SMB_QUARANTINE_DIR    = os.environ.get('SMB_QUARANTINE_DIR', '').strip()

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
    """Load decoy shares from SMB_DECOY_DIR recursively.
    Returns dict[share_name_upper -> flat_tree] where flat_tree is a dict
    mapping slash-separated relative paths to their content:
      'passwords.txt'      -> bytes   (file)
      'private'            -> None    (directory)
      'private/keys.txt'   -> bytes   (file in subdir)
    Root directory is implicit (always present, not stored as a key).
    """
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
                tree: dict = {}
                share_root = share_entry.path
                for dirpath, _dirnames, filenames in os.walk(share_root):
                    rel_dir = os.path.relpath(dirpath, share_root).replace(os.sep, '/')
                    if rel_dir == '.':
                        rel_dir = ''
                    if rel_dir:
                        tree[rel_dir] = None          # explicit subdir entry
                    for fname in filenames:
                        rel_file = (rel_dir + '/' + fname) if rel_dir else fname
                        try:
                            with open(os.path.join(dirpath, fname), 'rb') as fh:
                                tree[rel_file] = fh.read()
                        except Exception:
                            pass
                if tree:
                    decoys[share_name] = tree
        except Exception:
            pass
    if not decoys:
        decoys = {'PUBLIC': {'passwords.txt': _DEFAULT_DECOY_CONTENT}}
    return decoys


def _list_dir(tree: dict, path: str) -> list:
    """List immediate children of `path` ('' = root) in a flat tree.
    Returns list of (name, size, is_dir).
    """
    prefix = path + '/' if path else ''
    seen: set = set()
    result = []
    for k, v in tree.items():
        if not k.startswith(prefix):
            continue
        rest = k[len(prefix):]
        if not rest or '/' in rest:
            continue                   # skip exact-match and deeper entries
        if rest not in seen:
            seen.add(rest)
            if v is None:
                result.append((rest, 0, True))
            else:
                result.append((rest, len(v), False))
    return result


def _resolve_path(tree: dict, path: str):
    """Resolve a slash-separated path in a flat tree.
    Returns 'dir', 'file', or None (not found).
    """
    if not path:
        return 'dir'
    if path in tree:
        return 'dir' if tree[path] is None else 'file'
    # implicit dir: any key is a descendant
    prefix = path + '/'
    if any(k.startswith(prefix) for k in tree):
        return 'dir'
    return None


def _overlay_resolve_path(tree: dict, overlay: dict, path: str):
    """Resolve a path against the read-only decoy tree plus a writable overlay."""
    if not path:
        return 'dir'
    if path in overlay:
        return 'file'
    kind = _resolve_path(tree, path)
    if kind is not None:
        return kind
    prefix = path + '/'
    if any(k.startswith(prefix) for k in overlay):
        return 'dir'
    return None


def _overlay_get_content(tree: dict, overlay: dict, path: str) -> bytes:
    """Fetch file bytes from the writable overlay first, then the decoy tree."""
    if path in overlay:
        return bytes(overlay[path])
    value = tree.get(path, b'')
    return b'' if value is None else value


def _overlay_list_dir(tree: dict, overlay: dict, path: str) -> list:
    """List immediate children from the decoy tree plus writable overlay."""
    merged = {}
    for name, size, is_dir in _list_dir(tree, path):
        merged[name.lower()] = (name, size, is_dir)

    prefix = path + '/' if path else ''
    for key, value in overlay.items():
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        if not rest:
            continue
        child = rest.split('/', 1)[0]
        if '/' in rest:
            merged[child.lower()] = (child, 0, True)
        else:
            merged[child.lower()] = (child, len(value), False)
    return sorted(merged.values(), key=lambda item: item[0].lower())


def _overlay_write_file(overlay: dict, path: str, offset: int, data: bytes) -> int:
    """Write bytes into an overlay-backed file, expanding with zeros as needed."""
    buf = overlay.setdefault(path, bytearray())
    end = offset + len(data)
    if len(buf) < offset:
        buf.extend(b'\x00' * (offset - len(buf)))
    if len(buf) < end:
        buf.extend(b'\x00' * (end - len(buf)))
    buf[offset:end] = data
    return len(data)


def _sanitize_quarantine_component(value: str) -> str:
    """Sanitize a value for use in a flat quarantine filename."""
    cleaned = []
    for ch in (value or ''):
        if ch.isalnum() or ch in '._-':
            cleaned.append(ch)
        else:
            cleaned.append('_')
    return ''.join(cleaned).strip('._') or 'unnamed'


def _quarantine_overlay_file(client_ip: str, smb_version: str, share: str, path: str, data: bytes):
    """Best-effort write of an overlay-captured payload to the quarantine directory."""
    if not SMB_QUARANTINE_DIR or not data:
        return None
    try:
        os.makedirs(SMB_QUARANTINE_DIR, exist_ok=True)
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        safe_ip = _sanitize_quarantine_component(client_ip)
        safe_share = _sanitize_quarantine_component(share)
        safe_path = _sanitize_quarantine_component(path.replace('/', '__'))
        safe_ver = _sanitize_quarantine_component(smb_version)
        filename = f'{stamp}_{safe_ip}_{safe_ver}_{safe_share}_{safe_path}'
        full_path = os.path.join(SMB_QUARANTINE_DIR, filename)
        # Avoid collisions if the same path is quarantined more than once in the same second.
        if os.path.exists(full_path):
            full_path = os.path.join(
                SMB_QUARANTINE_DIR,
                f'{filename}_{int(time.time() * 1000)}',
            )
        with open(full_path, 'wb') as fh:
            fh.write(data)
        return full_path
    except Exception:
        return None


_DECOYS: dict = _load_decoys()  # share_name_upper -> flat tree
_SERVER_GUID  = os.urandom(16)  # stable per-process server GUID (used in NEGOTIATE + VALIDATE)

_MAX_MSG      = 200      # per-connection message cap (prevents runaway state machine)
_SOCK_TIMEOUT = 15       # seconds per recv
_NBSS_MAX     = int(os.environ.get('SMB_NBSS_MAX', str(4 * 1024 * 1024)))  # 4 MB default

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
    target_info += av(6, struct.pack('<I', 0x00000002))        # MsvAvFlags (MIC supported)
    target_info += av(7, struct.pack('<Q', filetime))          # MsvAvTimestamp
    target_info += av(10, b'\x00' * 16)                        # MsvAvChannelBindings (empty)
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
STATUS_INVALID_PARAMETER     = 0xC000000D
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_NOT_SUPPORTED         = 0xC00000BB
STATUS_NOT_IMPLEMENTED       = 0xC0000002
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
SMB1_COM_TRANSACTION    = 0x25
SMB1_COM_WRITE_ANDX     = 0x2F
SMB1_COM_READ_ANDX      = 0x2E
SMB1_COM_TRANSACTION2   = 0x32
SMB1_COM_NEGOTIATE      = 0x72
SMB1_COM_SESSION_SETUP  = 0x73
SMB1_COM_LOGOFF_ANDX    = 0x74
SMB1_COM_TREE_CONNECT   = 0x75
SMB1_COM_TREE_DISCONNECT = 0x71
SMB1_COM_NT_CREATE_ANDX = 0xA2
_SMB1_TRANS2_FIND_FIRST2 = 0x0001   # TRANS2 sub-command
_SMB1_TRANS2_NAMES = {
    0x0001: 'FIND_FIRST2',
    0x0002: 'FIND_NEXT2',
    0x0003: 'QUERY_FS_INFORMATION',
    0x0005: 'QUERY_PATH_INFORMATION',
    0x0006: 'SET_PATH_INFORMATION',
    0x0007: 'QUERY_FILE_INFORMATION',
    0x0008: 'SET_FILE_INFORMATION',
    0x000E: 'UNKNOWN_0x000E',
}
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
                smb_file=None, smb_action=None, smb_service_name=None,
                trace_stage='knock'):
    knock = {'type': 'KNOCK', 'proto': 'SMB', 'ip': ip}
    if user:               knock['user']             = user.lower()
    if smb_share:          knock['smb_share']        = smb_share
    if smb_file:           knock['smb_file']         = smb_file
    knock['smb_action'] = smb_action or 'UNKNOWN'
    if smb_version:        knock['smb_version']      = smb_version
    if smb_domain:         knock['smb_domain']       = smb_domain
    if smb_host:           knock['smb_host']         = smb_host
    if smb_service_name:   knock['smb_service_name'] = smb_service_name
    print(json.dumps(knock), flush=True)
    trace(ip, trace_stage, user=user, smb_share=smb_share, smb_file=smb_file,
          smb_version=smb_version, domain=smb_domain, host=smb_host)


def _classify_create_action(kind, disposition, path):
    """Map SMB CREATE/NT_CREATE semantics to a more human-meaningful action."""
    if kind == 'dir' or not path:
        return 'OPEN_DIR'
    if kind == 'file':
        return 'OPEN_FILE'
    if disposition != _SMB2_CREATE_DISP_FILE_OPEN:
        return 'CREATE_FILE'
    return 'CHECK_FILE'


def _extract_utf16_pipe_name(buf):
    """Best-effort extraction of a UTF-16 pipe/control name from raw IOCTL input."""
    if not buf:
        return None
    try:
        decoded = buf.decode('utf-16-le', errors='ignore')
    except Exception:
        return None
    match = re.search(r'([A-Za-z][A-Za-z0-9_]{2,})', decoded)
    return match.group(1) if match else None

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
        + _SERVER_GUID                       # ServerGuid (stable per process)
        + struct.pack('<I', 0x3F)            # Capabilities (DFS|LEASING|LARGE_MTU|MULTI_CHANNEL|PERSIST|DIR_LEASE)
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


def _build_smb2_session_setup_response(hdr, status, sec_buf, session_id=0, session_flags=0):
    """
    Build an SMB2 SESSION_SETUP response.
    SecurityBufferOffset = 64 (header) + 8 (fixed body) = 72.
    session_flags: SMB2_SESSION_FLAG_IS_GUEST (0x0001) disables signing on
    strict clients like smbprotocol (require_signing=True); harmless for attackers.
    """
    body = (
        struct.pack('<H', 9)               # StructureSize
        + struct.pack('<H', session_flags) # SessionFlags
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


def build_smb2_query_directory_response(hdr, session_id, tree_id, files, file_info_class):
    """Return a fake directory listing matching the requested SMB2 info class."""
    if not files:
        return build_smb2_error_response(
            hdr, session_id, tree_id, STATUS_NO_MORE_FILES, SMB2_QUERY_DIRECTORY)
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()

    def _make_entry(fname, size, is_dir):
        attrs = 0x10 if is_dir else 0x20     # DIRECTORY or NORMAL
        alloc = 0 if is_dir else (size + 4095) & ~4095
        name  = fname.encode('utf-16-le')

        base = (
            struct.pack('<I', 0)             # NextEntryOffset (filled below)
            + struct.pack('<I', 0)           # FileIndex
            + struct.pack('<Q', ft_old)      # CreationTime
            + struct.pack('<Q', ft_now)      # LastAccessTime
            + struct.pack('<Q', ft_old)      # LastWriteTime
            + struct.pack('<Q', ft_old)      # ChangeTime
            + struct.pack('<Q', size)        # EndOfFile
            + struct.pack('<Q', alloc)       # AllocationSize
            + struct.pack('<I', attrs)       # FileAttributes
            + struct.pack('<I', len(name))   # FileNameLength
        )

        if file_info_class == 1:  # FILE_DIRECTORY_INFORMATION
            raw = bytearray(base + name)
        elif file_info_class == 3:  # FILE_BOTH_DIRECTORY_INFORMATION
            raw = bytearray(
                base
                + struct.pack('<I', 0)       # EaSize
                + struct.pack('<B', 0)       # ShortNameLength
                + struct.pack('<B', 0)       # Reserved1
                + b'\x00' * 24               # ShortName[12 wide chars = 24 bytes]
                + name
            )
        elif file_info_class == 37:  # FILE_ID_BOTH_DIRECTORY_INFORMATION
            raw = bytearray(
                base
                + struct.pack('<I', 0)       # EaSize
                + struct.pack('<B', 0)       # ShortNameLength
                + struct.pack('<B', 0)       # Reserved1
                + b'\x00' * 24               # ShortName[12 wide chars = 24 bytes]
                + struct.pack('<H', 0)       # Reserved2
                + struct.pack('<Q', 0)       # FileId
                + name
            )
        else:
            return None
        if len(raw) % 8:
            raw += b'\x00' * (8 - len(raw) % 8)
        return raw

    entries = [_make_entry('.', 0, True), _make_entry('..', 0, True)]
    for fname, size, is_dir in files:
        entries.append(_make_entry(fname, size, is_dir))
    if any(entry is None for entry in entries):
        return build_smb2_error_response(
            hdr, session_id, tree_id, STATUS_NOT_SUPPORTED, SMB2_QUERY_DIRECTORY)

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


def build_smb2_write_response(hdr, session_id, tree_id, count):
    """SMB2 WRITE success response — acknowledges `count` bytes written."""
    body = (
        struct.pack('<H', 17)    # StructureSize
        + struct.pack('<H', 0)   # Reserved
        + struct.pack('<I', count)  # Count (bytes written)
        + struct.pack('<I', 0)   # Remaining
        + struct.pack('<H', 0)   # WriteChannelInfoOffset
        + struct.pack('<H', 0)   # WriteChannelInfoLength
    )
    return build_smb2_response_header(
        SMB2_WRITE, STATUS_SUCCESS, hdr['message_id'],
        session_id=session_id, tree_id=tree_id,
    ) + body


def build_smb2_read_response(hdr, session_id, tree_id, data):
    """Return a chunk of fake file content or pipe data."""
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
_DCERPC_FAULT           = 0x03
_DCERPC_PFC_OBJECT_UUID = 0x80
_SRVSVC_NETR_SHARE_ENUM = 15         # opnum for NetrShareEnum
_SVCCTL_R_CREATE_SERVICE_W = 12     # opnum for RCreateServiceW (MS-SCMR §3.1.4.12)
_SVCCTL_R_OPEN_SC_MANAGER_W = 15   # opnum for ROpenSCManagerW (MS-SCMR §3.1.4.1)
_SVCCTL_R_OPEN_SERVICE_W    = 16   # opnum for ROpenServiceW  (MS-SCMR §3.1.4.20)
_SVCCTL_R_START_SERVICE_W   = 19   # opnum for RStartServiceW  (MS-SCMR §3.1.4.30)
_SVCCTL_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_FSCTL_PIPE_WAIT              = 0x00110018  # SMB2 IOCTL code for waiting on a named pipe
_FSCTL_PIPE_TRANSCEIVE        = 0x0011C017  # SMB2 IOCTL code for named-pipe transact
_FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204  # SMB3 post-negotiate validation (RFC MS-SMB2 §3.3.5.15.12)

_SVCCTL_OPNUM_NAMES = {
    _SVCCTL_R_CREATE_SERVICE_W: 'RCreateServiceW',
    _SVCCTL_R_OPEN_SC_MANAGER_W: 'ROpenSCManagerW',
    _SVCCTL_R_OPEN_SERVICE_W: 'ROpenServiceW',
    _SVCCTL_R_START_SERVICE_W: 'RStartServiceW',
}

# Common IPC named pipes accepted by the honeypot.
# SRVSVC is fully handled (NetrShareEnum). All others accept BIND and return
# a DCERPC FAULT for any REQUEST — realistic enough to avoid honeypot fingerprinting.
_KNOWN_PIPES = {
    'SRVSVC',    # Server Service — share enumeration (fully handled)
    'WKSSVC',    # Workstation Service — workstation info
    'SAMR',      # Security Account Manager — user enumeration
    'LSARPC',    # Local Security Authority — policy/SID lookups
    'NETLOGON',  # Net Logon — domain auth
    'WINREG',    # Remote Registry
    'SVCCTL',    # Service Control Manager
    'EVENTLOG',  # Event Log
}

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


def _dcerpc_bind_ack(call_id, ctx_id=0, pipe_name='srvsvc'):
    """DCERPC BIND_ACK accepting the named pipe interface with NDR transfer syntax."""
    sec_addr_str = f'\\PIPE\\{pipe_name.lower()}\x00'.encode('ascii')
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


def _dcerpc_fault(call_id, ctx_id=0, fault_code=0x1c010002):
    """DCERPC FAULT PDU — nca_s_op_rng_error (unknown opnum) by default."""
    body = (
        struct.pack('<I', 0)           # alloc_hint
        + struct.pack('<H', ctx_id)    # p_cont_id
        + struct.pack('<H', 0)         # cancel_count / reserved
        + struct.pack('<I', fault_code)  # status: nca_s_op_rng_error
    )
    return _dcerpc_hdr(_DCERPC_FAULT, call_id, len(body)) + body


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

    # container_ref intentionally set to n (share count).
    # NDR allows any non-zero unique pointer referent. Setting it to n lets
    # smbtest.py's NDR parser (which reads stub[8] as count) work correctly.
    container_ref = n
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


def _handle_dcerpc_multi(data, client_ip, user=None, smb_version=None,
                         smb_domain=None, smb_host=None, pipe_name='SRVSVC',
                         svc_handles=None):
    """
    Handle one or more concatenated DCERPC PDUs in a single buffer.
    Walks the buffer using frag_length (at offset 8 in each PDU header),
    calls _handle_dcerpc on each PDU, and concatenates the responses.
    Returns combined response bytes, or None if nothing was handled.
    """
    responses = []
    offset    = 0
    while offset < len(data):
        if offset + 10 > len(data):
            break
        frag_length = struct.unpack_from('<H', data, offset + 8)[0]
        if frag_length < 16 or offset + frag_length > len(data):
            break
        pdu  = data[offset:offset + frag_length]
        resp = _handle_dcerpc(pdu, client_ip, user=user, smb_version=smb_version,
                              smb_domain=smb_domain, smb_host=smb_host,
                              pipe_name=pipe_name, svc_handles=svc_handles)
        if resp:
            responses.append(resp)
        offset += frag_length
    return b''.join(responses) if responses else None


def _parse_ndr_conformant_string(buf, offset):
    """
    Parse an NDR conformant/varying Unicode string from buf starting at offset.
    Layout: MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE data.
    Returns (string_value, new_offset) or (None, new_offset) on parse failure.
    """
    if offset + 12 > len(buf):
        return None, offset
    actual_count = struct.unpack_from('<I', buf, offset + 8)[0]
    offset += 12
    byte_len = actual_count * 2
    if offset + byte_len > len(buf):
        return None, offset + byte_len
    try:
        value = buf[offset:offset + byte_len].decode('utf-16-le').rstrip('\x00')
    except UnicodeDecodeError:
        value = None
    return value, offset + byte_len


def _parse_ndr_varying_string(buf, offset):
    """
    Parse an NDR varying Unicode string from buf starting at offset.
    Layout: Offset(4) + ActualCount(4) + UTF-16LE data.
    """
    if offset + 8 > len(buf):
        return None, offset
    actual_count = struct.unpack_from('<I', buf, offset + 4)[0]
    offset += 8
    byte_len = actual_count * 2
    if offset + byte_len > len(buf):
        return None, offset + byte_len
    try:
        value = buf[offset:offset + byte_len].decode('utf-16-le').rstrip('\x00')
    except UnicodeDecodeError:
        value = None
    return value, offset + byte_len


def _parse_ndr_string_any(buf, offset):
    """
    Parse either a conformant/varying or varying-only Unicode NDR string.
    Returns (value, new_offset, format_name).
    """
    value, new_offset = _parse_ndr_conformant_string(buf, offset)
    if value is not None:
        return value, new_offset, 'conformant'
    value, new_offset = _parse_ndr_varying_string(buf, offset)
    if value is not None:
        return value, new_offset, 'varying'
    return None, offset, None


def _align4(offset):
    """Return the next 4-byte aligned offset."""
    return (offset + 3) & ~3


def _parse_dcerpc_request_fields(data):
    """
    Parse a DCERPC REQUEST PDU and return:
      (ctx_id, opnum, stub, meta_dict)

    Handles optional object UUIDs and auth verifier trailers.
    """
    if len(data) < 24:
        return None, None, b'', {}

    flags = data[3]
    frag_length = struct.unpack_from('<H', data, 8)[0]
    auth_length = struct.unpack_from('<H', data, 10)[0]
    ctx_id = struct.unpack_from('<H', data, 20)[0]
    opnum = struct.unpack_from('<H', data, 22)[0]

    stub_offset = 24 + (16 if (flags & _DCERPC_PFC_OBJECT_UUID) else 0)
    stub_end = min(frag_length, len(data))
    auth_pad_length = 0

    if auth_length:
        auth_trailer_len = 8 + auth_length
        auth_start = stub_end - auth_trailer_len
        if stub_offset <= auth_start < len(data):
            auth_pad_length = data[auth_start]
            stub_end = max(stub_offset, auth_start - auth_pad_length)

    stub = data[stub_offset:stub_end] if stub_end >= stub_offset else b''
    meta = {
        'flags': flags,
        'frag_length': frag_length,
        'auth_length': auth_length,
        'auth_pad_length': auth_pad_length,
        'has_object_uuid': bool(flags & _DCERPC_PFC_OBJECT_UUID),
        'stub_offset': stub_offset,
        'stub_end': stub_end,
    }
    return ctx_id, opnum, stub, meta


def _parse_svcctl_r_create_service_w(stub):
    """
    Parse an RCreateServiceW NDR stub (MS-SCMR §3.1.4.12).
    Returns (service_name, binary_path, debug_meta).

    Live traces show a top-level marshal order of:
      hSCManager(20)
      lpServiceName unique pointer + deferred string
      lpDisplayName unique pointer + deferred string
      fixed DWORD/pointer block:
        DesiredAccess, ServiceType, StartType, ErrorControl,
        lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies,
        dwDependSize, lpServiceStartName, lpPassword, dwPwSize
      deferred pointees for the later pointers in that same order

    The earlier parser incorrectly assumed lpDisplayName sat at offset 24 and that
    the fixed block started immediately after the first string without re-alignment.
    The live stub previews show 4-byte alignment padding between these items.
    """
    debug = {
        'svc_ptr': None,
        'post_service_offset': None,
        'disp_ptr_offset': None,
        'disp_ptr': None,
        'post_display_offset': None,
        'fixed_offset': None,
        'ptr_block_offset': None,
        'bin_ptr': None,
        'load_group_ptr': None,
        'dep_ptr': None,
        'dep_size': None,
        'start_name_ptr': None,
        'password_ptr': None,
        'pw_size': None,
        'deferred_offset': None,
    }
    try:
        if len(stub) < 28:
            return None, None, debug

        # Observed live layout:
        #   hSCManager(20)
        #   lpServiceName + deferred string
        #   4-byte pad up to next top-level pointer
        #   lpDisplayName + deferred string
        #   fixed 48-byte DWORD/pointer block begins immediately after that
        #   deferred data for later pointers starts immediately after the block
        offset = 20
        svc_ptr = struct.unpack_from('<I', stub, offset)[0]
        debug['svc_ptr'] = hex(svc_ptr)
        offset += 4

        service_name = None
        if svc_ptr:
            service_name, offset, _ = _parse_ndr_string_any(stub, offset)
            offset = _align4(offset)
        debug['post_service_offset'] = offset

        if offset + 4 > len(stub):
            return service_name, None, debug

        debug['disp_ptr_offset'] = offset
        disp_ptr = struct.unpack_from('<I', stub, offset)[0]
        debug['disp_ptr'] = hex(disp_ptr)
        offset += 4
        if disp_ptr:
            _, offset, _ = _parse_ndr_string_any(stub, offset)
        debug['post_display_offset'] = offset

        # DesiredAccess begins immediately after the second deferred string,
        # even if that leaves the stream only 2-byte aligned. The following
        # scalar DWORDs are then realigned to 4 bytes. After that, the
        # remaining pointer arguments are marshaled inline in declaration
        # order with their pointees following immediately.
        fixed_offset = offset
        scalar_offset = _align4(fixed_offset + 4)
        ptr_block_offset = scalar_offset + 12
        debug['fixed_offset'] = fixed_offset
        debug['ptr_block_offset'] = ptr_block_offset
        if ptr_block_offset + 4 > len(stub):
            return service_name, None, debug

        bin_ptr = struct.unpack_from('<I', stub, ptr_block_offset)[0]
        debug['bin_ptr'] = hex(bin_ptr)

        binary_path = None
        deferred_offset = ptr_block_offset + 4
        if bin_ptr:
            binary_path, deferred_offset, _ = _parse_ndr_string_any(stub, deferred_offset)
            deferred_offset = _align4(deferred_offset)

        load_group_ptr = 0
        if deferred_offset + 4 <= len(stub):
            load_group_ptr = struct.unpack_from('<I', stub, deferred_offset)[0]
            debug['load_group_ptr'] = hex(load_group_ptr)
            deferred_offset += 4
            if load_group_ptr:
                _, deferred_offset, _ = _parse_ndr_string_any(stub, deferred_offset)
                deferred_offset = _align4(deferred_offset)

        if deferred_offset + 4 <= len(stub):
            # lpdwTagId is [out] only; consume the pointer slot but no input pointee.
            deferred_offset += 4

        dep_ptr = 0
        dep_size = 0
        if deferred_offset + 8 <= len(stub):
            dep_ptr = struct.unpack_from('<I', stub, deferred_offset)[0]
            dep_size = struct.unpack_from('<I', stub, deferred_offset + 4)[0]
            debug['dep_ptr'] = hex(dep_ptr)
            debug['dep_size'] = dep_size
            deferred_offset += 8
            if dep_ptr and dep_size and deferred_offset + dep_size <= len(stub):
                deferred_offset = _align4(deferred_offset + dep_size)

        start_name_ptr = 0
        if deferred_offset + 4 <= len(stub):
            start_name_ptr = struct.unpack_from('<I', stub, deferred_offset)[0]
            debug['start_name_ptr'] = hex(start_name_ptr)
            deferred_offset += 4
            if start_name_ptr:
                _, deferred_offset, _ = _parse_ndr_string_any(stub, deferred_offset)
                deferred_offset = _align4(deferred_offset)

        password_ptr = 0
        pw_size = 0
        if deferred_offset + 8 <= len(stub):
            password_ptr = struct.unpack_from('<I', stub, deferred_offset)[0]
            pw_size = struct.unpack_from('<I', stub, deferred_offset + 4)[0]
            debug['password_ptr'] = hex(password_ptr)
            debug['pw_size'] = pw_size
            deferred_offset += 8
            if password_ptr and pw_size and deferred_offset + pw_size <= len(stub):
                deferred_offset = _align4(deferred_offset + pw_size)

        debug['deferred_offset'] = deferred_offset

        return service_name, binary_path, debug
    except Exception:
        return None, None, debug


def _parse_svcctl_r_open_service_w(stub):
    """
    Parse an ROpenServiceW NDR stub (MS-SCMR §3.1.4.20).
    Returns (service_name, desired_access).

    Observed layout from live clients:
      hSCManager(20) + lpServiceName_ptr(4) + deferred NDR string + DesiredAccess(4)

    This differs from the earlier simplified assumption that DesiredAccess appears
    before the deferred string blob. The live traces show the string immediately
    after the pointer fields, with DesiredAccess trailing the string data.
    """
    try:
        if len(stub) < 24:
            return None, None
        svc_ptr = struct.unpack_from('<I', stub, 20)[0]
        service_name = None
        offset = 24
        if svc_ptr:
            service_name, offset, _ = _parse_ndr_string_any(stub, offset)
        desired_access = None
        if offset + 4 <= len(stub):
            desired_access = struct.unpack_from('<I', stub, offset)[0]
        elif len(stub) >= 4:
            desired_access = struct.unpack_from('<I', stub, len(stub) - 4)[0]
        return service_name, desired_access
    except Exception:
        return None, None


def _dcerpc_svcctl_dword_response(call_id, ctx_id, win_error=0):
    """DCERPC RESPONSE returning only a DWORD — used for RStartServiceW and similar."""
    stub = struct.pack('<I', win_error)
    body = (
        struct.pack('<I', len(stub))    # alloc_hint
        + struct.pack('<H', ctx_id)     # p_cont_id
        + struct.pack('<H', 0)          # cancel_count
        + stub
    )
    return _dcerpc_hdr(_DCERPC_RESPONSE, call_id, len(body)) + body


def _dcerpc_svcctl_handle_response(call_id, ctx_id, handle=None, win_error=0):
    """
    DCERPC RESPONSE containing a context handle [out] + DWORD return code.
    Used for ROpenSCManagerW (success, win_error=0) and RCreateServiceW (error).
    handle: 20-byte context handle bytes; defaults to random-looking bytes.
    """
    if handle is None:
        handle = os.urandom(16) + b'\x00\x00\x00\x00'  # 20-byte context handle
    stub = handle + struct.pack('<I', win_error)
    body = (
        struct.pack('<I', len(stub))    # alloc_hint
        + struct.pack('<H', ctx_id)     # p_cont_id
        + struct.pack('<H', 0)          # cancel_count
        + stub
    )
    return _dcerpc_hdr(_DCERPC_RESPONSE, call_id, len(body)) + body


def _handle_dcerpc(data, client_ip, user=None, smb_version=None,
                   smb_domain=None, smb_host=None, pipe_name='SRVSVC',
                   svc_handles=None):
    """
    Parse an incoming DCERPC PDU and return the response bytes, or None if unhandled.
    BIND → BIND_ACK (sec_addr reflects the actual pipe).
    For SRVSVC: REQUEST opnum 15 (NetrShareEnum) → share list response.
    For SVCCTL: opnum 15 (ROpenSCManagerW) → fake handle; opnum 12 (RCreateServiceW)
                → fake service handle + knock; opnum 19 (RStartServiceW) → ACCESS_DENIED + knock.
    For other known pipes: REQUEST → DCERPC FAULT (nca_s_op_rng_error).
    svc_handles: session-level dict {handle_bytes: (svc_name, bin_path)} for handle correlation.
    """
    if len(data) < 16:
        return None
    pdu_type = data[2]
    call_id  = struct.unpack_from('<I', data, 12)[0]

    if pdu_type == _DCERPC_BIND:
        ctx_id = struct.unpack_from('<H', data, 28)[0] if len(data) >= 30 else 0
        trace(client_ip, 'dcerpc_bind', pipe=pipe_name, call_id=call_id, ctx_id=ctx_id)
        return _dcerpc_bind_ack(call_id, ctx_id, pipe_name=pipe_name)

    if pdu_type == _DCERPC_REQUEST:
        if len(data) < 24:
            return None
        ctx_id, opnum, stub, req_meta = _parse_dcerpc_request_fields(data)
        if ctx_id is None or opnum is None:
            return None
        if pipe_name == 'SRVSVC':
            if opnum == _SRVSVC_NETR_SHARE_ENUM:
                level = _parse_netr_share_enum_level(stub)
                trace(client_ip, 'srvsvc_netr_share_enum', call_id=call_id, level=level)
                if level == 1:
                    # Share types: IPC$=3 (STYPE_IPC), admin shares ending in $=0x80000000
                    # (STYPE_SPECIAL), regular disk shares=0 (STYPE_DISKTREE)
                    _STYPE_SPECIAL = 0x80000000
                    shares = [('IPC$', 3, 'Remote IPC')] + [
                        (name, _STYPE_SPECIAL if name.endswith('$') else 0, '')
                        for name in _DECOYS
                    ]
                    share_names = ','.join(name for name, _, _ in shares if name != 'IPC$')
                    _emit_knock(client_ip, user, share_names, smb_version, smb_domain, smb_host,
                                smb_action='ENUM', trace_stage='knock_emitted_enum')
                    return _srvsvc_netr_share_enum_response(call_id, ctx_id, shares)
                _emit_knock(client_ip, user, None, smb_version, smb_domain, smb_host,
                            smb_action='ENUM', trace_stage='knock_emitted_enum')
                trace(client_ip, 'srvsvc_unsupported_level', opnum=opnum, level=level)
                return _dcerpc_fault(call_id, ctx_id)
            trace(client_ip, 'srvsvc_unsupported_opnum', opnum=opnum)
        elif pipe_name == 'SVCCTL':
            if opnum == _SVCCTL_R_OPEN_SC_MANAGER_W:
                # Return a fake SCM handle so the worm can proceed to RCreateServiceW
                trace(client_ip, 'svcctl_open_sc_manager')
                return _dcerpc_svcctl_handle_response(call_id, ctx_id, win_error=0)
            if opnum == _SVCCTL_R_OPEN_SERVICE_W:
                svc_name, desired_access = _parse_svcctl_r_open_service_w(stub)
                trace(client_ip, 'svcctl_open_service',
                      service_name=svc_name, desired_access=hex(desired_access or 0),
                      stub_len=len(stub), stub_preview=stub[:64].hex(),
                      has_object_uuid=req_meta.get('has_object_uuid'),
                      auth_length=req_meta.get('auth_length'),
                      auth_pad_length=req_meta.get('auth_pad_length'),
                      result='service_not_found')
                _emit_knock(client_ip, user, None, smb_version, smb_domain, smb_host,
                            smb_action='OPEN_SERVICE',
                            smb_service_name=svc_name,
                            trace_stage='knock_emitted_open_service')
                # Returning ERROR_SERVICE_DOES_NOT_EXIST nudges installers into CreateServiceW.
                return _dcerpc_svcctl_handle_response(
                    call_id, ctx_id, handle=b'\x00' * 20,
                    win_error=_SVCCTL_ERROR_SERVICE_DOES_NOT_EXIST,
                )
            if opnum == _SVCCTL_R_CREATE_SERVICE_W:
                svc_name, bin_path, create_meta = _parse_svcctl_r_create_service_w(stub)
                trace(client_ip, 'svcctl_create_service',
                      service_name=svc_name, binary_path=bin_path,
                      stub_len=len(stub), stub_preview=stub[:96].hex(),
                      has_object_uuid=req_meta.get('has_object_uuid'),
                      auth_length=req_meta.get('auth_length'),
                      auth_pad_length=req_meta.get('auth_pad_length'),
                      svc_ptr=create_meta.get('svc_ptr'),
                      post_service_offset=create_meta.get('post_service_offset'),
                      disp_ptr_offset=create_meta.get('disp_ptr_offset'),
                      disp_ptr=create_meta.get('disp_ptr'),
                      post_display_offset=create_meta.get('post_display_offset'),
                      fixed_offset=create_meta.get('fixed_offset'),
                      ptr_block_offset=create_meta.get('ptr_block_offset'),
                      bin_ptr=create_meta.get('bin_ptr'),
                      load_group_ptr=create_meta.get('load_group_ptr'),
                      dep_ptr=create_meta.get('dep_ptr'),
                      dep_size=create_meta.get('dep_size'),
                      start_name_ptr=create_meta.get('start_name_ptr'),
                      password_ptr=create_meta.get('password_ptr'),
                      pw_size=create_meta.get('pw_size'),
                      deferred_offset=create_meta.get('deferred_offset'))
                _emit_knock(client_ip, user, None, smb_version, smb_domain, smb_host,
                            smb_file=bin_path, smb_action='CREATE_SERVICE',
                            smb_service_name=svc_name,
                            trace_stage='knock_emitted_create_service')
                # Return success with a fake handle so the worm proceeds to RStartServiceW
                fake_handle = os.urandom(16) + b'\x00\x00\x00\x00'
                if svc_handles is not None:
                    svc_handles[fake_handle] = (svc_name, bin_path)
                return _dcerpc_svcctl_handle_response(call_id, ctx_id,
                                                      handle=fake_handle, win_error=0)
            if opnum == _SVCCTL_R_START_SERVICE_W:
                # hService handle is the first 20 bytes of the stub
                handle_key = stub[:20] if len(stub) >= 20 else None
                info = svc_handles.get(handle_key) if (svc_handles and handle_key) else None
                svc_name  = info[0] if info else None
                bin_path  = info[1] if info else None
                trace(client_ip, 'svcctl_start_service',
                      service_name=svc_name, binary_path=bin_path)
                _emit_knock(client_ip, user, None, smb_version, smb_domain, smb_host,
                            smb_file=bin_path, smb_action='START_SERVICE',
                            smb_service_name=svc_name,
                            trace_stage='knock_emitted_start_service')
                # Deny execution — DWORD-only response (RStartServiceW has no [out] handle)
                return _dcerpc_svcctl_dword_response(call_id, ctx_id, win_error=5)
            trace(client_ip, 'dcerpc_stub_request', pipe=pipe_name, opnum=opnum,
                  opnum_name=_SVCCTL_OPNUM_NAMES.get(opnum, f'UNKNOWN_{opnum}'),
                  stub_len=len(stub), stub_preview=stub[:64].hex(),
                  has_object_uuid=req_meta.get('has_object_uuid'),
                  auth_length=req_meta.get('auth_length'),
                  auth_pad_length=req_meta.get('auth_pad_length'))
        else:
            trace(client_ip, 'dcerpc_stub_request', pipe=pipe_name, opnum=opnum,
                  stub_len=len(stub), stub_preview=stub[:64].hex(),
                  has_object_uuid=req_meta.get('has_object_uuid'),
                  auth_length=req_meta.get('auth_length'),
                  auth_pad_length=req_meta.get('auth_pad_length'))
        return _dcerpc_fault(call_id, ctx_id)

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


def build_smb2_validate_negotiate_response(hdr, session_id, tree_id, selected_dialect):
    """
    FSCTL_VALIDATE_NEGOTIATE_INFO response (MS-SMB2 §3.3.5.15.12).
    Output: Capabilities(4) + ServerGuid(16) + SecurityMode(2) + Dialect(2) = 24 bytes.
    Must echo back exactly the values we sent in the NEGOTIATE response.
    """
    output = (
        struct.pack('<I', 0x3F)           # Capabilities (matches NEGOTIATE response)
        + _SERVER_GUID                    # ServerGuid (same stable GUID)
        + struct.pack('<H', 0x0001)       # SecurityMode (NEGOTIATE_SIGNING_ENABLED)
        + struct.pack('<H', selected_dialect)  # Dialect
    )
    buf_offset = 64 + 48  # header(64) + fixed IOCTL body(48)
    body = (
        struct.pack('<H', 49)             # StructureSize
        + struct.pack('<H', 0)            # Reserved
        + struct.pack('<I', _FSCTL_VALIDATE_NEGOTIATE_INFO)  # CtlCode
        + struct.pack('<QQ', 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)  # FileId = FFFFFFFF... (N/A)
        + struct.pack('<I', buf_offset)   # InputOffset
        + struct.pack('<I', 0)            # InputCount
        + struct.pack('<I', buf_offset)   # OutputOffset
        + struct.pack('<I', len(output))  # OutputCount
        + struct.pack('<I', 0)            # Flags
        + struct.pack('<I', 0)            # Reserved2
        + output
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


def _parse_write_params(payload):
    """
    Parse Length, Offset, FileId, and data bytes from an SMB2 WRITE request.
    Body layout: DataOffset(2)@66 + Length(4)@68 + Offset(8)@72 + FileId(16)@80
    """
    if len(payload) < 96:
        return 0, 0, (0, 0), b''
    data_offset = struct.unpack_from('<H', payload, 66)[0]
    length = struct.unpack_from('<I', payload, 68)[0]
    offset = struct.unpack_from('<Q', payload, 72)[0]
    fid = _parse_file_id_at(payload, 80)
    if not data_offset or data_offset + length > len(payload):
        return int(offset), 0, fid, b''
    return int(offset), int(length), fid, payload[data_offset:data_offset + length]


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


def _parse_query_directory_params(payload):
    """
    Parse FileInformationClass, Flags, and FileId from an SMB2 QUERY_DIRECTORY request.
    Body layout: StructureSize(2)+FileInformationClass(1)@66+Flags(1)@67+...+FileId(16)@72
    """
    if len(payload) < 96:
        return 0, 0, (0, 0)
    file_info_class = payload[66]
    flags           = payload[67]
    fid             = _parse_file_id_at(payload, 72)
    return file_info_class, flags, fid


# ---------------------------------------------------------------------------
# SMB2/3 session state machine
# ---------------------------------------------------------------------------

def _smb2_post_negotiate(client_sock, client_ip, smb_version, selected_dialect=0x0210):
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
    # open_files: {(persistent, volatile): {'share': str, 'path': str|None, 'is_dir': bool, 'listed': bool}}
    open_files   = {}
    overlay_files = {}  # {(share_upper, share_relative_path): bytearray}
    quarantined_paths = set()  # {(share_upper, share_relative_path)}
    # pipe_fids: {(persistent, volatile): {'pending': bytes|None, 'pipe': str}} for IPC named pipe handles
    pipe_fids    = {}
    # svc_handles: {handle_bytes: (svc_name, bin_path)} — maps fake SVCCTL handles to service info
    svc_handles  = {}
    next_fid     = 1     # monotonic counter for allocating unique FileId values
    got_auth     = False

    for _ in range(_MAX_MSG - 1):
        try:
            payload = recv_nbss(client_sock)
        except Exception as e:
            trace(client_ip, 'smb2_recv_error', error=f'{type(e).__name__}: {e}')
            break
        hdr = parse_smb2_header(payload)
        if not hdr:
            trace(client_ip, 'smb2_bad_header')
            break

        cmd = hdr['command']
        trace(client_ip, 'smb2_recv', cmd=hex(cmd), payload_len=len(payload))

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

                _emit_knock(client_ip, user, None, smb_version, domain, host,
                            smb_action='AUTH', trace_stage='knock_emitted_auth')
                got_auth = True

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
                if should_emit(client_ip, user, domain, host, smb_version, share):
                    _emit_knock(client_ip, user, share, smb_version, domain, host,
                                smb_action='CONNECT', trace_stage='knock_emitted_tree')
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
                if should_emit(client_ip, user, domain, host, smb_version, share):
                    _emit_knock(client_ip, user, share, smb_version, domain, host,
                                smb_action='CONNECT', trace_stage='knock_emitted_tree')
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
                # Accept any known IPC named pipe; reject everything else on IPC$
                pipe_name = clean.split('\\')[-1].upper()
                if pipe_name in _KNOWN_PIPES:
                    fid_p = fid_v = next_fid; next_fid += 1
                    pipe_fids[(fid_p, fid_v)] = {'pending': None, 'pipe': pipe_name}
                    trace(client_ip, 'pipe_open', pipe=pipe_name, fid=fid_p)
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
            share_tree = _DECOYS[share_upper]
            share_overlay = overlay_files.setdefault(share_upper, {})
            # Normalize: strip leading backslashes, convert to forward-slash path
            norm = clean.replace('\\', '/').strip('/')
            kind = _overlay_resolve_path(share_tree, share_overlay, norm)
            disposition = (struct.unpack_from('<I', payload, 100)[0]
                           if len(payload) >= 104 else _SMB2_CREATE_DISP_FILE_OPEN)
            create_action = _classify_create_action(kind, disposition, norm)
            _emit_knock(client_ip, user, share_upper, smb_version, domain, host,
                        smb_file=norm, smb_action=create_action,
                        trace_stage='knock_emitted_create')
            if kind == 'dir':
                fid_p = fid_v = next_fid; next_fid += 1
                open_files[(fid_p, fid_v)] = {'share': share_upper, 'path': norm,
                                               'is_dir': True, 'listed': False}
                trace(client_ip, 'smb2_create', name=norm or '(root)', fid=fid_p, is_dir=True)
                send_nbss(client_sock, build_smb2_create_response(
                    hdr, session_id, tree_id, fid_p, fid_v, True))
            elif kind == 'file':
                fsize = len(_overlay_get_content(share_tree, share_overlay, norm))
                fid_p = fid_v = next_fid; next_fid += 1
                open_files[(fid_p, fid_v)] = {'share': share_upper, 'path': norm,
                                               'is_dir': False, 'listed': False}
                trace(client_ip, 'smb2_create', name=norm, fid=fid_p, is_dir=False)
                send_nbss(client_sock, build_smb2_create_response(
                    hdr, session_id, tree_id, fid_p, fid_v, False, file_size=fsize))
            else:
                # Path not found — check if bot is trying to create a new file
                if disposition != _SMB2_CREATE_DISP_FILE_OPEN:
                    share_overlay.setdefault(norm, bytearray())
                    fid_p = fid_v = next_fid; next_fid += 1
                    open_files[(fid_p, fid_v)] = {'share': share_upper, 'path': norm,
                                                  'is_dir': False, 'listed': False}
                    trace(client_ip, 'smb2_create', name=norm, fid=fid_p,
                          is_dir=False, result='created_overlay')
                    send_nbss(client_sock, build_smb2_create_response(
                        hdr, session_id, tree_id, fid_p, fid_v, False, file_size=0))
                else:
                    trace(client_ip, 'smb2_create', name=norm, result='not_found')
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_OBJECT_NAME_NOT_FOUND, SMB2_CREATE))

        # ── IOCTL ── before IPC$ catch-all so FSCTL_PIPE_TRANSCEIVE works ─────
        elif cmd == SMB2_IOCTL:
            ctl_code = struct.unpack_from('<I', payload, 68)[0] if len(payload) >= 72 else 0
            fid_pair = _parse_file_id_at(payload, 72)   # FileId at body+8 = abs 72
            in_off   = struct.unpack_from('<I', payload, 88)[0] if len(payload) >= 92 else 0
            in_cnt   = struct.unpack_from('<I', payload, 92)[0] if len(payload) >= 96 else 0
            out_off  = struct.unpack_from('<I', payload, 96)[0] if len(payload) >= 100 else 0
            out_cnt  = struct.unpack_from('<I', payload, 100)[0] if len(payload) >= 104 else 0
            max_in   = struct.unpack_from('<I', payload, 104)[0] if len(payload) >= 108 else 0
            max_out  = struct.unpack_from('<I', payload, 108)[0] if len(payload) >= 112 else 0
            ioctl_input = b''
            pipe_name = None
            if in_cnt and in_off and in_off + in_cnt <= len(payload):
                ioctl_input = payload[in_off:in_off + in_cnt]
                pipe_name = _extract_utf16_pipe_name(ioctl_input)
            if ctl_code == _FSCTL_VALIDATE_NEGOTIATE_INFO:
                trace(client_ip, 'smb2_validate_negotiate', dialect=hex(selected_dialect))
                send_nbss(client_sock, build_smb2_validate_negotiate_response(
                    hdr, session_id, hdr['tree_id'], selected_dialect))
            elif ctl_code == _FSCTL_PIPE_WAIT and pipe_name:
                trace(client_ip, 'smb2_pipe_wait',
                      pipe=pipe_name, input_count=in_cnt)
                _emit_knock(client_ip, user, 'IPC$', smb_version, domain, host,
                            smb_file=pipe_name, smb_action='REMOTE_COMMAND',
                            trace_stage='knock_emitted_remote_command')
                send_nbss(client_sock, build_smb2_ioctl_pipe_response(
                    hdr, session_id, hdr['tree_id'], ctl_code,
                    fid_pair or (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF), b''))
            elif ctl_code == _FSCTL_PIPE_TRANSCEIVE and fid_pair in pipe_fids:
                dcerpc  = payload[in_off:in_off + in_cnt]
                trace(client_ip, 'smb2_pipe_transceive',
                      fid=fid_pair[0], data_len=len(dcerpc))
                rpc_resp = _handle_dcerpc_multi(dcerpc, client_ip,
                                               user=user, smb_version=smb_version,
                                               smb_domain=domain, smb_host=host,
                                               pipe_name=pipe_fids[fid_pair].get('pipe', 'SRVSVC'),
                                               svc_handles=svc_handles)
                if rpc_resp:
                    send_nbss(client_sock, build_smb2_ioctl_pipe_response(
                        hdr, session_id, hdr['tree_id'], ctl_code, fid_pair, rpc_resp))
                else:
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))
            else:
                input_preview = None
                if in_cnt and in_off and in_off + min(in_cnt, 64) <= len(payload):
                    input_preview = payload[in_off:in_off + min(in_cnt, 64)].hex()
                trace(client_ip, 'smb2_ioctl',
                      ctl_code=hex(ctl_code), tree_id=hex(hdr['tree_id']),
                      fid=None if not fid_pair else fid_pair[0],
                      pipe=pipe_name,
                      input_offset=in_off, input_count=in_cnt,
                      output_offset=out_off, output_count=out_cnt,
                      max_input=max_in, max_output=max_out,
                      input_preview=input_preview)
                if ctl_code in (_FSCTL_PIPE_WAIT, _FSCTL_PIPE_TRANSCEIVE) and pipe_name:
                    _emit_knock(client_ip, user, 'IPC$', smb_version, domain, host,
                                smb_file=pipe_name, smb_action='REMOTE_COMMAND',
                                trace_stage='knock_emitted_remote_command')
                    send_nbss(client_sock, build_smb2_ioctl_pipe_response(
                        hdr, session_id, hdr['tree_id'], ctl_code,
                        fid_pair or (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF), b''))
                else:
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))

        # ── READ: pipe FID check must come before ipc_stub ───────────────────
        elif cmd == SMB2_READ:
            tree_id              = hdr['tree_id']
            offset, length, fid_pair = _parse_read_params(payload)
            # ── Pipe read (WRITE+READ DCERPC path) ───────────────────────────
            if fid_pair in pipe_fids:
                rpc_resp = pipe_fids[fid_pair]['pending']
                if rpc_resp:
                    pipe_fids[fid_pair]['pending'] = None
                    trace(client_ip, 'smb2_pipe_read',
                          fid=fid_pair[0], data_len=len(rpc_resp))
                    send_nbss(client_sock, build_smb2_read_response(
                        hdr, session_id, tree_id, rpc_resp))
                else:
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_END_OF_FILE, SMB2_READ))
                continue
            # ── Decoy file read ───────────────────────────────────────────────
            share_upper = decoy_trees.get(tree_id)
            if share_upper is None:
                trace(client_ip, 'smb2_read_denied', tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_READ))
                continue
            offset, length, fid_pair = _parse_read_params(payload)
            fh     = open_files.get(fid_pair)
            is_dir = fh is None or fh['is_dir']
            trace(client_ip, 'smb2_read', offset=offset, length=length, is_dir=is_dir)
            if is_dir:
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_READ))
            else:
                content = _overlay_get_content(
                    _DECOYS[fh['share']],
                    overlay_files.setdefault(fh['share'], {}),
                    fh['path'])
                chunk   = content[offset: offset + length]
                if not chunk:
                    trace(client_ip, 'smb2_read_eof', file=fh['path'], offset=offset)
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_END_OF_FILE, SMB2_READ))
                else:
                    # Always emit — reading a bait file is a high-value event
                    _emit_knock(client_ip, user, fh['share'], smb_version, domain, host,
                                smb_file=fh['path'], smb_action='READ',
                                trace_stage='knock_emitted_read')
                    trace(client_ip, 'smb2_read_ok',
                          file=fh['path'], offset=offset, bytes_returned=len(chunk))
                    send_nbss(client_sock, build_smb2_read_response(
                        hdr, session_id, tree_id, chunk))

        # ── WRITE: pipe FID check must come before ipc_stub ──────────────────
        elif cmd == SMB2_WRITE:
            tree_id  = hdr['tree_id']
            offset, data_length, fid_pair, write_data = _parse_write_params(payload)
            # ── Pipe write (WRITE+READ DCERPC path) ──────────────────────────
            if fid_pair in pipe_fids:
                dcerpc = write_data
                trace(client_ip, 'smb2_pipe_write',
                      fid=fid_pair[0], data_len=len(dcerpc))
                pipe_fids[fid_pair]['pending'] = _handle_dcerpc_multi(
                    dcerpc, client_ip, user=user, smb_version=smb_version,
                    smb_domain=domain, smb_host=host,
                    pipe_name=pipe_fids[fid_pair].get('pipe', 'SRVSVC'),
                    svc_handles=svc_handles)
                send_nbss(client_sock, build_smb2_write_response(
                    hdr, session_id, tree_id, data_length))
            elif tree_id in ipc_tree_ids:
                # Non-pipe write on IPC$ — stub, no knock
                trace(client_ip, 'smb2_ipc_stub', cmd=hex(cmd), tree_id=hex(tree_id))
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_NOT_SUPPORTED, cmd))
            else:
                # ── Decoy file write (overlay-backed) ───────────────────────
                share_upper = decoy_trees.get(tree_id)
                fh          = open_files.get(fid_pair)
                fname       = fh['path'] if fh else None
                write_share = share_upper or (fh['share'] if fh else None)
                trace(client_ip, 'smb2_write',
                      tree_id=hex(tree_id), fid=fid_pair[0],
                      file=fname, on_decoy=share_upper is not None)
                _emit_knock(client_ip, user, write_share, smb_version, domain, host,
                            smb_file=fname, smb_action='WRITE',
                            trace_stage='knock_emitted_write')
                if share_upper is None or fh is None or fh['is_dir'] or fname is None:
                    send_nbss(client_sock, build_smb2_error_response(
                        hdr, session_id, tree_id, STATUS_ACCESS_DENIED, SMB2_WRITE))
                else:
                    written = _overlay_write_file(
                        overlay_files.setdefault(fh['share'], {}),
                        fname,
                        offset,
                        write_data)
                    trace(client_ip, 'smb2_write_ok',
                          file=fname, offset=offset, bytes_written=written)
                    send_nbss(client_sock, build_smb2_write_response(
                        hdr, session_id, tree_id, written))

        # ── CLOSE: before IPC$ catch-all so pipe FID closes succeed ─────────
        elif cmd == SMB2_CLOSE:
            fid_pair = _parse_file_id_at(payload, 72)   # CLOSE: FileId at body+8 = abs 72
            if fid_pair in pipe_fids:
                pipe_fids.pop(fid_pair)
                trace(client_ip, 'smb2_pipe_close', fid=fid_pair[0])
            else:
                closed_fh = open_files.pop(fid_pair, None)
                if closed_fh and not closed_fh['is_dir']:
                    share = closed_fh['share']
                    path = closed_fh['path']
                    overlay_content = overlay_files.setdefault(share, {}).get(path)
                    if overlay_content:
                        qkey = (share, path)
                        qpath = _quarantine_overlay_file(
                            client_ip, smb_version, share, path, bytes(overlay_content))
                        if qpath:
                            quarantined_paths.add(qkey)
                            trace(client_ip, 'smb_quarantine_saved',
                                  smb_version=smb_version, share=share, file=path, saved_to=qpath)
                trace(client_ip, 'smb2_close',
                      fid=fid_pair[0], had_handle=closed_fh is not None,
                      file=closed_fh['path'] if closed_fh else None)
            send_nbss(client_sock, build_smb2_close_response(hdr, session_id, hdr['tree_id']))

        # ── TREE_DISCONNECT: remove tree, respond OK, keep session alive ──────
        elif cmd == SMB2_TREE_DISCONNECT:
            tid = hdr['tree_id']
            decoy_trees.pop(tid, None)
            ipc_tree_ids.discard(tid)
            trace(client_ip, 'smb2_tree_disconnect', tree_id=hex(tid))
            body = struct.pack('<HH', 4, 0)
            send_nbss(client_sock, build_smb2_response_header(
                SMB2_TREE_DISCONNECT, STATUS_SUCCESS, hdr['message_id'],
                session_id=session_id, tree_id=tid) + body)

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
            file_info_class, flags, fid_pair = _parse_query_directory_params(payload)
            fh       = open_files.get(fid_pair)
            restart  = bool(flags & 0x12)               # REOPEN(0x10) or RESTART_SCANS(0x02)
            if restart and fh:
                fh['listed'] = False
            dir_listed = fh['listed'] if fh else False
            dir_path   = fh['path'] if fh else ''
            trace(client_ip, 'smb2_query_dir', path=dir_path or '(root)',
                  listed=dir_listed, flags=hex(flags), file_info_class=file_info_class)
            if dir_listed:
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, tree_id, STATUS_NO_MORE_FILES, SMB2_QUERY_DIRECTORY))
            else:
                if fh:
                    fh['listed'] = True
                children  = _overlay_list_dir(
                    _DECOYS[share_upper],
                    overlay_files.setdefault(share_upper, {}),
                    dir_path)
                trace(client_ip, 'smb2_query_dir_result',
                      path=dir_path or '(root)',
                      entries=[(n, 'dir' if d else 'file') for n, _, d in children])
                _emit_knock(client_ip, user, share_upper, smb_version, domain, host,
                            smb_file=dir_path or None,
                            smb_action='DIR', trace_stage='knock_emitted_dir')
                send_nbss(client_sock, build_smb2_query_directory_response(
                    hdr, session_id, tree_id, children, file_info_class))

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
            is_dir   = fh is None or fh['is_dir']
            fsize    = 0 if is_dir else len(_overlay_get_content(
                _DECOYS[fh['share']],
                overlay_files.setdefault(fh['share'], {}),
                fh['path']))
            trace(client_ip, 'smb2_query_info',
                  info_type=info_type, file_info_class=file_info_class,
                  is_dir=is_dir, file=None if is_dir else fh['path'])
            send_nbss(client_sock, build_smb2_query_info_response(
                hdr, session_id, tree_id, info_type, file_info_class, is_dir,
                file_size=fsize, share_label=share_upper))

        elif cmd == SMB2_IOCTL:
            ctl_code = struct.unpack_from('<I', payload, 68)[0] if len(payload) >= 72 else 0
            fid_pair = _parse_file_id_at(payload, 72) if len(payload) >= 88 else None
            in_off   = struct.unpack_from('<I', payload, 88)[0] if len(payload) >= 92 else 0
            in_cnt   = struct.unpack_from('<I', payload, 92)[0] if len(payload) >= 96 else 0
            out_off  = struct.unpack_from('<I', payload, 96)[0] if len(payload) >= 100 else 0
            out_cnt  = struct.unpack_from('<I', payload, 100)[0] if len(payload) >= 104 else 0
            max_in   = struct.unpack_from('<I', payload, 104)[0] if len(payload) >= 108 else 0
            max_out  = struct.unpack_from('<I', payload, 108)[0] if len(payload) >= 112 else 0
            if ctl_code == _FSCTL_VALIDATE_NEGOTIATE_INFO:
                trace(client_ip, 'smb2_validate_negotiate', dialect=hex(selected_dialect))
                send_nbss(client_sock, build_smb2_validate_negotiate_response(
                    hdr, session_id, hdr['tree_id'], selected_dialect))
            else:
                input_preview = None
                if in_cnt and in_off and in_off + min(in_cnt, 64) <= len(payload):
                    input_preview = payload[in_off:in_off + min(in_cnt, 64)].hex()
                trace(client_ip, 'smb2_ioctl',
                      ctl_code=hex(ctl_code), tree_id=hex(hdr['tree_id']),
                      fid=None if not fid_pair else fid_pair[0],
                      input_offset=in_off, input_count=in_cnt,
                      output_offset=out_off, output_count=out_cnt,
                      max_input=max_in, max_output=max_out,
                      input_preview=input_preview)
                send_nbss(client_sock, build_smb2_error_response(
                    hdr, session_id, hdr['tree_id'], STATUS_NOT_SUPPORTED, SMB2_IOCTL))

        elif cmd == SMB2_LOGOFF:
            trace(client_ip, 'smb2_logoff')
            body = struct.pack('<HH', 4, 0)
            send_nbss(client_sock, build_smb2_response_header(
                SMB2_LOGOFF, STATUS_SUCCESS, hdr['message_id'],
                session_id=session_id) + body)
            # Brief drain: let the client read the response and close gracefully
            # before we close. Without this, socket.close() races the client's
            # worker thread reading the LOGOFF response.
            try:
                client_sock.settimeout(0.5)
                client_sock.recv(4096)
            except Exception:
                pass
            break

        else:
            trace(client_ip, 'smb2_unexpected_cmd',
                  command=hex(cmd), setup_round=setup_round)
            break

    if not got_auth and should_emit(client_ip, None, None, None, smb_version, None):
        _emit_knock(client_ip, None, None, smb_version, None, None,
                    smb_action='PROBE', trace_stage='knock_emitted_probe')
    for share, files in overlay_files.items():
        for path, content in files.items():
            if content and (share, path) not in quarantined_paths:
                qpath = _quarantine_overlay_file(client_ip, smb_version, share, path, bytes(content))
                if qpath:
                    trace(client_ip, 'smb_quarantine_saved',
                          smb_version=smb_version, share=share, file=path, saved_to=qpath)


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
    _smb2_post_negotiate(client_sock, client_ip, smb_version, selected_dialect)


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
    # NativeOS + NativeLanMan — UTF-16LE null-terminated, matching Windows Server 2019 banner
    native = (SMB_NATIVE_OS.encode('utf-16-le')      + b'\x00\x00'
            + SMB_NATIVE_LAN_MAN.encode('utf-16-le') + b'\x00\x00')
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
    native = (SMB_NATIVE_OS.encode('utf-16-le')      + b'\x00\x00'
            + SMB_NATIVE_LAN_MAN.encode('utf-16-le') + b'\x00\x00')
    body   = struct.pack('<B', 3) + params + struct.pack('<H', len(native)) + native
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
        if name_len & 1 or 84 + name_len > len(data):
            return ''
        fname = data[84:84 + name_len].decode('utf-16-le', errors='replace').strip('\x00')
    else:
        if 83 + name_len > len(data):
            return ''
        fname = data[83:83 + name_len].decode('latin-1', errors='replace').strip('\x00')
    return fname.replace('\\', '/').lstrip('/').strip()


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


def build_smb1_trans2_response(hdr, uid, tid, entries):
    """TRANS2 FIND_FIRST2 response listing the given (filename, size, is_dir) entries."""
    if not entries:
        return build_smb1_error_response(
            hdr, uid, tid, STATUS_NO_MORE_FILES, SMB1_COM_TRANSACTION2)
    ft_old = _smb2_filetime(time.time() - 86400 * 30)
    ft_now = _smb2_filetime()

    # FILE_BOTH_DIRECTORY_INFORMATION entries (same format as SMB2 QUERY_DIRECTORY)
    records = []
    for fname, size, is_dir in entries:
        name  = fname.encode('utf-16-le')
        alloc = 0 if is_dir else ((size + 4095) & ~4095)
        attrs = smb.ATTR_DIRECTORY if is_dir else smb.ATTR_NORMAL
        raw   = bytearray(
            struct.pack('<I', 0)              # NextEntryOffset (filled below)
            + struct.pack('<I', 0)            # FileIndex
            + struct.pack('<Q', ft_old)       # CreationTime
            + struct.pack('<Q', ft_now)       # LastAccessTime
            + struct.pack('<Q', ft_old)       # LastWriteTime
            + struct.pack('<Q', ft_old)       # ChangeTime
            + struct.pack('<Q', size)         # EndOfFile
            + struct.pack('<Q', alloc)        # AllocationSize
            + struct.pack('<I', attrs)        # FileAttributes
            + struct.pack('<I', len(name))    # FileNameLength
            + struct.pack('<I', 0)            # EaSize
            + struct.pack('<B', 0)            # ShortNameLength
            + struct.pack('<B', 0)            # Reserved
            + b'\x00' * 24                    # ShortName[24]
            + name
        )
        if len(raw) % 8:
            raw += b'\x00' * (8 - len(raw) % 8)
        records.append(raw)
    for i in range(len(records) - 1):
        struct.pack_into('<I', records[i], 0, len(records[i]))
    data_buf = b''.join(records)

    # FIND_FIRST2 response parameters (12 bytes)
    sid    = (int.from_bytes(os.urandom(2), 'little') or 1)
    params = (struct.pack('<H', sid)              # SearchHandle
              + struct.pack('<H', len(entries))   # SearchCount
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


def _smb1_parse_write_andx(data):
    """Extract (fid, offset, write_mode, payload_bytes) from a WRITE_ANDX request."""
    if len(data) < 61:
        return 0, 0, 0, b''
    fid       = struct.unpack_from('<H', data, 37)[0]
    offset    = struct.unpack_from('<I', data, 39)[0]
    write_mode = struct.unpack_from('<H', data, 47)[0]
    data_cnt  = struct.unpack_from('<H', data, 53)[0]
    data_off  = struct.unpack_from('<H', data, 55)[0]
    if not data_cnt or data_off < 32 or data_off + data_cnt > len(data):
        return fid, offset, write_mode, b''
    payload = data[data_off:data_off + data_cnt]
    # SMB1 named-pipe writes commonly prefix the first fragment with 0xFFFF.
    if payload.startswith(b'\xff\xff'):
        payload = payload[2:]
    return fid, offset, write_mode, payload


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


def build_smb1_empty_success_response(hdr, uid, tid, command):
    """WordCount=0 SMB1 success response for simple teardown commands."""
    body   = struct.pack('<B', 0) + struct.pack('<H', 0)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        command, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def build_smb1_logoff_andx_response(hdr, uid, tid):
    """LOGOFF_ANDX success response with no chained command."""
    params = (
        struct.pack('<B', 0xFF)
        + struct.pack('<B', 0)
        + struct.pack('<H', 0)
    )
    body   = struct.pack('<B', 2) + params + struct.pack('<H', 0)
    flags2 = hdr['flags2'] | SMB1_FLAGS2_UNICODE
    return build_smb1_response_header(
        SMB1_COM_LOGOFF_ANDX, STATUS_SUCCESS, flags2,
        uid=uid, tid=tid, mid=hdr['mid'],
    ) + body


def _smb1_parse_transaction(payload, flags2):
    """
    Parse an SMB1 TRANSACTION (0x25) request.
    Returns a metadata dict with:
      pipe_name: normalized upper-case pipe name or None
      pipe_raw: raw decoded name field
      dcerpc: extracted Data section bytes
      setup_count / param_count / param_offset / data_count / data_offset
      setup_preview / param_preview / data_preview
    pipe_name_upper: last path component of the Name field (e.g. 'SRVSVC'), or None.
    dcerpc_bytes: raw Data section bytes (may be empty).
    Returns None on parse failure.

    Layout after 32-byte SMB1 header:
      [32]    WordCount
      [33-54] Fixed parameter words (always present regardless of SetupCount)
      [55-56] DataCount
      [57-58] DataOffset  ← offset from start of SMB header into payload
      [59]    SetupCount
      [60]    Reserved
      [61+]   Setup[0..SetupCount-1] words
      [32+1+WordCount*2]    ByteCount (2 bytes)
      [32+1+WordCount*2+2]  Name field (null-terminated, ASCII or UTF-16LE)
    """
    if len(payload) < 60:
        return None
    try:
        wc          = payload[32]
        setup_count = payload[59]
        param_count = struct.unpack_from('<H', payload, 51)[0]
        param_offset = struct.unpack_from('<H', payload, 53)[0]
        data_count  = struct.unpack_from('<H', payload, 55)[0]
        data_offset = struct.unpack_from('<H', payload, 57)[0]

        # ByteCount is right after the Setup words
        bc_off     = 32 + 1 + wc * 2
        if len(payload) < bc_off + 2:
            return None

        # Name field follows ByteCount; align to 2-byte boundary for Unicode
        name_start = bc_off + 2
        pipe_name  = None
        pipe_raw   = None
        if name_start < len(payload):
            if flags2 & SMB1_FLAGS2_UNICODE:
                if name_start % 2 != 0:
                    name_start += 1
                end = name_start
                while end + 1 < len(payload):
                    if payload[end] == 0 and payload[end + 1] == 0:
                        break
                    end += 2
                raw = payload[name_start:end].decode('utf-16-le', errors='replace')
            else:
                nul = payload.find(b'\x00', name_start)
                raw = payload[name_start:nul if nul != -1 else len(payload)].decode(
                    'ascii', errors='replace')
            pipe_raw = raw
            # Last path component: '\PIPE\srvsvc' → 'SRVSVC', '\PIPE\' → None
            parts     = [p for p in raw.replace('/', '\\').split('\\') if p]
            # Drop leading 'PIPE' namespace component; remainder is the pipe name
            if parts and parts[0].upper() == 'PIPE':
                parts = parts[1:]
            pipe_name = parts[0].upper() if parts else None

        dcerpc = b''
        if data_count > 0 and data_offset + data_count <= len(payload):
            dcerpc = payload[data_offset:data_offset + data_count]
        setup_preview = None
        setup_off = 61
        setup_len = setup_count * 2
        if setup_count and setup_off + setup_len <= len(payload):
            setup_preview = payload[setup_off:setup_off + min(setup_len, 24)].hex()
        param_preview = None
        if param_count and param_offset and param_offset + param_count <= len(payload):
            param_preview = payload[param_offset:param_offset + min(param_count, 24)].hex()
        data_preview = dcerpc[:24].hex() if dcerpc else None

        return {
            'pipe_name': pipe_name,
            'pipe_raw': pipe_raw,
            'dcerpc': dcerpc,
            'setup_count': setup_count,
            'param_count': param_count,
            'param_offset': param_offset,
            'data_count': data_count,
            'data_offset': data_offset,
            'setup_preview': setup_preview,
            'param_preview': param_preview,
            'data_preview': data_preview,
        }
    except Exception:
        return None


def _smb1_parse_find_first2(payload, flags2):
    """Parse SMB1 TRANS2_FIND_FIRST2 and return (dir_path, pattern, info_level)."""
    if len(payload) < 61:
        return None, None, None
    try:
        param_count  = struct.unpack_from('<H', payload, 51)[0]
        param_offset = struct.unpack_from('<H', payload, 53)[0]
        if not param_count or not param_offset or param_offset + param_count > len(payload):
            return None, None, None
        params = payload[param_offset:param_offset + param_count]
        req = smb.SMBFindFirst2_Parameters(flags=flags2, data=params)
        raw_name = req['FileName']
        if isinstance(raw_name, bytes):
            encoding = 'utf-16-le' if flags2 & SMB1_FLAGS2_UNICODE else 'cp437'
            search = raw_name.decode(encoding, errors='ignore').rstrip('\x00')
        else:
            search = str(raw_name).rstrip('\x00')
        search = search.replace('\\', '/').lstrip('/')
        if not search:
            search = '*'
        if '/' in search:
            dir_path, pattern = search.rsplit('/', 1)
        else:
            dir_path, pattern = '', search
        dir_parts = []
        for part in dir_path.split('/'):
            if not part or part == '.':
                continue
            if part == '..':
                return None, None, None
            dir_parts.append(part)
        pattern = (pattern or '*').strip()
        if not pattern or len(pattern) > 255:
            return None, None, None
        return '/'.join(dir_parts), pattern, req['InformationLevel']
    except Exception:
        return None, None, None


def _smb1_parse_transaction2_meta(payload):
    """Parse basic SMB1 TRANSACTION2 metadata for logging/debugging."""
    if len(payload) < 63:
        return None
    try:
        setup_count = payload[59]
        param_count = struct.unpack_from('<H', payload, 51)[0]
        param_offset = struct.unpack_from('<H', payload, 53)[0]
        data_count = struct.unpack_from('<H', payload, 55)[0]
        data_offset = struct.unpack_from('<H', payload, 57)[0]
        subcommand = None
        if setup_count >= 1 and len(payload) >= 63:
            subcommand = struct.unpack_from('<H', payload, 61)[0]
        param_preview = None
        if param_count and param_offset and param_offset + param_count <= len(payload):
            params = payload[param_offset:param_offset + min(param_count, 24)]
            param_preview = params.hex()
        return {
            'setup_count': setup_count,
            'subcommand': subcommand,
            'param_count': param_count,
            'param_offset': param_offset,
            'data_count': data_count,
            'data_offset': data_offset,
            'param_preview': param_preview,
        }
    except Exception:
        return None


def build_smb1_transaction_response(hdr, uid, tid, flags2, dcerpc_data):
    """
    SMB1 TRANSACTION success response carrying dcerpc_data as the response Data section.
    WordCount=10, no parameters, data starts at offset 55 (32+1+20+2).
    """
    n     = len(dcerpc_data)
    words = (
        struct.pack('<H', 0)      # TotalParameterCount
        + struct.pack('<H', n)    # TotalDataCount
        + struct.pack('<H', 0)    # Reserved
        + struct.pack('<H', 0)    # ParameterCount
        + struct.pack('<H', 55)   # ParameterOffset (no params, but offset must be valid)
        + struct.pack('<H', 0)    # ParameterDisplacement
        + struct.pack('<H', n)    # DataCount
        + struct.pack('<H', 55)   # DataOffset = 32+1+20+2 = 55
        + struct.pack('<H', 0)    # DataDisplacement
        + struct.pack('<BB', 0, 0)  # SetupCount=0, Reserved
    )
    body = struct.pack('<B', 10) + words + struct.pack('<H', n) + dcerpc_data
    return build_smb1_response_header(
        SMB1_COM_TRANSACTION, STATUS_SUCCESS, flags2, uid=uid, tid=tid, mid=hdr['mid'],
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
        _smb2_post_negotiate(client_sock, client_ip, 'SMB2', 0x0210)
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
    overlay_files = {}   # {share_upper: {share_relative_path: bytearray}}
    quarantined_paths = set()  # {(share_upper, share_relative_path)}
    pipe_fids    = {}    # {fid(int): {'pending': bytes|None, 'pipe': str}} for IPC named pipe handles
    svc_handles  = {}    # {handle_bytes: (svc_name, bin_path)} — maps fake SVCCTL handles to service info
    next_fid     = 1
    got_auth     = False

    for _ in range(_MAX_MSG - 1):
        try:
            payload = recv_nbss(client_sock)
        except Exception as e:
            trace(client_ip, 'smb1_recv_error', error=f'{type(e).__name__}: {e}')
            break
        hdr = parse_smb1_header(payload)
        if not hdr:
            trace(client_ip, 'smb1_bad_header')
            break

        cmd    = hdr['command']
        flags2 = hdr['flags2']
        trace(client_ip, 'smb1_recv', cmd=hex(cmd), payload_len=len(payload))

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
                    _emit_knock(client_ip, user, None, 'SMB1', domain, host,
                                smb_action='AUTH', trace_stage='knock_emitted_auth')
                    got_auth = True
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
                _emit_knock(client_ip, user, None, 'SMB1', domain, None,
                            smb_action='AUTH', trace_stage='knock_emitted_auth')
                got_auth = True
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
            if should_emit(client_ip, user, domain, host, 'SMB1', share):
                _emit_knock(client_ip, user, share, 'SMB1', domain, host,
                            smb_action='CONNECT', trace_stage='knock_emitted_tree')
            else:
                trace(client_ip, 'knock_dedup', user=user, share=share,
                      smb_version='SMB1')
            send_nbss(client_sock, build_smb1_tree_connect_ok_response(hdr, new_tid, share_upper))

        # ── IPC$ and other non-decoy trees ───────────────────────────────────
        elif hdr['tid'] in ipc_tree_ids:
            tid = hdr['tid']
            if cmd == SMB1_COM_NT_CREATE_ANDX:
                # Accept any known IPC named pipe; reject everything else on IPC$
                name      = _smb1_parse_nt_create(payload, flags2)
                pipe_name = (name or '').split('\\')[-1].upper()
                if pipe_name in _KNOWN_PIPES:
                    fid = next_fid; next_fid += 1
                    pipe_fids[fid] = {'pending': None, 'pipe': pipe_name}
                    trace(client_ip, 'pipe_open', pipe=pipe_name, fid=fid)
                    send_nbss(client_sock, build_smb1_nt_create_response(
                        hdr, uid, tid, fid, False, 0))
                else:
                    trace(client_ip, 'smb1_ipc_create_unknown',
                          name=(name or '').split('\\')[-1])
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_OBJECT_NAME_NOT_FOUND, SMB1_COM_NT_CREATE_ANDX))
            elif cmd == SMB1_COM_WRITE_ANDX:
                # DCERPC write on pipe — process and cache response for next READ
                fid, write_offset, write_mode, dcerpc = _smb1_parse_write_andx(payload)
                if fid in pipe_fids:
                    trace(client_ip, 'smb1_pipe_write', fid=fid, data_len=len(dcerpc),
                          write_mode=hex(write_mode), offset=write_offset)
                    pipe_fids[fid]['pending'] = _handle_dcerpc_multi(dcerpc, client_ip,
                                                                    user=user, smb_version='SMB1',
                                                                    smb_domain=domain, smb_host=host,
                                                                    pipe_name=pipe_fids[fid].get('pipe', 'SRVSVC'),
                                                                    svc_handles=svc_handles)
                    # Acknowledge the write
                    ack_body = (struct.pack('<B', 6)        # WC=6
                                + struct.pack('<B', 0xFF)   # AndXCmd=none
                                + struct.pack('<B', 0)      # AndXRsvd
                                + struct.pack('<H', 0)      # AndXOff
                                + struct.pack('<H', len(dcerpc))  # Count
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
            elif cmd == SMB1_COM_TRANSACTION:
                # Direct named-pipe transact: DCERPC bundled in one request/response.
                # Scanners that skip NT_CREATE_ANDX use this path to call NetrShareEnum.
                txn_meta = _smb1_parse_transaction(payload, flags2) or {}
                pipe_name = txn_meta.get('pipe_name')
                dcerpc = txn_meta.get('dcerpc')
                trace(client_ip, 'smb1_transaction', pipe=pipe_name,
                      pipe_raw=txn_meta.get('pipe_raw'),
                      data_len=len(dcerpc) if dcerpc else 0,
                      setup_count=txn_meta.get('setup_count'),
                      param_count=txn_meta.get('param_count'),
                      param_offset=txn_meta.get('param_offset'),
                      data_count=txn_meta.get('data_count'),
                      data_offset=txn_meta.get('data_offset'),
                      setup_preview=txn_meta.get('setup_preview'),
                      param_preview=txn_meta.get('param_preview'),
                      data_preview=txn_meta.get('data_preview'))
                rpc_resp = None
                if pipe_name in _KNOWN_PIPES and dcerpc:
                    rpc_resp = _handle_dcerpc_multi(dcerpc, client_ip, user=user,
                                                   smb_version='SMB1',
                                                   smb_domain=domain, smb_host=host,
                                                   pipe_name=pipe_name,
                                                   svc_handles=svc_handles)
                if rpc_resp:
                    send_nbss(client_sock, build_smb1_transaction_response(
                        hdr, uid, tid, flags2, rpc_resp))
                elif not pipe_name:
                    # Empty pipe name after stripping '\PIPE\' — Samba returns
                    # STATUS_INVALID_PARAMETER (setup_count check fails on empty name)
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_INVALID_PARAMETER, cmd))
                elif pipe_name not in _KNOWN_PIPES:
                    # Unrecognised pipe name → STATUS_OBJECT_NAME_NOT_FOUND
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_OBJECT_NAME_NOT_FOUND, cmd))
                else:
                    send_nbss(client_sock, build_smb1_error_response(
                        hdr, uid, tid, STATUS_NOT_SUPPORTED, cmd))
            elif cmd == SMB1_COM_TRANSACTION2:
                meta = _smb1_parse_transaction2_meta(payload) or {}
                subcommand = meta.get('subcommand')
                trace(client_ip, 'smb1_ipc_trans2',
                      subcommand=(hex(subcommand) if subcommand is not None else None),
                      subcommand_name=_SMB1_TRANS2_NAMES.get(subcommand, 'UNKNOWN'),
                      setup_count=meta.get('setup_count'),
                      param_count=meta.get('param_count'),
                      param_offset=meta.get('param_offset'),
                      data_count=meta.get('data_count'),
                      data_offset=meta.get('data_offset'),
                      param_preview=meta.get('param_preview'))
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_IMPLEMENTED, cmd))
            else:
                trace(client_ip, 'smb1_ipc_stub', cmd=hex(cmd))
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_IMPLEMENTED, cmd))

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
            share_overlay = overlay_files.setdefault(share_upper, {})
            if not clean:
                _emit_knock(client_ip, user, share_upper, 'SMB1', domain, host,
                            smb_file=clean, smb_action='OPEN_DIR',
                            trace_stage='knock_emitted_create')
                fid = next_fid; next_fid += 1
                open_files[fid] = {'share': share_upper, 'filename': None}
                trace(client_ip, 'smb1_create', name='', fid=fid, is_dir=True)
                send_nbss(client_sock, build_smb1_nt_create_response(
                    hdr, uid, tid, fid, True, 0))
            else:
                kind = _overlay_resolve_path(share_files, share_overlay, clean)
                disposition = (struct.unpack_from('<I', payload, 68)[0]
                               if len(payload) >= 72 else _SMB2_CREATE_DISP_FILE_OPEN)
                create_action = _classify_create_action(kind, disposition, clean)
                _emit_knock(client_ip, user, share_upper, 'SMB1', domain, host,
                            smb_file=clean, smb_action=create_action,
                            trace_stage='knock_emitted_create')
                if kind == 'file':
                    fid = next_fid; next_fid += 1
                    open_files[fid] = {'share': share_upper, 'filename': clean}
                    trace(client_ip, 'smb1_create', name=clean, fid=fid, is_dir=False)
                    send_nbss(client_sock, build_smb1_nt_create_response(
                        hdr, uid, tid, fid, False,
                        len(_overlay_get_content(share_files, share_overlay, clean))))
                elif kind == 'dir':
                    fid = next_fid; next_fid += 1
                    open_files[fid] = {'share': share_upper, 'filename': clean}
                    trace(client_ip, 'smb1_create', name=clean, fid=fid, is_dir=True)
                    send_nbss(client_sock, build_smb1_nt_create_response(
                        hdr, uid, tid, fid, True, 0))
                else:
                    # CreateDisposition at params[35] = payload[68]
                    if disposition != _SMB2_CREATE_DISP_FILE_OPEN:
                        share_overlay.setdefault(clean, bytearray())
                        fid = next_fid; next_fid += 1
                        open_files[fid] = {'share': share_upper, 'filename': clean}
                        trace(client_ip, 'smb1_create', name=clean, fid=fid,
                              is_dir=False, result='created_overlay')
                        send_nbss(client_sock, build_smb1_nt_create_response(
                            hdr, uid, tid, fid, False, 0))
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
            dir_path, pattern, info_level = _smb1_parse_find_first2(payload, flags2)
            if info_level != smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                trace(client_ip, 'smb1_trans2_find_first2',
                      share=share_upper, path=dir_path, pattern=pattern,
                      info_level=info_level, result='unsupported_info_level')
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NOT_SUPPORTED, SMB1_COM_TRANSACTION2))
                continue
            if dir_path is None or _overlay_resolve_path(
                    _DECOYS[share_upper],
                    overlay_files.setdefault(share_upper, {}),
                    dir_path) != 'dir':
                trace(client_ip, 'smb1_trans2_find_first2',
                      share=share_upper, path=dir_path, pattern=pattern,
                      info_level=info_level, result='dir_not_found')
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_NO_SUCH_FILE, SMB1_COM_TRANSACTION2))
                continue
            file_list = [
                (name, size, is_dir)
                for name, size, is_dir in _overlay_list_dir(
                    _DECOYS[share_upper],
                    overlay_files.setdefault(share_upper, {}),
                    dir_path)
                if fnmatch.fnmatchcase(name, pattern)
            ]
            trace(client_ip, 'smb1_trans2_find_first2',
                  share=share_upper, path=dir_path, pattern=pattern,
                  info_level=info_level, count=len(file_list),
                  files=[fn for fn, _, _ in file_list])
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
                content = _overlay_get_content(
                    _DECOYS[fh['share']],
                    overlay_files.setdefault(fh['share'], {}),
                    fh['filename'])
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
            if share_upper is None or fh is None or fname is None:
                send_nbss(client_sock, build_smb1_error_response(
                    hdr, uid, tid, STATUS_ACCESS_DENIED, SMB1_COM_WRITE_ANDX))
            else:
                _fid, write_offset, _write_mode, write_data = _smb1_parse_write_andx(payload)
                written = _overlay_write_file(
                    overlay_files.setdefault(fh['share'], {}),
                    fname,
                    write_offset,
                    write_data)
                trace(client_ip, 'smb1_write_ok', file=fname,
                      offset=write_offset, bytes_written=written)
                ack_body = (
                    struct.pack('<B', 6)
                    + struct.pack('<B', 0xFF)
                    + struct.pack('<B', 0)
                    + struct.pack('<H', 0)
                    + struct.pack('<H', written)
                    + struct.pack('<H', 0)
                    + struct.pack('<I', 0)
                    + struct.pack('<H', 0)
                )
                send_nbss(client_sock,
                          build_smb1_response_header(SMB1_COM_WRITE_ANDX, STATUS_SUCCESS,
                                                     flags2, uid=uid, tid=tid)
                          + ack_body)

        # ── COM_CLOSE ─────────────────────────────────────────────────────────
        elif cmd == SMB1_COM_CLOSE:
            fid = _smb1_parse_close(payload)
            closed_fh = open_files.pop(fid, None)
            if closed_fh and closed_fh['filename'] is not None:
                share = closed_fh['share']
                path = closed_fh['filename']
                overlay_content = overlay_files.setdefault(share, {}).get(path)
                if overlay_content:
                    qkey = (share, path)
                    qpath = _quarantine_overlay_file(
                        client_ip, 'SMB1', share, path, bytes(overlay_content))
                    if qpath:
                        quarantined_paths.add(qkey)
                        trace(client_ip, 'smb_quarantine_saved',
                              smb_version='SMB1', share=share, file=path, saved_to=qpath)
            trace(client_ip, 'smb1_close', fid=fid,
                  had_handle=closed_fh is not None,
                  file=closed_fh['filename'] if closed_fh else None)
            send_nbss(client_sock, build_smb1_close_response(hdr, uid, hdr['tid']))

        elif cmd == SMB1_COM_TREE_DISCONNECT:
            old_tid = hdr['tid']
            decoy_trees.pop(old_tid, None)
            trace(client_ip, 'smb1_tree_disconnect', tid=hex(old_tid))
            send_nbss(client_sock, build_smb1_empty_success_response(
                hdr, uid, old_tid, SMB1_COM_TREE_DISCONNECT))

        elif cmd == SMB1_COM_LOGOFF_ANDX:
            trace(client_ip, 'smb1_logoff')
            send_nbss(client_sock, build_smb1_logoff_andx_response(
                hdr, uid, hdr['tid']))
            break

        else:
            trace(client_ip, 'smb1_unexpected_cmd',
                  command=hex(cmd), setup_round=setup_round)
            break

    if not got_auth and should_emit(client_ip, None, None, None, 'SMB1', None):
        _emit_knock(client_ip, None, None, 'SMB1', None, None,
                    smb_action='PROBE', trace_stage='knock_emitted_probe')
    for share, files in overlay_files.items():
        for path, content in files.items():
            if content and (share, path) not in quarantined_paths:
                qpath = _quarantine_overlay_file(client_ip, 'SMB1', share, path, bytes(content))
                if qpath:
                    trace(client_ip, 'smb_quarantine_saved',
                          smb_version='SMB1', share=share, file=path, saved_to=qpath)


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

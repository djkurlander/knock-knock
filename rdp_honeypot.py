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

from impacket import ntlm

BLOCKLIST_FILE = os.environ.get('DB_DIR', 'data') + '/blocklist.txt'
BLOCKLIST_RELOAD_INTERVAL = 60
CERT_FILE = os.environ.get('DB_DIR', 'data') + '/rdp.crt'
KEY_FILE  = os.environ.get('DB_DIR', 'data') + '/rdp.key'

_blocklist_cache = set()
_blocklist_last_load = 0

def get_blocklist():
    global _blocklist_cache, _blocklist_last_load
    now = time.time()
    if now - _blocklist_last_load > BLOCKLIST_RELOAD_INTERVAL:
        _blocklist_last_load = now
        if os.path.exists(BLOCKLIST_FILE):
            try:
                with open(BLOCKLIST_FILE, 'r') as f:
                    _blocklist_cache = set(
                        line.split('#')[0].strip() for line in f
                        if line.split('#')[0].strip()
                    )
            except Exception:
                pass
    return _blocklist_cache

def ensure_cert():
    """Generate a self-signed cert for TLS if not already present."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    subprocess.run([
        'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', KEY_FILE, '-x509', '-days', '3650',
        '-out', CERT_FILE,
        '-subj', '/CN=DESKTOP-RDP/O=Microsoft/C=US'
    ], capture_output=True)

# --- X.224 / TPKT helpers ---

# X.224 Connection Confirm with SSL (PROTOCOL_SSL = 0x00000001) selected
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
    0x01, 0x00, 0x00, 0x00,   # selectedProtocol=PROTOCOL_SSL
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

# --- NTLM challenge (Type 2) builder ---

def build_ntlm_challenge():
    """Build a minimal NTLMSSP CHALLENGE (Type 2) message manually."""
    domain = 'WORKGROUP'.encode('utf-16-le')

    # TargetInfo AV pairs: MsvAvNbDomainName (id=2) + MsvAvEOL (id=0)
    target_info  = struct.pack('<HH', 2, len(domain)) + domain
    target_info += struct.pack('<HH', 0, 0)

    flags = (
        0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
        0x00000004 |  # NTLMSSP_REQUEST_TARGET
        0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
        0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0x00020000 |  # NTLMSSP_TARGET_TYPE_DOMAIN
        0x00200000 |  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x00800000 |  # NTLMSSP_NEGOTIATE_TARGET_INFO
        0x20000000 |  # NTLMSSP_NEGOTIATE_128
        0x80000000    # NTLMSSP_NEGOTIATE_56
    )

    # Fixed header without version = 48 bytes
    domain_offset      = 48
    target_info_offset = domain_offset + len(domain)

    msg  = b'NTLMSSP\x00'                                              # Signature
    msg += struct.pack('<I', 2)                                        # MessageType=2
    msg += struct.pack('<HHI', len(domain), len(domain), domain_offset)  # TargetNameFields
    msg += struct.pack('<I', flags)                                    # NegotiateFlags
    msg += os.urandom(8)                                               # ServerChallenge
    msg += b'\x00' * 8                                                 # Reserved
    msg += struct.pack('<HHI',
                       len(target_info), len(target_info), target_info_offset)  # TargetInfoFields
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

def do_nla(raw_sock):
    """
    Complete the NLA/CredSSP handshake and return (username, domain).
    Returns (None, None) if handshake fails or no credentials captured.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        tls = ctx.wrap_socket(raw_sock, server_side=True)
    except ssl.SSLError:
        return None, None

    try:
        tls.settimeout(15)

        # Step 1: receive TSRequest with NTLM NEGOTIATE (Type 1)
        data = tls.recv(4096)
        if not find_ntlmssp(data):
            return None, None

        # Step 2: send TSRequest with NTLM CHALLENGE (Type 2)
        challenge_bytes = build_ntlm_challenge()
        tls.sendall(build_tsrequest(challenge_bytes))

        # Step 3: receive TSRequest with NTLM AUTHENTICATE (Type 3)
        data = tls.recv(4096)
        ntlm_auth = find_ntlmssp(data)
        if not ntlm_auth:
            return None, None

        return parse_ntlm_authenticate(ntlm_auth)

    except Exception:
        return None, None
    finally:
        try:
            tls.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

# --- Connection handler ---

def handle_connection(client_sock, client_ip):
    try:
        print(f"🔌 RDP connect {client_ip}", flush=True)

        # Read X.224 Connection Request
        data = read_x224_packet(client_sock)
        if not data:
            return

        # Fast path: cookie-based username (older clients)
        cookie_user, cookie_domain = extract_cookie_username(data)
        if cookie_user:
            knock = {"type": "KNOCK", "proto": "RDP",
                     "ip": client_ip, "user": cookie_user, "pass": cookie_domain or ''}
            print(json.dumps(knock), flush=True)
            return

        # Check if client requested SSL/TLS (NLA bots always do)
        # RDP_NEG_REQ is at byte offset 11 in X.224 CR (after TPKT+X.224 header)
        # requestedProtocols at offset 15, bit 0 = PROTOCOL_SSL
        if len(data) >= 19:
            req_protocols = struct.unpack_from('<I', data, 15)[0] if len(data) >= 19 else 0
            if not (req_protocols & 0x01):
                return  # client doesn't want SSL, nothing more we can do

        # Send X.224 CC selecting SSL
        client_sock.sendall(X224_CC_SSL)

        # NLA handshake
        username, domain = do_nla(client_sock)
        if username:
            knock = {"type": "KNOCK", "proto": "RDP",
                     "ip": client_ip, "user": username, "pass": domain or ''}
            print(json.dumps(knock), flush=True)

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

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
        if client_ip in get_blocklist():
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

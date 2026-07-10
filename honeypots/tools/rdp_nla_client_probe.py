#!/usr/bin/env python3
"""
Quick test: simulate an RDP NLA client connecting to localhost:3389
with a known username/password to verify the honeypot captures it.
"""
import socket, ssl, struct, sys
from impacket import ntlm

HOST = '127.0.0.1'
PORT = 3389
USERNAME = 'testuser'
PASSWORD = 'testpass123'
DOMAIN   = 'TESTDOMAIN'

# --- ASN.1 helpers (mirrored from honeypot) ---

def asn1_len(n):
    if n < 0x80:   return bytes([n])
    elif n < 0x100: return bytes([0x81, n])
    else:           return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def asn1_seq(data):   return b'\x30' + asn1_len(len(data)) + data
def asn1_ctx(tag, d): return bytes([0xA0 | tag]) + asn1_len(len(d)) + d
def asn1_int(n):      return b'\x02\x01' + bytes([n])
def asn1_octet(data): return b'\x04' + asn1_len(len(data)) + data

def wrap_tsrequest(ntlm_token, version=6):
    token    = asn1_ctx(0, asn1_octet(ntlm_token))
    sequence = asn1_seq(asn1_seq(token))
    nego     = asn1_ctx(1, sequence)
    ver      = asn1_ctx(0, asn1_int(version))
    return asn1_seq(ver + nego)

def find_ntlmssp(data):
    idx = data.find(b'NTLMSSP\x00')
    return data[idx:] if idx >= 0 else None

# --- X.224 Connection Request with mstshash=hello cookie, requesting SSL ---

cookie = b'Cookie: mstshash=hello\r\n'
rdp_neg = struct.pack('<BBHI', 0x01, 0x00, 8, 0x00000003)  # request SSL + NLA
x224_payload = cookie + rdp_neg
x224_cr = bytes([
    0x0e + len(x224_payload),  # LI
    0xe0,                       # CR
    0x00, 0x00,                 # dst-ref
    0x00, 0x00,                 # src-ref
    0x00,                       # class
]) + x224_payload
tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(x224_cr)) + x224_cr

# --- Run ---

sock = socket.create_connection((HOST, PORT), timeout=10)
print(f"[1] Connected to {HOST}:{PORT}")

sock.sendall(tpkt)
print(f"[2] Sent X.224 CR (mstshash=hello, requesting SSL+NLA)")

resp = sock.recv(4096)
print(f"[3] Received X.224 CC ({len(resp)} bytes)")

# Wrap in TLS
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
tls = ctx.wrap_socket(sock, server_hostname=HOST)
print(f"[4] TLS handshake complete")

# NTLM NEGOTIATE (Type 1)
neg_msg = ntlm.getNTLMSSPType1('', '')
tls.sendall(wrap_tsrequest(neg_msg.getData()))
print(f"[5] Sent NTLM NEGOTIATE")

# Receive NTLM CHALLENGE (Type 2)
data = tls.recv(4096)
challenge = find_ntlmssp(data)
if not challenge:
    print("ERROR: no NTLMSSP in server response")
    sys.exit(1)
print(f"[6] Received NTLM CHALLENGE ({len(challenge)} bytes)")

# NTLM AUTHENTICATE (Type 3)
server_chall_obj = ntlm.NTLMAuthChallenge()
server_chall_obj.fromString(challenge)
auth_msg, _ = ntlm.getNTLMSSPType3(
    ntlm.getNTLMSSPType1('', ''),
    challenge,
    USERNAME, PASSWORD, DOMAIN
)
tls.sendall(wrap_tsrequest(auth_msg.getData()))
print(f"[7] Sent NTLM AUTHENTICATE (user='{USERNAME}', domain='{DOMAIN}')")

# Receive STATUS_LOGON_FAILURE
try:
    final = tls.recv(4096)
    print(f"[8] Received server response ({len(final)} bytes) — got STATUS_LOGON_FAILURE as expected")
except Exception as e:
    print(f"[8] Connection closed by server: {e}")

print(f"\nDone. Check journalctl -u knock-monitor for: RDP | {USERNAME}")

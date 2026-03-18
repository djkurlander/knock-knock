"""
rdp_classic_security.py — Classic (non-NLA) RDP Security handshake for knock-knock.

Implements enough of the MS-RDPBCGR connection sequence to extract plaintext
credentials from legacy RDP clients that don't support NLA/CredSSP.

Protocol flow handled:
  1. X.224 CC (already sent by caller, selecting PROTOCOL_RDP = 0)
  2. MCS Connect Initial  ← recv from client  (contains GCC CR with client security data)
  3. MCS Connect Response → send to client     (contains server random + RSA public key)
  4. MCS Erect Domain     ← recv
  5. MCS Attach User Req  ← recv
  6. MCS Attach User Conf → send
  7. MCS Channel Join Req ← recv  (user channel)
  8. MCS Channel Join Conf→ send
  9. MCS Channel Join Req ← recv  (I/O channel)
  10. MCS Channel Join Conf→ send
  11. Security Exchange PDU ← recv (encrypted client random → RSA decrypt)
  12. Client Info PDU       ← recv (RC4-encrypted, contains plaintext username+password)

References:
  [MS-RDPBCGR] sections 1.3.1.1, 2.2.1.3–2.2.1.11, 5.3.4, 5.3.5
"""

import struct
import hashlib
import os
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# RSA key pair — generated once at module load, kept in memory.
# Modern cryptography backends enforce >=1024-bit keys.
# ---------------------------------------------------------------------------

RSA_KEY_BITS = max(1024, int(os.environ.get('RDP_CLASSIC_RSA_BITS', '1024')))
CLASSIC_PRESEC_MAX_PDUS = max(8, int(os.environ.get('RDP_CLASSIC_PRESEC_MAX_PDUS', '36')))
CLASSIC_PRESEC_RECV_TIMEOUT = max(2.0, float(os.environ.get('RDP_CLASSIC_PRESEC_RECV_TIMEOUT', '10')))
_RSA_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=RSA_KEY_BITS,
    backend=default_backend(),
)
_RSA_PUB = _RSA_KEY.public_key()
_RSA_PUB_NUMBERS = _RSA_PUB.public_numbers()
_RSA_KEY_BYTES = (RSA_KEY_BITS + 7) // 8

def _pub_key_bytes():
    """Return (modulus_le, pub_exp_le) as little-endian bytes for embedding in GCC."""
    n = _RSA_PUB_NUMBERS.n
    e = _RSA_PUB_NUMBERS.e
    # Modulus as key-sized little-endian bytes.
    mod_bytes = n.to_bytes(_RSA_KEY_BYTES, byteorder='little')
    exp_bytes = e.to_bytes(4, byteorder='little')
    return mod_bytes, exp_bytes

def rsa_decrypt_client_random(encrypted_random):
    """
    RSA-decrypt the client random using our private key.
    MS-RDPBCGR uses raw RSA (no OAEP/PKCS1v15 padding) with little-endian integers.
    The encrypted blob is a LE integer; result is a 32-byte LE integer (the client random).
    """
    # Convert LE blob → big-endian int
    # Trim/pad to key size in bytes.
    trimmed = encrypted_random[:_RSA_KEY_BYTES].ljust(_RSA_KEY_BYTES, b'\x00')
    val = int.from_bytes(trimmed, byteorder='little')

    # Raw RSA: plaintext = cipher^d mod n
    d = _RSA_KEY.private_numbers().d
    n = _RSA_PUB_NUMBERS.n
    decrypted_int = pow(val, d, n)

    # Result is 32-byte client random (little-endian)
    return decrypted_int.to_bytes(_RSA_KEY_BYTES, byteorder='little')[:32]


# ---------------------------------------------------------------------------
# Session key derivation  (MS-RDPBCGR §5.3.5.1  —  Non-FIPS, 128-bit)
# ---------------------------------------------------------------------------

def _salted_hash(s, i_bytes, client_random, server_random):
    sha = hashlib.sha1(i_bytes + s + client_random + server_random).digest()
    return hashlib.md5(s + sha).digest()

def _pre_master_hash(pre_master, i_bytes, client_random, server_random):
    return _salted_hash(pre_master, i_bytes, client_random, server_random)

def _final_hash(k, client_random, server_random):
    return hashlib.md5(k + client_random + server_random).digest()

def derive_session_keys(client_random, server_random):
    """
    Derive 128-bit RC4 session keys per MS-RDPBCGR §5.3.5.1.
    Returns (decrypt_key, mac_key) — we only need the server's decryption key
    (= client's encryption key) to decrypt Client Info PDU.
    """
    pre_master = client_random[:24] + server_random[:24]  # 384 bits

    master_secret = (
        _pre_master_hash(pre_master, b'\x41', client_random, server_random) +        # 'A'
        _pre_master_hash(pre_master, b'\x42\x42', client_random, server_random) +    # 'BB'
        _pre_master_hash(pre_master, b'\x43\x43\x43', client_random, server_random)  # 'CCC'
    )  # 48 bytes

    session_key_blob = (
        _salted_hash(master_secret, b'\x58', client_random, server_random) +          # 'X'
        _salted_hash(master_secret, b'\x59\x59', client_random, server_random) +      # 'YY'
        _salted_hash(master_secret, b'\x5a\x5a\x5a', client_random, server_random)   # 'ZZZ'
    )  # 48 bytes

    mac_key_128 = session_key_blob[0:16]

    # Server decrypt key = FinalHash(Third128Bits(SessionKeyBlob))
    # "Third128Bits" = bytes 32..47
    server_decrypt_key_128 = _final_hash(session_key_blob[32:48], client_random, server_random)

    return server_decrypt_key_128, mac_key_128


# ---------------------------------------------------------------------------
# RC4 — minimal pure-Python implementation (no OpenSSL dependency for this)
# ---------------------------------------------------------------------------

class RC4:
    """Minimal RC4 stream cipher."""
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) & 0xFF
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def process(self, data):
        out = bytearray(len(data))
        for idx, byte in enumerate(data):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.S[self.i]) & 0xFF
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            out[idx] = byte ^ self.S[(self.S[self.i] + self.S[self.j]) & 0xFF]
        return bytes(out)


# ---------------------------------------------------------------------------
# TPKT / X.224 / BER / PER helpers
# ---------------------------------------------------------------------------

def _tpkt_wrap(payload):
    """Wrap payload in TPKT + X.224 Data headers."""
    x224 = b'\x02\xf0\x80'  # X.224 DT TPDU (LI=2, DT, EOT)
    total = 4 + len(x224) + len(payload)
    return struct.pack('>BBH', 3, 0, total) + x224 + payload

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def _ber_write_int(tag, value, width=2):
    data = value.to_bytes(width, 'big')
    return bytes([tag]) + _ber_len(len(data)) + data

def _read_ber_len(data, offset):
    """Read BER length, return (length_value, new_offset)."""
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    elif b == 0x81:
        return data[offset + 1], offset + 2
    elif b == 0x82:
        return struct.unpack('>H', data[offset+1:offset+3])[0], offset + 3
    return 0, offset + 1


# ---------------------------------------------------------------------------
# GCC / MCS packet builders
# ---------------------------------------------------------------------------

# Server Random (32 bytes) — generated per session
def _generate_server_random():
    return os.urandom(32)

def _build_server_security_data(server_random):
    """
    Build TS_UD_SC_SEC (Server Security Data) containing:
      - encryption method (128-bit RC4)
      - encryption level (High)
      - server random
      - RSA public key in a Server Certificate
    """
    mod_bytes, exp_bytes = _pub_key_bytes()

    # --- RSA Public Key structure (MS-RDPBCGR §2.2.1.4.3.1.1.1) ---
    # magic "RSA1", keylen, bitlen, datalen, pubExp, modulus
    keylen = len(mod_bytes) + 8  # modulus + 8 bytes padding (MS spec says +8)
    bitlen = len(mod_bytes) * 8
    datalen = len(mod_bytes) - 1
    rsa_pub = b'RSA1'
    rsa_pub += struct.pack('<I', keylen)
    rsa_pub += struct.pack('<I', bitlen)
    rsa_pub += struct.pack('<I', datalen)
    rsa_pub += exp_bytes  # pubExp (4 bytes LE)
    rsa_pub += mod_bytes  # modulus
    rsa_pub += b'\x00' * 8  # padding (8 zero bytes)

    # --- Server Proprietary Certificate (§2.2.1.4.3.1.1) ---
    # dwSigAlgId=1 (RSA), dwKeyAlgId=1 (RSA), wPublicKeyBlobType=0x0006,
    # wPublicKeyBlobLen, PublicKeyBlob, wSignatureBlobType=0x0008,
    # wSignatureBlobLen, SignatureBlob
    cert  = struct.pack('<I', 1)        # dwSigAlgId = SIGNATURE_ALG_RSA
    cert += struct.pack('<I', 1)        # dwKeyAlgId = KEY_EXCHANGE_ALG_RSA
    cert += struct.pack('<H', 0x0006)   # wPublicKeyBlobType = BB_RSA_KEY_BLOB
    cert += struct.pack('<H', len(rsa_pub))
    cert += rsa_pub
    # Signature — for a honeypot, we can use a dummy signature
    # Real clients using standard RDP security validate against the Terminal Services
    # well-known public key, but brute-force tools typically skip validation
    sig = b'\x00' * (_RSA_KEY_BYTES + 8)
    cert += struct.pack('<H', 0x0008)   # wSignatureBlobType = BB_RSA_SIGNATURE_BLOB
    cert += struct.pack('<H', len(sig))
    cert += sig

    # --- TS_UD_SC_SEC structure ---
    # Header: type=0x0C02, length (set later)
    # Advertise multiple classic methods for wider client compatibility.
    # 0x00000001=40bit, 0x00000002=128bit, 0x00000008=56bit.
    enc_method = 0x0000000B
    # ENCRYPTION_LEVEL_CLIENT_COMPATIBLE is usually tolerated best by legacy tools.
    enc_level  = 0x00000002
    body  = struct.pack('<I', enc_method)
    body += struct.pack('<I', enc_level)
    body += struct.pack('<I', len(server_random))
    body += struct.pack('<I', len(cert))
    body += server_random
    body += cert

    header = struct.pack('<HH', 0x0C02, len(body) + 4)
    return header + body


def _build_server_core_data():
    """TS_UD_SC_CORE — minimal server core data."""
    # version = 0x00080004 (RDP 5.0+)
    body = struct.pack('<I', 0x00080004)
    # clientRequestedProtocols = 0 (standard RDP)
    body += struct.pack('<I', 0)
    # earlyCapabilityFlags = 0
    body += struct.pack('<I', 0)
    header = struct.pack('<HH', 0x0C01, len(body) + 4)
    return header + body


def _build_server_network_data(channel_ids=None):
    """TS_UD_SC_NET — I/O channel plus optional server-assigned virtual channels."""
    channel_ids = channel_ids or []
    body = struct.pack('<H', 0x03EB)  # MCS channel ID for I/O = 1003
    body += struct.pack('<H', len(channel_ids))
    for channel_id in channel_ids:
        body += struct.pack('<H', channel_id)
    # Pad to 4-byte boundary
    if len(body) % 4 != 0:
        body += b'\x00' * (4 - len(body) % 4)
    header = struct.pack('<HH', 0x0C03, len(body) + 4)
    return header + body


def _read_per_length(data, offset):
    if offset >= len(data):
        return None, offset
    b0 = data[offset]
    offset += 1
    if b0 & 0x80:
        if offset >= len(data):
            return None, offset
        return ((b0 & 0x7F) << 8) | data[offset], offset + 1
    return b0, offset


def _read_ber_tlv(data, offset):
    """
    Minimal BER TLV reader supporting one-byte and 0x7fXX two-byte tags.
    Returns (tag_bytes, value, next_offset) or (None, None, offset) on failure.
    """
    if offset >= len(data):
        return None, None, offset
    first = data[offset]
    offset += 1
    if first == 0x7F:
        if offset >= len(data):
            return None, None, offset
        tag = bytes([first, data[offset]])
        offset += 1
    else:
        tag = bytes([first])
    length, offset = _read_ber_len(data, offset)
    end = offset + length
    if end > len(data):
        return None, None, offset
    return tag, data[offset:end], end


def _extract_client_network_profile(mcs_connect_initial):
    """
    Parse enough of MCS Connect Initial to tune response compatibility.
    Returns dict with:
      domain_params_raw: BER bytes for targetDomainParameters (if found)
      requested_channel_ids: list of server-assigned virtual channel IDs to advertise
      requested_channel_count: reported client virtual channel count
    """
    profile = {
        'domain_params_raw': None,
        'requested_channel_ids': [],
        'requested_channel_count': 0,
    }
    off = _skip_tpkt_x224(mcs_connect_initial)
    if off >= len(mcs_connect_initial):
        return profile
    # Expect MCS Connect Initial tag 0x7f65.
    if mcs_connect_initial[off:off + 2] != b'\x7f\x65':
        return profile
    off += 2
    _, off = _read_ber_len(mcs_connect_initial, off)
    # callingDomainSelector, calledDomainSelector, upwardFlag
    for _ in range(3):
        _tag, _val, off = _read_ber_tlv(mcs_connect_initial, off)
    # targetDomainParameters (sequence) — reuse if present
    tag, value, off = _read_ber_tlv(mcs_connect_initial, off)
    if tag == b'\x30':
        profile['domain_params_raw'] = value
    # min/max parameters
    _tag, _value, off = _read_ber_tlv(mcs_connect_initial, off)
    _tag, _value, off = _read_ber_tlv(mcs_connect_initial, off)
    # userData octet-string (contains GCC payload)
    tag, gcc_payload, _off = _read_ber_tlv(mcs_connect_initial, off)
    if tag != b'\x04' or not gcc_payload:
        return profile

    # TS_UD_CS_NET is type 0xC003 (little-endian bytes 03 c0).
    # We only need the channel count to mirror a realistic server network block.
    marker = b'\x03\xc0'
    i = 0
    while True:
        i = gcc_payload.find(marker, i)
        if i < 0 or i + 8 > len(gcc_payload):
            break
        try:
            block_len = struct.unpack_from('<H', gcc_payload, i + 2)[0]
            if block_len >= 8 and i + block_len <= len(gcc_payload):
                chan_count = struct.unpack_from('<I', gcc_payload, i + 4)[0]
                # Bound to a sane number for response construction.
                chan_count = max(0, min(int(chan_count), 16))
                profile['requested_channel_count'] = chan_count
                profile['requested_channel_ids'] = [0x03EC + n for n in range(chan_count)]
                break
        except Exception:
            pass
        i += 2
    return profile


def build_mcs_connect_response(server_random, client_profile=None):
    """
    Build a complete MCS Connect Response (BER-encoded) wrapping a
    GCC Conference Create Response with our server security data.
    """
    # --- GCC Conference Create Response user data ---
    client_profile = client_profile or {}
    sc_core = _build_server_core_data()
    sc_sec  = _build_server_security_data(server_random)
    sc_net  = _build_server_network_data(client_profile.get('requested_channel_ids', []))
    user_data = sc_core + sc_sec + sc_net

    # --- GCC Conference Create Response (T.124) ---
    # Per-encoded: ConferenceCreateResponse
    gcc  = b'\x00\x05\x00'  # T.124 key (object, h221NonStandard = "McDn")
    gcc += b'\x14'           # ConnectGCCPDU select conferenceCreateResponse
    gcc += b'\x7c'           # key: h221NonStandard
    gcc += struct.pack('>H', len(user_data) + 14)  # ≈ userData container length
    gcc += b'\x4d\x63\x44\x6e'  # h221NonStandard key: "McDn"

    # PER: nodeID, tag, result=success
    gcc_resp  = b'\x00\x05\x00\x14\x7c\x01'
    gcc_resp += bytes([0x2a])  # ≈ PER length marker
    gcc_resp += b'\x14\x76\x0a\x01\x01\x00\x01\xc0\x00'
    gcc_resp += struct.pack('>H', len(user_data) + 2)
    gcc_resp += struct.pack('>H', len(user_data))
    gcc_resp += user_data

    # --- MCS Connect Response (T.125, BER-encoded) ---
    # result (enumerated, success=0)
    mcs_result = b'\x0a\x01\x00'
    # calledConnectId (integer, 0)
    mcs_called = b'\x02\x01\x00'
    # Domain parameters: mirror targetDomainParameters from client if we parsed it,
    # else fall back to permissive defaults.
    client_domain_params = client_profile.get('domain_params_raw')
    if client_domain_params:
        domain_params = bytes([0x30]) + _ber_len(len(client_domain_params)) + client_domain_params
    else:
        dp  = _ber_write_int(0x02, 34)     # maxChannelIds
        dp += _ber_write_int(0x02, 3)      # maxUserIds
        dp += _ber_write_int(0x02, 0)      # maxTokenIds
        dp += _ber_write_int(0x02, 1)      # numPriorities
        dp += _ber_write_int(0x02, 0)      # minThroughput
        dp += _ber_write_int(0x02, 1)      # maxHeight
        dp += _ber_write_int(0x02, 65535, 4)  # maxMCSPDUsize
        dp += _ber_write_int(0x02, 2)      # protocolVersion
        domain_params = bytes([0x30]) + _ber_len(len(dp)) + dp

    # userData (OCTET STRING wrapping GCC)
    user_data_field = bytes([0x04]) + _ber_len(len(gcc_resp)) + gcc_resp

    inner = mcs_result + mcs_called + domain_params + user_data_field

    # MCS CONNECT-RESPONSE tag = 0x7f66 (BER: application tag 101)
    mcs_cr = bytes([0x7f, 0x66]) + _ber_len(len(inner)) + inner

    return mcs_cr


def build_mcs_attach_user_confirm(user_channel_id):
    """
    PER-encoded MCS Attach User Confirm.
    AttachUserConfirm ::= [APPLICATION 11] IMPLICIT SEQUENCE {
        result     Result (success = rt-successful = 0),
        initiator  UserId OPTIONAL
    }
    """
    # MCS choice index for AttachUserConfirm = 11, PER-encoded
    return bytes([
        0x2e,  # AttachUserConfirm tag (PER)
        0x00,  # result = rt-successful
        (user_channel_id >> 8) & 0xFF,
        user_channel_id & 0xFF,
    ])


def build_mcs_channel_join_confirm(user_channel_id, channel_id):
    """
    PER-encoded MCS Channel Join Confirm.
    """
    return bytes([
        0x3e,  # ChannelJoinConfirm tag (PER)
        0x00,  # result = rt-successful
        (user_channel_id >> 8) & 0xFF,
        user_channel_id & 0xFF,
        (channel_id >> 8) & 0xFF,
        channel_id & 0xFF,
        (channel_id >> 8) & 0xFF,
        channel_id & 0xFF,
    ])


# ---------------------------------------------------------------------------
# Packet receivers / parsers
# ---------------------------------------------------------------------------

def recv_tpkt(sock, timeout=10):
    """Read one TPKT-framed packet, return raw bytes. Raises on error."""
    sock.settimeout(timeout)
    hdr = b''
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError('connection closed')
        hdr += chunk

    if hdr[0] != 0x03:
        # Not TPKT — read what we can and return
        extra = sock.recv(4096)
        return hdr + extra

    pkt_len = struct.unpack('>H', hdr[2:4])[0]
    body = b''
    remaining = pkt_len - 4
    while len(body) < remaining:
        chunk = sock.recv(min(remaining - len(body), 4096))
        if not chunk:
            raise ConnectionError('connection closed')
        body += chunk
    return hdr + body


def _skip_tpkt_x224(data):
    """Return offset past the TPKT (4 bytes) + X.224 Data (3 bytes) headers."""
    return 7

def _preview_hex(data, n=24):
    if not data:
        return ''
    return data[:n].hex()

def _packet_tag(data):
    off = _skip_tpkt_x224(data)
    if off >= len(data):
        return None
    return data[off]


def parse_mcs_send_data_request(data):
    """
    Minimal parse of PER-encoded MCS Send Data Request to extract userData.
    SDrq is choice 25 in DomainMCSPDU.
    PER: 0x64 tag, initiator(2), channelId(2), dataPriority+segmentation(1),
         userData length (PER length), userData bytes
    """
    off = _skip_tpkt_x224(data)

    if off >= len(data):
        return None
    tag = data[off]
    off += 1

    # SDrq tag should be 0x64
    if tag != 0x64:
        return None

    off += 2  # initiator (2 bytes)
    off += 2  # channelId (2 bytes)
    off += 1  # dataPriority + segmentation

    # PER-encoded length of userData (short or 2-byte forms)
    length, off = _read_per_length(data, off)
    if length is None:
        return None
    if off + length > len(data):
        return None
    return data[off:off + length]


def parse_security_exchange(user_data):
    """
    Extract encrypted client random from Security Exchange PDU Data.
    Structure: basicSecurityHeader(4 bytes: flags + flagsHi) + length(4) + encryptedClientRandom
    flags must contain SEC_EXCHANGE_PKT (0x0001).
    """
    if not user_data or len(user_data) < 12:
        return None

    flags = struct.unpack_from('<H', user_data, 0)[0]
    if not (flags & 0x0001):  # SEC_EXCHANGE_PKT
        return None

    enc_len = struct.unpack_from('<I', user_data, 4)[0]
    enc_data = user_data[8:8 + enc_len]
    return enc_data


def parse_client_info_pdu(user_data, decrypt_key, trace_fn=None):
    """
    Decrypt and parse the Client Info PDU to extract username and password.
    Structure:
      securityHeader (12 bytes for Non-FIPS: flags(2) + flagsHi(2) + MAC(8))
      encrypted TS_INFO_PACKET
    Returns (username, password, domain) or (None, None, None).
    """
    if not user_data or len(user_data) < 16:
        if trace_fn:
            trace_fn('classic_client_info_too_short', total=len(user_data) if user_data else 0)
        return None, None, None

    flags = struct.unpack_from('<H', user_data, 0)[0]
    encrypted = bool(flags & 0x0008)  # SEC_ENCRYPT
    if trace_fn:
        trace_fn(
            'classic_client_info_header',
            flags=f'0x{flags:04x}',
            encrypted=encrypted,
            total=len(user_data),
            preview=_preview_hex(user_data),
        )

    if encrypted:
        # Non-FIPS header: flags(2) + flagsHi(2) + dataSignature(8) = 12 bytes
        encrypted = user_data[12:]
        rc4 = RC4(decrypt_key)
        decrypted = rc4.process(encrypted)
        if trace_fn:
            trace_fn('classic_client_info_decrypted', decrypted_len=len(decrypted), preview=_preview_hex(decrypted))
    else:
        # Not encrypted (ENCRYPTION_LEVEL_NONE or already decrypted via TLS)
        decrypted = user_data[4:]  # skip basic security header
        if trace_fn:
            trace_fn('classic_client_info_plain', decrypted_len=len(decrypted), preview=_preview_hex(decrypted))

    return _parse_ts_info_packet(decrypted, trace_fn=trace_fn)


def _parse_ts_info_packet(data, trace_fn=None):
    """
    Parse TS_INFO_PACKET structure (MS-RDPBCGR §2.2.1.11.1.1).

    Fixed header (18 bytes):
      CodePage(4) + flags(4) + cbDomain(2) + cbUserName(2) +
      cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2)

    Variable fields (each null-terminated, sizes from header EXCLUDE null terminator):
      Domain, UserName, Password, AlternateShell, WorkingDir
    """
    if not data or len(data) < 18:
        if trace_fn:
            trace_fn('classic_ts_info_too_short', total=len(data) if data else 0)
        return None, None, None

    try:
        code_page = struct.unpack_from('<I', data, 0)[0]
        info_flags = struct.unpack_from('<I', data, 4)[0]
        cb_domain   = struct.unpack_from('<H', data, 8)[0]
        cb_username = struct.unpack_from('<H', data, 10)[0]
        cb_password = struct.unpack_from('<H', data, 12)[0]
        # cb_alt_shell = struct.unpack_from('<H', data, 14)[0]
        # cb_working_dir = struct.unpack_from('<H', data, 16)[0]

        is_unicode = bool(info_flags & 0x00000010)  # INFO_UNICODE
        null_size = 2 if is_unicode else 1
        encoding = 'utf-16-le' if is_unicode else 'latin-1'
        if trace_fn:
            trace_fn(
                'classic_ts_info_header',
                code_page=code_page,
                info_flags=f'0x{info_flags:08x}',
                cb_domain=cb_domain,
                cb_username=cb_username,
                cb_password=cb_password,
                encoding=encoding,
            )

        off = 18

        # Domain
        domain_raw = data[off:off + cb_domain]
        off += cb_domain + null_size

        # UserName
        username_raw = data[off:off + cb_username]
        off += cb_username + null_size

        # Password
        password_raw = data[off:off + cb_password]
        off += cb_password + null_size

        domain   = domain_raw.decode(encoding, errors='replace').strip('\x00') if domain_raw else ''
        username = username_raw.decode(encoding, errors='replace').strip('\x00') if username_raw else ''
        password = password_raw.decode(encoding, errors='replace').strip('\x00') if password_raw else ''

        if trace_fn:
            trace_fn(
                'classic_ts_info_fields',
                domain_len=len(domain),
                user_len=len(username),
                pass_len=len(password),
            )
        return username or None, password or None, domain or None

    except Exception:
        if trace_fn:
            trace_fn('classic_ts_info_parse_error', preview=_preview_hex(data))
        return None, None, None


# ---------------------------------------------------------------------------
# Main handshake function — called from handle_connection
# ---------------------------------------------------------------------------

X224_CC_RDP = bytes([
    0x03, 0x00, 0x00, 0x0B,   # TPKT: version=3, length=11
    0x06,                      # LI=6
    0xD0,                      # X.224 Connection Confirm
    0x00, 0x00,                # dst-ref
    0x00, 0x00,                # src-ref
    0x00,                      # class 0
    # No RDP_NEG_RSP → standard RDP security selected
])


def do_classic_rdp_security(sock, client_ip, trace_fn=None, session_id='-'):
    """
    Perform the classic (non-NLA) RDP security handshake to extract plaintext
    credentials from a legacy client.

    Call this INSTEAD of do_nla() when the client's req_protocols indicates
    it doesn't support NLA (req_protocols & 0x02 == 0) and also doesn't
    support SSL-only (req_protocols == 0 → pure classic).

    The X.224 Connection Confirm should be sent by the caller before calling this
    (use X224_CC_RDP for standard RDP security, no NLA/SSL).

    Args:
        sock: Raw TCP socket (post X.224 CC)
        client_ip: For logging
        trace_fn: Optional callable(session_id, client_ip, stage, **fields)
        session_id: For logging correlation

    Returns:
        (username, password, domain, status_str)
        Any of username/password/domain may be None on failure.
    """
    def _trace(stage, **kw):
        if trace_fn:
            trace_fn(session_id, client_ip, stage, **kw)

    server_random = _generate_server_random()
    # Assign stable IDs for this minimal server implementation.
    # User channel id is server-assigned during Attach User Confirm.
    user_channel_id = 0x03EA  # 1002
    io_channel_id = 0x03EB    # 1003

    try:
        _trace(
            'classic_handshake_start',
            user_channel_id=user_channel_id,
            io_channel_id=io_channel_id,
        )
        # --- Step 1: Receive MCS Connect Initial ---
        _trace('classic_await_mcs_connect_initial')
        pkt = recv_tpkt(sock)
        _trace(
            'classic_mcs_connect_initial_recv',
            bytes=len(pkt),
            tag=_packet_tag(pkt),
            preview=_preview_hex(pkt),
        )

        client_profile = _extract_client_network_profile(pkt)
        _trace(
            'classic_client_profile',
            requested_channel_count=client_profile.get('requested_channel_count', 0),
            mirrored_channel_ids=client_profile.get('requested_channel_ids', []),
            has_client_domain_params=bool(client_profile.get('domain_params_raw')),
        )

        # --- Step 2: Send MCS Connect Response ---
        mcs_resp = build_mcs_connect_response(server_random, client_profile=client_profile)
        sock.sendall(_tpkt_wrap(mcs_resp))
        _trace('classic_mcs_connect_response_sent')

        # --- Step 3..9: Tolerant pre-security state loop ---
        # Legacy tools vary sequence/order, so we accept the common packet classes
        # until first Send Data Request (Security Exchange candidate).
        saw_erect_domain = False
        sent_attach_confirm = False
        joined_channels = []
        pending_pkt = None
        try:
            for idx in range(CLASSIC_PRESEC_MAX_PDUS):
                pkt = recv_tpkt(sock, timeout=CLASSIC_PRESEC_RECV_TIMEOUT)
                tag = _packet_tag(pkt)
                _trace(
                    'classic_presec_recv',
                    index=idx,
                    bytes=len(pkt),
                    tag=tag,
                    preview=_preview_hex(pkt),
                )

                # MCS Erect Domain Request
                if tag == 0x04:
                    saw_erect_domain = True
                    _trace('classic_erect_domain_recv')
                    continue

                # MCS Attach User Request
                if tag == 0x28 and not sent_attach_confirm:
                    sock.sendall(_tpkt_wrap(build_mcs_attach_user_confirm(user_channel_id)))
                    sent_attach_confirm = True
                    _trace('classic_attach_user_confirm_sent', channel=user_channel_id)
                    continue

                # MCS Channel Join Request
                if tag == 0x38:
                    off = _skip_tpkt_x224(pkt)
                    if off + 5 <= len(pkt):
                        req_channel = struct.unpack('>H', pkt[off + 3:off + 5])[0]
                    else:
                        req_channel = io_channel_id
                    sock.sendall(_tpkt_wrap(build_mcs_channel_join_confirm(user_channel_id, req_channel)))
                    joined_channels.append(req_channel)
                    _trace(
                        'classic_channel_join_confirm_sent',
                        channel=req_channel,
                        joined_count=len(joined_channels),
                    )
                    continue

                # MCS Send Data Request — likely security exchange or follow-on PDU.
                if tag == 0x64:
                    pending_pkt = pkt
                    _trace(
                        'classic_first_non_join_after_channels',
                        bytes=len(pkt),
                        tag=tag,
                        preview=_preview_hex(pkt),
                    )
                    break
                # Any other tag: keep it for downstream parser and log as variant.
                pending_pkt = pkt
                _trace(
                    'classic_unexpected_presec_pdu',
                    saw_erect_domain=saw_erect_domain,
                    sent_attach_confirm=sent_attach_confirm,
                    joined_count=len(joined_channels),
                )
                break
        except (socket.timeout, TimeoutError):
            _trace(
                'classic_presec_timeout',
                saw_erect_domain=saw_erect_domain,
                sent_attach_confirm=sent_attach_confirm,
                joined_count=len(joined_channels),
            )
        except Exception as e:
            _trace(
                'classic_presec_exception',
                error=type(e).__name__,
                detail=str(e),
                saw_erect_domain=saw_erect_domain,
                sent_attach_confirm=sent_attach_confirm,
                joined_count=len(joined_channels),
            )
        if pending_pkt is None:
            return None, None, None, 'classic_timeout_waiting_security_exchange'

        # --- Step 10: Receive Security Exchange PDU ---
        _trace('classic_await_security_exchange')
        pkt = pending_pkt if pending_pkt is not None else recv_tpkt(sock, timeout=10)
        _trace(
            'classic_security_exchange_recv',
            bytes=len(pkt),
            tag=_packet_tag(pkt),
            preview=_preview_hex(pkt),
        )

        user_data = parse_mcs_send_data_request(pkt)
        if not user_data:
            _trace('classic_security_exchange_no_mcs_userdata', tag=_packet_tag(pkt))
            return None, None, None, 'classic_no_mcs_userdata_in_sec_exchange'
        _trace('classic_security_exchange_mcs_userdata', user_data_len=len(user_data), preview=_preview_hex(user_data))

        enc_client_random = parse_security_exchange(user_data)
        if not enc_client_random:
            _trace('classic_security_exchange_no_encrypted_random', preview=_preview_hex(user_data))
            return None, None, None, 'classic_no_encrypted_random'

        _trace('classic_rsa_decrypt_start', enc_len=len(enc_client_random))
        client_random = rsa_decrypt_client_random(enc_client_random)
        _trace('classic_rsa_decrypt_ok')

        # Derive session keys
        decrypt_key, _mac_key = derive_session_keys(client_random, server_random)
        _trace('classic_session_keys_derived')

        # --- Step 11: Receive Client Info PDU ---
        pkt = recv_tpkt(sock, timeout=10)
        _trace('classic_client_info_recv', bytes=len(pkt), tag=_packet_tag(pkt), preview=_preview_hex(pkt))

        user_data = parse_mcs_send_data_request(pkt)
        if not user_data:
            _trace('classic_client_info_no_mcs_userdata', tag=_packet_tag(pkt))
            return None, None, None, 'classic_no_mcs_userdata_in_info'
        _trace('classic_client_info_mcs_userdata', user_data_len=len(user_data), preview=_preview_hex(user_data))

        username, password, domain = parse_client_info_pdu(user_data, decrypt_key, trace_fn=_trace)
        _trace('classic_credentials_parsed', user=username, has_password=bool(password), domain=domain)

        return username, password, domain, 'classic_credentials_ok'

    except ConnectionError as e:
        _trace('classic_connection_error', error=str(e))
        return None, None, None, f'classic_connection_error:{e}'
    except Exception as e:
        _trace('classic_exception', error=type(e).__name__, detail=str(e))
        return None, None, None, f'classic_exception:{type(e).__name__}'

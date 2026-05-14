#!/usr/bin/env python3
"""
Siemens S7 TCP honeypot — listens on port 102, implements the TPKT/COTP/S7comm
stack to simulate a Siemens S7-315-2 PN/DP PLC, and emits S7 JSON knocks.

Usage:
    python honeypots/s7_honeypot.py
    S7_PORT=102 python honeypots/s7_honeypot.py
"""

import argparse
import json
import os
import socket
import struct
import threading

from common import create_dualstack_tcp_listener, is_blocked, normalize_ip


S7_PORT = int(os.environ.get('S7_PORT', '102'))
KNOCK_PROTO = os.environ.get('KNOCK_PROTO', 'S7').strip().upper() or 'S7'
S7_TIMEOUT = float(os.environ.get('S7_TIMEOUT', '20'))
S7_MAX_REQUESTS = int(os.environ.get('S7_MAX_REQUESTS', '20'))
S7_TRACE = os.environ.get('S7_TRACE', '0').lower() not in ('0', 'false', 'no')
S7_TRACE_IP = os.environ.get('S7_TRACE_IP', '').strip()
S7_MMS_RESPOND = os.environ.get('S7_MMS_RESPOND', 'true').lower() not in ('0', 'false', 'no')

# COTP PDU types
COTP_CR = 0xE0  # Connection Request
COTP_CC = 0xD0  # Connection Confirm
COTP_DT = 0xF0  # Data Transfer

# S7comm message types
S7_JOB      = 0x01
S7_ACK_DATA = 0x03
S7_USERDATA = 0x07

# S7 Job function codes
S7_FUNC_READ     = 0x04  # Read Variable
S7_FUNC_WRITE    = 0x05  # Write Variable
S7_FUNC_REQ_DL   = 0x1D  # Request Download (to PLC)
S7_FUNC_DL       = 0x1E  # Download Block
S7_FUNC_DL_END   = 0x1F  # Download Ended
S7_FUNC_START_UL = 0x28  # Start Upload (from PLC)
S7_FUNC_UL       = 0x29  # Upload
S7_FUNC_UL_END   = 0x2A  # End Upload
S7_FUNC_SETUP    = 0xF0  # Setup Communication

FUNC_NAMES = {
    S7_FUNC_READ:     'Read Variable',
    S7_FUNC_WRITE:    'Write Variable',
    S7_FUNC_REQ_DL:   'Request Download',
    S7_FUNC_DL:       'Download Block',
    S7_FUNC_DL_END:   'Download Ended',
    S7_FUNC_START_UL: 'Start Upload',
    S7_FUNC_UL:       'Upload',
    S7_FUNC_UL_END:   'End Upload',
    S7_FUNC_SETUP:    'Setup Communication',
}

AREA_NAMES = {
    0x81: 'I',   # Inputs
    0x82: 'Q',   # Outputs
    0x83: 'M',   # Merkers/Flags
    0x84: 'DB',  # Data Blocks
    0x85: 'DI',  # Instance Data Blocks
    0x86: 'L',   # Local Data
    0x1C: 'C',   # Counter
    0x1D: 'T',   # Timer
}

TRANSFER_FUNCS = frozenset({
    S7_FUNC_START_UL, S7_FUNC_UL, S7_FUNC_UL_END,
    S7_FUNC_REQ_DL, S7_FUNC_DL, S7_FUNC_DL_END,
})

# Fake S7-315-2 PN/DP identity
_MODULE_ORDER = b'6ES7 315-2EH14-0AB0\x00'
_FIRMWARE_VER = b'V3.2'

# SZL IDs advertised as supported by our fake S7-315-2
_SZL_SUPPORTED = [
    0x0011, 0x0012, 0x0013, 0x0014, 0x0015,
    0x0111, 0x0112, 0x0113, 0x0114, 0x0118, 0x0119,
    0x0131, 0x0132,
    0x0174, 0x0175,
    0x0232, 0x0524,
    0x0100,
]


class S7ParseError(Exception):
    pass


def _trace(client_ip, stage, **kwargs):
    if not S7_TRACE:
        return
    if S7_TRACE_IP and client_ip != S7_TRACE_IP:
        return
    parts = [f'S7TRACE ip={client_ip}', f'stage={stage}']
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f'{k}={v!r}')
    print(' '.join(parts), flush=True)


def read_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise S7ParseError('connection closed')
        buf += chunk
    return buf


def read_tpkt(sock):
    """Read one TPKT frame. Returns the COTP+payload bytes."""
    header = read_exact(sock, 4)
    version, _, length = struct.unpack('>BBH', header)
    if version != 3:
        raise S7ParseError(f'invalid TPKT version: {version}')
    payload_len = length - 4
    if not (0 < payload_len <= 8192):
        raise S7ParseError(f'invalid TPKT payload length: {payload_len}')
    return read_exact(sock, payload_len)


def make_tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload


def parse_cotp(data):
    """Parse COTP header. Returns (pdu_type, cotp_body, s7_payload)."""
    if len(data) < 2:
        raise S7ParseError('COTP too short')
    li = data[0]
    if 1 + li > len(data):
        raise S7ParseError('COTP LI overrun')
    pdu_type = data[1]
    cotp_body = data[1:1 + li]    # PDU type + rest of COTP header
    s7_payload = data[1 + li:]    # S7comm payload (empty for CR/CC)
    return pdu_type, cotp_body, s7_payload


def make_cotp_cc(src_ref):
    """Build COTP Connection Confirm."""
    body = struct.pack('>BHHB', COTP_CC, src_ref, 0x0001, 0x00)
    body += bytes([0xC0, 0x01, 0x0A])        # TPDU-SIZE: 1024 bytes
    body += bytes([0xC1, 0x02, 0x01, 0x00])  # SRC-TSAP
    body += bytes([0xC2, 0x02, 0x01, 0x02])  # DST-TSAP
    return bytes([len(body)]) + body


def make_cotp_dt(s7_payload):
    """Wrap S7 payload in COTP DT frame."""
    return bytes([0x02, COTP_DT, 0x80]) + s7_payload


def make_mms_association_response():
    """Build a minimal ACSE AARE response for MMS association probes."""
    # Presentation data + ACSE AARE accepted. This mirrors the compact response
    # seen from MMS/IEC-61850 scanners closely enough to test whether they
    # continue into MMS service requests.
    return bytes.fromhex('01000100610e300c020103a007a0050201018200')


def cotp_src_ref(cotp_body):
    """Extract SRC-REF from a COTP CR body."""
    if len(cotp_body) >= 5:
        return struct.unpack('>H', cotp_body[3:5])[0]
    return 0x0001


def parse_s7(data):
    """Parse S7comm header. Returns a dict."""
    if len(data) < 10 or data[0] != 0x32:
        raise S7ParseError('not S7comm')
    msg_type = data[1]
    pdu_ref = struct.unpack('>H', data[4:6])[0]
    param_len = struct.unpack('>H', data[6:8])[0]
    data_len = struct.unpack('>H', data[8:10])[0]
    # Ack types carry error class/code at bytes 10-11 before params
    offset = 12 if msg_type in (0x02, 0x03) else 10
    params = data[offset:offset + param_len]
    payload = data[offset + param_len:offset + param_len + data_len]
    return {'msg_type': msg_type, 'pdu_ref': pdu_ref, 'params': params, 'payload': payload}


def make_ack(pdu_ref, params=b'', data=b'', err_class=0, err_code=0):
    """Build an S7 Ack-Data response frame."""
    hdr = struct.pack('>BBHHHH BB',
        0x32, S7_ACK_DATA, 0x0000, pdu_ref,
        len(params), len(data), err_class, err_code,
    )
    return hdr + params + data


def respond(parsed):
    """Build the appropriate S7 response for a parsed request."""
    msg_type = parsed['msg_type']
    params = parsed['params']
    pdu_ref = parsed['pdu_ref']
    func = params[0] if params else None

    if msg_type == S7_JOB:
        if func == S7_FUNC_SETUP:
            # Echo negotiated PDU size (480 bytes — typical for S7-315)
            resp_params = bytes([0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0])
            return make_ack(pdu_ref, params=resp_params)

        elif func == S7_FUNC_READ:
            item_count = params[1] if len(params) > 1 else 1
            resp_params = bytes([0x04, item_count])
            # Return zero word value for each requested item
            resp_data = bytes([0xFF, 0x04, 0x00, 0x02, 0x00, 0x00]) * max(1, item_count)
            return make_ack(pdu_ref, params=resp_params, data=resp_data)

        elif func == S7_FUNC_WRITE:
            item_count = params[1] if len(params) > 1 else 1
            resp_params = bytes([0x05, item_count])
            resp_data = bytes([0xFF] * max(1, item_count))
            return make_ack(pdu_ref, params=resp_params, data=resp_data)

        elif func in TRANSFER_FUNCS:
            return make_ack(pdu_ref)

        else:
            return make_ack(pdu_ref, err_class=0x81, err_code=0x01)

    elif msg_type == S7_USERDATA:
        return _respond_szl(pdu_ref, parsed['params'], parsed['payload'])

    return make_ack(pdu_ref, err_class=0x81, err_code=0x01)


def _szl_id_from(params, payload):
    """Extract SZL-ID: prefer data section payload, fall back to params."""
    if len(payload) >= 6:
        try:
            szl_id = struct.unpack('>H', payload[4:6])[0]
            if szl_id:
                return szl_id
        except Exception:
            pass
    if len(params) >= 8:
        try:
            return struct.unpack('>H', params[6:8])[0]
        except Exception:
            pass
    return 0


def _make_szl_ack(pdu_ref, seq, szl_data):
    """Build a proper S7 Userdata response with correct parameter block."""
    resp_params = bytes([
        0x00, 0x01, 0x12, 0x08,   # param head
        0x12, 0x84, 0x01, seq,    # type=response+CPU, 0x84, subfunction, echo seq
        0x00, 0x00, 0x00, 0x00,   # error bytes
    ])
    resp_data = struct.pack('>BBH', 0xFF, 0x09, len(szl_data)) + szl_data
    return make_ack(pdu_ref, params=resp_params, data=resp_data)


def _szl_list_of_lists():
    """SZL 0x0100: list of all SZL IDs supported by this device."""
    entries = b''.join(struct.pack('>H', s) for s in _SZL_SUPPORTED)
    # Header: szl_id, index, lenthd (1 word per entry), n_dr
    header = struct.pack('>HHHH', 0x0100, 0x0000, 1, len(_SZL_SUPPORTED))
    return header + entries


def _szl_module_id(szl_id):
    """SZL 0x0132/0x0111/etc: component/CPU identification."""
    entry = (
        b'\x00\x1C'                              # entry length (28 bytes)
        b'\x03\x00'                              # module type (CPU)
        + _MODULE_ORDER[:20].ljust(20, b'\x00')
        + _FIRMWARE_VER[:4].ljust(4, b'\x00')
    )
    header = struct.pack('>HHHH', szl_id, 0x0000, 14, 1)  # 14 words/entry, 1 entry
    return header + entry


def _szl_component_id():
    """SZL 0x001C: Component identification — order number, serial, versions."""
    # Each entry: MLFB(20) + BGTyp(2) + AusbgNr(2) + AusbgV(2) + reserved(2) = 28 bytes = 14 words
    mlfb = b'6ES7 315-2EH14-0AB0 '  # 20 bytes, space-padded (standard Siemens format)
    entry = mlfb + struct.pack('>HHHH',
        0x0003,   # BGTyp: CPU module
        0x0001,   # AusbgNr: assembly 1
        0x0302,   # AusbgV: version 3.2
        0x0000,   # reserved
    )
    header = struct.pack('>HHHH', 0x001C, 0x0000, 14, 1)
    return header + entry


def _szl_cpu_characteristics():
    """SZL 0x0011: CPU characteristics — capability flags per index."""
    # Each entry: index(2) + value1(2) + value2(2) + reserved(18) = 24 bytes = 12 words
    # A real S7-315-2 returns ~20 entries; we return a minimal convincing set.
    def entry(idx, v1, v2=0):
        return struct.pack('>HHH', idx, v1, v2) + b'\x00' * 18

    entries = b''.join([
        entry(0x0001, 0x0003),   # execution modes: RUN + STOP
        entry(0x0002, 0x7FFF),   # work memory size (32KB)
        entry(0x0003, 0x0001),   # number of OBs: 1
        entry(0x0004, 0x0010),   # number of DBs: 16
        entry(0x0005, 0x0010),   # number of FBs: 16
        entry(0x0006, 0x0010),   # number of FCs: 16
    ])
    header = struct.pack('>HHHH', 0x0011, 0x0000, 12, 6)
    return header + entries


def _szl_generic(szl_id):
    """Generic SZL response for unrecognised IDs."""
    entry = _MODULE_ORDER[:8].ljust(8, b'\x00') + _FIRMWARE_VER[:4].ljust(4, b'\x00') + b'\x00\x00'
    header = struct.pack('>HHHH', szl_id, 0x0000, 7, 1)
    return header + entry


def _respond_szl(pdu_ref, params, payload):
    szl_id = _szl_id_from(params, payload)
    seq = params[6] if len(params) > 6 else 0x00
    if szl_id == 0x0100:
        return _make_szl_ack(pdu_ref, seq, _szl_list_of_lists())
    elif szl_id == 0x001C:
        return _make_szl_ack(pdu_ref, seq, _szl_component_id())
    elif szl_id == 0x0011:
        return _make_szl_ack(pdu_ref, seq, _szl_cpu_characteristics())
    elif szl_id in (0x0111, 0x0112, 0x0113, 0x0114, 0x0132):
        return _make_szl_ack(pdu_ref, seq, _szl_module_id(szl_id))
    else:
        return _make_szl_ack(pdu_ref, seq, _szl_generic(szl_id or 0x0011))


def extract_fields(parsed):
    """Extract knock fields from an S7 request."""
    fields = {}
    msg_type = parsed['msg_type']
    params = parsed['params']
    func = params[0] if params else None

    if msg_type == S7_USERDATA:
        fields['s7_function_name'] = 'SZL Read'
        szl_id = _szl_id_from(params, parsed.get('payload', b''))
        if szl_id:
            fields['s7_szl_id'] = f'0x{szl_id:04X}'
        return fields

    if func is not None:
        fields['s7_function'] = func
        fields['s7_function_name'] = FUNC_NAMES.get(func, f'Unknown (0x{func:02X})')

    # Extract memory area + DB number from first S7ANY item in read/write requests
    # S7ANY item layout (from params[2]): var_spec(1) addr_len(1) syntax_id(1)
    # transport_size(1) count(2) db_num(2) area(1) byte_addr(3)
    if func in (S7_FUNC_READ, S7_FUNC_WRITE) and len(params) >= 14:
        try:
            db_num = struct.unpack('>H', params[8:10])[0]
            area = params[10]
            fields['s7_area'] = AREA_NAMES.get(area, f'0x{area:02X}')
            if db_num > 0:
                fields['s7_db_number'] = db_num
        except Exception:
            pass

    return fields


def _display_format(parsed):
    msg_type = parsed['msg_type']
    params = parsed['params']
    func = params[0] if params else None

    if msg_type == S7_USERDATA or func == S7_FUNC_SETUP:
        return 'identify'
    if func == S7_FUNC_READ:
        return 'read'
    if func == S7_FUNC_WRITE:
        return 'write'
    if func in TRANSFER_FUNCS:
        return 'transfer'
    return 'other'


def _ber_len(data, pos):
    if pos >= len(data):
        return None, pos
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4 or pos + n > len(data):
        return None, pos
    length = int.from_bytes(data[pos:pos + n], 'big')
    return length, pos + n


def _decode_oid_value(value):
    if not value:
        return None
    first = value[0]
    parts = [first // 40, first % 40]
    current = 0
    for b in value[1:]:
        current = (current << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(current)
            current = 0
    if current:
        return None
    return '.'.join(str(p) for p in parts)


def _find_ber_oids(data):
    oids = []
    for pos, tag in enumerate(data):
        if tag != 0x06:
            continue
        length, value_pos = _ber_len(data, pos + 1)
        if length is None or length <= 0 or value_pos + length > len(data):
            continue
        oid = _decode_oid_value(data[value_pos:value_pos + length])
        if oid:
            oids.append(oid)
    return oids


def _has_ber_tlv_tag(data, tag, stop=None):
    limit = min(len(data), stop if stop is not None else len(data))
    for pos in range(limit):
        if data[pos] != tag:
            continue
        length, value_pos = _ber_len(data, pos + 1)
        if length is not None and value_pos + length <= len(data):
            return True
    return False


def decode_mms_payload(data):
    """Best-effort MMS/ACSE identification inside ISO-on-TCP user data."""
    oids = _find_ber_oids(data)
    mms_oids = [oid for oid in oids if oid.startswith('1.0.9506.')]
    message = None
    if data and data[0] == 0x0D and _has_ber_tlv_tag(data, 0x60):
        message = 'Association Request'
    elif _has_ber_tlv_tag(data, 0x61, stop=8):
        message = 'Association Response'
    if not (mms_oids or message):
        return None
    return {
        'tcp102_protocol': 'MMS',
        'mms_message': message or 'MMS / ACSE',
        'mms_oid': mms_oids[0] if mms_oids else (oids[0] if oids else None),
    }



def send_mms_response(sock, client_ip, decoded_mms):
    if not S7_MMS_RESPOND:
        _trace(client_ip, 'mms_response_skipped', reason='disabled')
        return False
    if not decoded_mms or decoded_mms.get('mms_message') != 'Association Request':
        _trace(client_ip, 'mms_response_skipped', reason='not_association_request')
        return False
    response = make_mms_association_response()
    try:
        sock.sendall(make_tpkt(make_cotp_dt(response)))
        _trace(client_ip, 'mms_response',
               message='Association Response',
               response_len=len(response),
               response_hex=response.hex())
        return True
    except OSError as e:
        _trace(client_ip, 'mms_response_error', reason=str(e))
        return False


def emit_knock(client_ip, port, parsed):
    fields = extract_fields(parsed)
    knock = {
        'type': 'KNOCK',
        'proto': KNOCK_PROTO,
        'ip': client_ip,
        'tcp102_protocol': 'S7',
        's7_port': port,
        'display_format': _display_format(parsed),
        **fields,
    }
    print(json.dumps({k: v for k, v in knock.items() if v is not None}), flush=True)


def handle_connection(sock, client_ip, port):
    try:
        sock.settimeout(S7_TIMEOUT)
        print(f'🔌 S7 connect {client_ip}', flush=True)
        _trace(client_ip, 'connect')
        connected = False

        for _ in range(S7_MAX_REQUESTS):
            if is_blocked(client_ip):
                return
            try:
                payload = read_tpkt(sock)
            except S7ParseError as e:
                _trace(client_ip, 'tpkt_error', reason=str(e))
                return
            except (struct.error, socket.timeout, OSError):
                return

            try:
                pdu_type, cotp_body, s7_data = parse_cotp(payload)
            except S7ParseError as e:
                _trace(client_ip, 'cotp_error', reason=str(e))
                return

            if pdu_type == COTP_CR:
                src_ref = cotp_src_ref(cotp_body)
                try:
                    sock.sendall(make_tpkt(make_cotp_cc(src_ref)))
                except OSError:
                    return
                connected = True
                _trace(client_ip, 'connected', src_ref=f'0x{src_ref:04X}')
                continue

            if not connected or pdu_type != COTP_DT or not s7_data:
                _trace(client_ip, 'unexpected_pdu', pdu_type=f'0x{pdu_type:02X}', connected=connected)
                return

            try:
                parsed = parse_s7(s7_data)
            except S7ParseError as e:
                raw_hex = s7_data.hex()
                display_hex = s7_data[:30].hex()
                decoded_mms = decode_mms_payload(s7_data)
                _trace(client_ip, 's7_parse_error', reason=str(e), raw_hex=raw_hex)
                if decoded_mms:
                    _trace(client_ip, 'mms_detected',
                           message=decoded_mms.get('mms_message'),
                           oid=decoded_mms.get('mms_oid'),
                           request_len=len(s7_data),
                           raw_prefix=display_hex)
                # Emit a knock so unsupported TCP/102 probes appear in the feed.
                knock = {
                    'type': 'KNOCK',
                    'proto': KNOCK_PROTO,
                    'ip': client_ip,
                    'tcp102_protocol': 'MMS' if decoded_mms else 'UNKNOWN',
                    'tcp102_raw_prefix': display_hex,
                    's7_port': port,
                    's7_function_name': 'Unsupported Protocol',
                    's7_raw_prefix': display_hex,
                    'display_format': 'mms' if decoded_mms else 'other',
                }
                if decoded_mms:
                    knock.update({k: v for k, v in decoded_mms.items() if v is not None})
                print(json.dumps(knock), flush=True)
                if decoded_mms and send_mms_response(sock, client_ip, decoded_mms):
                    continue
                # Send a generic S7 error response for unknown non-MMS probes.
                if not decoded_mms:
                    try:
                        sock.sendall(make_tpkt(make_cotp_dt(
                            make_ack(0x0000, err_class=0x81, err_code=0x01)
                        )))
                    except OSError:
                        pass
                continue

            # Trace the request
            params = parsed['params']
            func = params[0] if params else None
            if parsed['msg_type'] == S7_USERDATA:
                szl_id = _szl_id_from(params, parsed.get('payload', b''))
                _trace(client_ip, 'request', msg_type='USERDATA',
                       function='SZL Read', szl_id=f'0x{szl_id:04X}' if szl_id else None)
            else:
                _trace(client_ip, 'request',
                       msg_type=f'0x{parsed["msg_type"]:02X}',
                       function=FUNC_NAMES.get(func, f'0x{func:02X}') if func is not None else None)

            try:
                sock.sendall(make_tpkt(make_cotp_dt(respond(parsed))))
            except OSError:
                return

            # Skip emitting for Setup Communication — it's just handshake
            if func == S7_FUNC_SETUP and parsed['msg_type'] == S7_JOB:
                continue

            emit_knock(client_ip, port, parsed)

    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description='Siemens S7 TCP honeypot')
    parser.add_argument('--port', type=int, default=S7_PORT)
    args = parser.parse_args()

    server = create_dualstack_tcp_listener(args.port)
    print(f'🚀 S7 Honeypot Active on Port {args.port} (IPv4+IPv6). Collecting knocks...', flush=True)
    while True:
        try:
            conn, addr = server.accept()
            client_ip = normalize_ip(addr[0])
            if is_blocked(client_ip):
                conn.close()
                continue
            threading.Thread(
                target=handle_connection,
                args=(conn, client_ip, args.port),
                daemon=True,
            ).start()
        except OSError:
            break


if __name__ == '__main__':
    main()

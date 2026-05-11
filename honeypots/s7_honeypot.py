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
        # Return minimal fake SZL module identification
        szl_data = (
            b'\x00\x22\x00\x00'  # SZL header: length=34, index=0
            + _MODULE_ORDER[:20].ljust(20, b'\x00')
            + _FIRMWARE_VER.ljust(4, b'\x00')
        )
        return make_ack(pdu_ref, data=szl_data)

    return make_ack(pdu_ref, err_class=0x81, err_code=0x01)


def extract_fields(parsed):
    """Extract knock fields from an S7 request."""
    fields = {}
    msg_type = parsed['msg_type']
    params = parsed['params']
    func = params[0] if params else None

    if msg_type == S7_USERDATA:
        fields['s7_function_name'] = 'SZL Read'
        # Userdata params: param header (4 bytes) then SZL ID at offset 4 or 6
        if len(params) >= 8:
            try:
                szl_id = struct.unpack('>H', params[6:8])[0]
                if szl_id:
                    fields['s7_szl_id'] = f'0x{szl_id:04X}'
            except Exception:
                pass
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


def emit_knock(client_ip, port, parsed):
    fields = extract_fields(parsed)
    knock = {
        'type': 'KNOCK',
        'proto': KNOCK_PROTO,
        'ip': client_ip,
        's7_port': port,
        'display_format': _display_format(parsed),
        **fields,
    }
    print(json.dumps({k: v for k, v in knock.items() if v is not None}), flush=True)


def handle_connection(sock, client_ip, port):
    try:
        sock.settimeout(S7_TIMEOUT)
        _trace(client_ip, 'connect')
        connected = False

        for _ in range(S7_MAX_REQUESTS):
            if is_blocked(client_ip):
                return
            try:
                payload = read_tpkt(sock)
            except (S7ParseError, struct.error, socket.timeout, OSError):
                return

            try:
                pdu_type, cotp_body, s7_data = parse_cotp(payload)
            except S7ParseError:
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
                return

            try:
                parsed = parse_s7(s7_data)
            except S7ParseError:
                return

            try:
                sock.sendall(make_tpkt(make_cotp_dt(respond(parsed))))
            except OSError:
                return

            # Skip emitting for Setup Communication — it's just handshake
            params = parsed['params']
            func = params[0] if params else None
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

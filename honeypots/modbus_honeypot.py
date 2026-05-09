#!/usr/bin/env python3
"""
Modbus TCP honeypot — listens on port 502, returns realistic Modbus responses,
and emits MODB JSON knocks on stdout for monitor.py.

Usage:
    python honeypots/modbus_honeypot.py
    MODB_PORT=502 python honeypots/modbus_honeypot.py
"""

import argparse
import json
import os
import random
import socket
import struct
import threading

from common import create_dualstack_tcp_listener, is_blocked, normalize_ip


MODB_PORT = int(os.environ.get('MODB_PORT', '502'))
KNOCK_PROTO = os.environ.get('KNOCK_PROTO', 'MODB').strip().upper() or 'MODB'
MODB_TIMEOUT = float(os.environ.get('MODB_TIMEOUT', '20'))
MODB_MAX_REQUESTS = int(os.environ.get('MODB_MAX_REQUESTS', '16'))
MODB_TRACE = os.environ.get('MODB_TRACE', '0').lower() not in ('0', 'false', 'no')
MODB_TRACE_IP = os.environ.get('MODB_TRACE_IP', '').strip()

FC_NAMES = {
    0x01: 'Read Coils',
    0x02: 'Read Discrete Inputs',
    0x03: 'Read Holding Registers',
    0x04: 'Read Input Registers',
    0x05: 'Write Single Coil',
    0x06: 'Write Single Register',
    0x0F: 'Write Multiple Coils',
    0x10: 'Write Multiple Registers',
    0x11: 'Report Server ID',
    0x17: 'Read/Write Multiple Registers',
    0x2B: 'Read Device Identification',
}

READ_FCS    = frozenset({0x01, 0x02, 0x03, 0x04})
WRITE_FCS   = frozenset({0x05, 0x06, 0x0F, 0x10, 0x17})
IDENTIFY_FCS = frozenset({0x11, 0x2B})

# Fake Schneider Electric Modicon M340 PLC identity
_VENDOR       = b'Schneider Electric'
_PRODUCT_CODE = b'BMX P34 2020'
_REVISION     = b'V2.60'
_VENDOR_URL   = b'www.schneider-electric.com'
_PRODUCT_NAME = b'Modicon M340'
_MODEL_NAME   = b'BMX P34 2020'
_SERVER_ID    = b'\x01\xFFModicon_M340'

# Stable fake process register values — generated once at startup
_FAKE_REGS = [random.randint(0, 32767) for _ in range(256)]


class ModbusParseError(Exception):
    pass


def _trace(client_ip, stage, **kwargs):
    if not MODB_TRACE:
        return
    if MODB_TRACE_IP and client_ip != MODB_TRACE_IP:
        return
    parts = [f'MODBTRACE ip={client_ip}', f'stage={stage}']
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f'{k}={v!r}')
    print(' '.join(parts), flush=True)


def read_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ModbusParseError('connection closed')
        buf += chunk
    return buf


def parse_mbap(sock):
    header = read_exact(sock, 7)
    transaction_id, protocol_id, length, unit_id = struct.unpack('>HHHB', header)
    return transaction_id, protocol_id, length, unit_id


def read_pdu(sock, length):
    pdu_len = length - 1  # unit_id already consumed
    if pdu_len < 1 or pdu_len > 260:
        raise ModbusParseError(f'invalid PDU length: {pdu_len}')
    return read_exact(sock, pdu_len)


def make_mbap(transaction_id, unit_id, pdu):
    return struct.pack('>HHHB', transaction_id, 0, 1 + len(pdu), unit_id) + pdu


def make_exception(fc, code):
    return bytes([fc | 0x80, code])


def _mei_obj(obj_id, value):
    return bytes([obj_id, len(value)]) + value


def build_response(fc, data):
    try:
        if fc in (0x01, 0x02):
            if len(data) < 4:
                return make_exception(fc, 0x03)
            _, quantity = struct.unpack('>HH', data[:4])
            if not (1 <= quantity <= 2000):
                return make_exception(fc, 0x03)
            byte_count = (quantity + 7) // 8
            return bytes([fc, byte_count]) + bytes(random.randint(0, 255) for _ in range(byte_count))

        elif fc in (0x03, 0x04):
            if len(data) < 4:
                return make_exception(fc, 0x03)
            address, quantity = struct.unpack('>HH', data[:4])
            if not (1 <= quantity <= 125):
                return make_exception(fc, 0x03)
            reg_bytes = b''.join(struct.pack('>H', _FAKE_REGS[(address + i) % len(_FAKE_REGS)]) for i in range(quantity))
            return bytes([fc, quantity * 2]) + reg_bytes

        elif fc in (0x05, 0x06):
            if len(data) < 4:
                return make_exception(fc, 0x03)
            return bytes([fc]) + data[:4]

        elif fc in (0x0F, 0x10):
            if len(data) < 4:
                return make_exception(fc, 0x03)
            address, quantity = struct.unpack('>HH', data[:4])
            return bytes([fc]) + struct.pack('>HH', address, quantity)

        elif fc == 0x11:
            return bytes([fc, len(_SERVER_ID)]) + _SERVER_ID

        elif fc == 0x2B:
            if len(data) < 2 or data[0] != 0x0E:
                return make_exception(fc, 0x01)
            read_code = data[1]
            objects = (
                _mei_obj(0x00, _VENDOR) +
                _mei_obj(0x01, _PRODUCT_CODE) +
                _mei_obj(0x02, _REVISION) +
                _mei_obj(0x03, _VENDOR_URL) +
                _mei_obj(0x04, _PRODUCT_NAME) +
                _mei_obj(0x05, _MODEL_NAME)
            )
            return bytes([fc, 0x0E, read_code, 0x83, 0x00, 0x00, 6]) + objects

        else:
            return make_exception(fc, 0x01)

    except Exception:
        return make_exception(fc, 0x04)


def extract_fields(fc, data):
    fields = {}
    try:
        if fc in READ_FCS and len(data) >= 4:
            address, quantity = struct.unpack('>HH', data[:4])
            fields['modb_address'] = address
            fields['modb_quantity'] = quantity

        elif fc == 0x05 and len(data) >= 4:
            address, value = struct.unpack('>HH', data[:4])
            fields['modb_address'] = address
            fields['modb_write_value'] = f'0x{value:04X}'

        elif fc == 0x06 and len(data) >= 4:
            address, value = struct.unpack('>HH', data[:4])
            fields['modb_address'] = address
            fields['modb_write_value'] = f'0x{value:04X}'

        elif fc in (0x0F, 0x10) and len(data) >= 4:
            address, quantity = struct.unpack('>HH', data[:4])
            fields['modb_address'] = address
            fields['modb_quantity'] = quantity
            if len(data) > 5:
                fields['modb_write_data'] = data[5:37].hex()  # up to 32 bytes

        elif fc == 0x2B and len(data) >= 2:
            fields['modb_mei_type'] = data[0]

    except Exception:
        pass
    return fields


def _display_format(fc):
    if fc in READ_FCS:
        return 'read'
    if fc in WRITE_FCS:
        return 'write'
    if fc in IDENTIFY_FCS:
        return 'identify'
    return 'other'


def emit_knock(client_ip, port, transaction_id, unit_id, fc, data, protocol_id):
    knock = {
        'type': 'KNOCK',
        'proto': KNOCK_PROTO,
        'ip': client_ip,
        'modb_port': port,
        'modb_unit_id': unit_id,
        'modb_fc': fc,
        'modb_fc_name': FC_NAMES.get(fc, f'Unknown (0x{fc:02X})'),
        'modb_protocol_id': protocol_id if protocol_id != 0 else None,
        'display_format': _display_format(fc),
        **extract_fields(fc, data),
    }
    print(json.dumps({k: v for k, v in knock.items() if v is not None}), flush=True)


def handle_connection(sock, client_ip, port):
    try:
        sock.settimeout(MODB_TIMEOUT)
        _trace(client_ip, 'connect')
        for _ in range(MODB_MAX_REQUESTS):
            if is_blocked(client_ip):
                return
            try:
                transaction_id, protocol_id, length, unit_id = parse_mbap(sock)
            except (ModbusParseError, struct.error, socket.timeout, OSError):
                return
            try:
                pdu = read_pdu(sock, length)
            except (ModbusParseError, socket.timeout, OSError):
                return
            if not pdu:
                return
            fc, data = pdu[0], pdu[1:]
            _trace(client_ip, 'request', fc=f'0x{fc:02X}', fc_name=FC_NAMES.get(fc), unit_id=unit_id)
            try:
                sock.sendall(make_mbap(transaction_id, unit_id, build_response(fc, data)))
            except OSError:
                return
            emit_knock(client_ip, port, transaction_id, unit_id, fc, data, protocol_id)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description='Modbus TCP honeypot')
    parser.add_argument('--port', type=int, default=MODB_PORT)
    args = parser.parse_args()
    server = create_dualstack_tcp_listener(args.port)
    print(f'🚀 MODB Honeypot Active on Port {args.port} (IPv4+IPv6). Collecting knocks...', flush=True)
    while True:
        try:
            conn, addr = server.accept()
            client_ip = normalize_ip(addr[0])
            if is_blocked(client_ip):
                conn.close()
                continue
            threading.Thread(target=handle_connection, args=(conn, client_ip, args.port), daemon=True).start()
        except OSError:
            break


if __name__ == '__main__':
    main()

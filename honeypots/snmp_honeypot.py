#!/usr/bin/env python3
"""
SNMP honeypot — listens on UDP/161, captures SNMPv1/v2c community strings
and requested OIDs, and returns small plausible MIB-II responses.
"""

import argparse
import json
import os
import socket

from common import create_dualstack_udp_listener, is_blocked, normalize_ip


SNMP_PORT = int(os.environ.get('SNMP_PORT', '161'))
KNOCK_PROTO = os.environ.get('KNOCK_PROTO', 'SNMP').strip().upper() or 'SNMP'
SNMP_TRACE = os.environ.get('SNMP_TRACE', '0').lower() not in ('0', 'false', 'no')
SNMP_TRACE_IP = os.environ.get('SNMP_TRACE_IP', '').strip()

PDU_NAMES = {
    0xA0: 'GetRequest',
    0xA1: 'GetNextRequest',
    0xA3: 'SetRequest',
    0xA5: 'GetBulkRequest',
}

# System group
SYS_DESCR     = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
SYS_UPTIME    = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SYS_CONTACT   = (1, 3, 6, 1, 2, 1, 1, 4, 0)
SYS_NAME      = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SYS_LOCATION  = (1, 3, 6, 1, 2, 1, 1, 6, 0)
SYS_SERVICES  = (1, 3, 6, 1, 2, 1, 1, 7, 0)

# Interfaces group
IF_NUMBER     = (1, 3, 6, 1, 2, 1, 2, 1, 0)
IF_INDEX_1    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1)
IF_INDEX_2    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2)
IF_DESCR_1    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)
IF_DESCR_2    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2)
IF_TYPE_1     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1)
IF_TYPE_2     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 2)
IF_MTU_1      = (1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 1)
IF_MTU_2      = (1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 2)
IF_SPEED_1    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1)
IF_SPEED_2    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 2)
IF_PHYS_1     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1)
IF_PHYS_2     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 2)
IF_ADMIN_1    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 1)
IF_ADMIN_2    = (1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 2)
IF_OPER_1     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)
IF_OPER_2     = (1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2)
IF_IN_OCTS_1  = (1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1)
IF_IN_OCTS_2  = (1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 2)
IF_OUT_OCTS_1 = (1, 3, 6, 1, 2, 1, 2, 2, 1, 16, 1)
IF_OUT_OCTS_2 = (1, 3, 6, 1, 2, 1, 2, 2, 1, 16, 2)

# IP group
IP_FORWARDING = (1, 3, 6, 1, 2, 1, 4, 1, 0)
IP_DEFAULT_TTL = (1, 3, 6, 1, 2, 1, 4, 2, 0)

NEXT_OIDS = [
    SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION, SYS_SERVICES,
    IF_NUMBER,
    IF_INDEX_1, IF_INDEX_2, IF_DESCR_1, IF_DESCR_2,
    IF_TYPE_1, IF_TYPE_2, IF_MTU_1, IF_MTU_2,
    IF_SPEED_1, IF_SPEED_2, IF_PHYS_1, IF_PHYS_2,
    IF_ADMIN_1, IF_ADMIN_2, IF_OPER_1, IF_OPER_2,
    IF_IN_OCTS_1, IF_IN_OCTS_2, IF_OUT_OCTS_1, IF_OUT_OCTS_2,
    IP_FORWARDING, IP_DEFAULT_TTL,
]


class SNMPParseError(Exception):
    pass


def trace(client_ip, stage, **kwargs):
    if not SNMP_TRACE:
        return
    if SNMP_TRACE_IP and client_ip != SNMP_TRACE_IP:
        return
    parts = [f'SNMPTRACE ip={client_ip}', f'stage={stage}']
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f'{k}={v!r}')
    print(' '.join(parts), flush=True)


def read_len(data, pos):
    if pos >= len(data):
        raise SNMPParseError('missing length')
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4 or pos + n > len(data):
        raise SNMPParseError('bad length')
    return int.from_bytes(data[pos:pos + n], 'big'), pos + n


def read_tlv(data, pos):
    if pos >= len(data):
        raise SNMPParseError('missing tag')
    tag = data[pos]
    length, value_pos = read_len(data, pos + 1)
    end = value_pos + length
    if end > len(data):
        raise SNMPParseError('length overrun')
    return tag, data[value_pos:end], end


def decode_int(value):
    if not value:
        return 0
    return int.from_bytes(value, 'big', signed=value[0] & 0x80 != 0)


def decode_oid(value):
    if not value:
        raise SNMPParseError('empty oid')
    first = value[0]
    oid = [first // 40, first % 40]
    current = 0
    for b in value[1:]:
        current = (current << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid.append(current)
            current = 0
    if current:
        raise SNMPParseError('unterminated oid')
    return tuple(oid)


def safe_text(value, limit=120):
    text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in value)
    return text[:limit]


def parse_snmp(data):
    tag, msg, end = read_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise SNMPParseError('not an SNMP sequence')
    pos = 0
    tag, value, pos = read_tlv(msg, pos)
    if tag != 0x02:
        raise SNMPParseError('missing version')
    version_int = decode_int(value)
    version = {0: '1', 1: '2c'}.get(version_int, str(version_int))
    tag, community_raw, pos = read_tlv(msg, pos)
    if tag != 0x04:
        raise SNMPParseError('missing community')
    community = safe_text(community_raw, 80)
    pdu_tag, pdu, pos = read_tlv(msg, pos)
    if pdu_tag not in PDU_NAMES:
        raise SNMPParseError(f'unsupported pdu 0x{pdu_tag:02X}')

    p = 0
    tag, value, p = read_tlv(pdu, p)
    if tag != 0x02:
        raise SNMPParseError('missing request id')
    request_id = decode_int(value)
    tag, value, p = read_tlv(pdu, p)
    if tag != 0x02:
        raise SNMPParseError('missing error/non-repeaters')
    first_status = decode_int(value)
    tag, value, p = read_tlv(pdu, p)
    if tag != 0x02:
        raise SNMPParseError('missing index/max-repetitions')
    second_status = decode_int(value)
    tag, varbinds, p = read_tlv(pdu, p)
    if tag != 0x30:
        raise SNMPParseError('missing varbind list')

    oids = []
    set_value = None
    vpos = 0
    while vpos < len(varbinds):
        tag, varbind, vpos = read_tlv(varbinds, vpos)
        if tag != 0x30:
            continue
        bpos = 0
        tag, oid_value, bpos = read_tlv(varbind, bpos)
        if tag != 0x06:
            continue
        oid = decode_oid(oid_value)
        oids.append(oid)
        if pdu_tag == 0xA3 and bpos < len(varbind):
            value_tag, raw_value, _ = read_tlv(varbind, bpos)
            set_value = format_snmp_value(value_tag, raw_value)

    return {
        'version_int': version_int,
        'version': version,
        'community': community,
        'pdu_tag': pdu_tag,
        'pdu_name': PDU_NAMES[pdu_tag],
        'request_id': request_id,
        'first_status': first_status,
        'second_status': second_status,
        'oids': oids,
        'set_value': set_value,
    }


def oid_text(oid):
    return '.'.join(str(part) for part in oid)


def format_snmp_value(tag, value):
    if tag == 0x02:
        return str(decode_int(value))
    if tag == 0x04:
        return safe_text(value, 120)
    if tag == 0x05:
        return 'NULL'
    if tag == 0x06:
        try:
            return oid_text(decode_oid(value))
        except SNMPParseError:
            return '<bad oid>'
    return f'0x{tag:02X}:{value[:30].hex()}'


def enc_len(length):
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, value):
    return bytes([tag]) + enc_len(len(value)) + value


def enc_int(value):
    if value == 0:
        raw = b'\x00'
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        if raw[0] & 0x80:
            raw = b'\x00' + raw
    return tlv(0x02, raw)


def enc_oid(oid):
    oid = tuple(oid)
    first = bytes([oid[0] * 40 + oid[1]])
    out = bytearray(first)
    for part in oid[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.append(0x80 | (part & 0x7F))
            part >>= 7
        out.extend(reversed(stack))
    return tlv(0x06, bytes(out))


def _int(n):
    return tlv(0x02, enc_int(n))

def _str(s):
    return tlv(0x04, s if isinstance(s, bytes) else s.encode())

def _counter(n):
    return tlv(0x41, n.to_bytes(4, 'big'))

def _gauge(n):
    return tlv(0x42, n.to_bytes(4, 'big'))


def snmp_value_for(oid, version_int):
    values = {
        # System group
        SYS_DESCR:     _str(b'Linux gateway snmpd 5.9; embedded network appliance'),
        SYS_OBJECT_ID: enc_oid((1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)),
        SYS_UPTIME:    tlv(0x43, (287654321).to_bytes(5, 'big').lstrip(b'\x00')),
        SYS_CONTACT:   _str(b'admin@example.local'),
        SYS_NAME:      _str(b'edge-gw-01'),
        SYS_LOCATION:  _str(b'utility closet'),
        SYS_SERVICES:  _int(78),   # physical(8)+datalink(2)+internet(4)+end-to-end(64) = gateway

        # Interfaces
        IF_NUMBER:     _int(2),
        IF_INDEX_1:    _int(1),
        IF_INDEX_2:    _int(2),
        IF_DESCR_1:    _str(b'eth0'),
        IF_DESCR_2:    _str(b'eth1'),
        IF_TYPE_1:     _int(6),    # ethernetCsmacd
        IF_TYPE_2:     _int(6),
        IF_MTU_1:      _int(1500),
        IF_MTU_2:      _int(1500),
        IF_SPEED_1:    _gauge(100_000_000),   # 100 Mbps WAN
        IF_SPEED_2:    _gauge(1_000_000_000), # 1 Gbps LAN
        IF_PHYS_1:     _str(b'\x00\x1a\x2b\x3c\x4d\x5e'),  # fake MAC
        IF_PHYS_2:     _str(b'\x00\x1a\x2b\x3c\x4d\x5f'),
        IF_ADMIN_1:    _int(1),   # up
        IF_ADMIN_2:    _int(1),
        IF_OPER_1:     _int(1),   # up
        IF_OPER_2:     _int(1),
        IF_IN_OCTS_1:  _counter(3_847_291_033),
        IF_IN_OCTS_2:  _counter(1_293_847_562),
        IF_OUT_OCTS_1: _counter(2_938_471_920),
        IF_OUT_OCTS_2: _counter(984_726_341),

        # IP group
        IP_FORWARDING:  _int(1),  # forwarding — it's a gateway
        IP_DEFAULT_TTL: _int(64),
    }
    if oid in values:
        return values[oid]
    if version_int >= 1:
        return tlv(0x80, b'')  # noSuchObject
    return tlv(0x05, b'')


def next_oid_after(oid):
    for candidate in NEXT_OIDS:
        if candidate > oid:
            return candidate
    return NEXT_OIDS[-1]


def build_response(req):
    varbind_items = []
    for oid in req['oids'][:20]:
        resp_oid = next_oid_after(oid) if req['pdu_tag'] in (0xA1, 0xA5) else oid
        varbind_items.append(tlv(0x30, enc_oid(resp_oid) + snmp_value_for(resp_oid, req['version_int'])))
    varbind_list = tlv(0x30, b''.join(varbind_items))
    pdu = tlv(0xA2, enc_int(req['request_id']) + enc_int(0) + enc_int(0) + varbind_list)
    msg = enc_int(req['version_int']) + tlv(0x04, req['community'].encode('ascii', errors='ignore')) + pdu
    return tlv(0x30, msg)


def emit_knock(client_ip, port, req):
    oids = [oid_text(oid) for oid in req['oids']]
    knock = {
        'type': 'KNOCK',
        'proto': KNOCK_PROTO,
        'ip': client_ip,
        'pass': req['community'],
        'snmp_port': port,
        'snmp_version': req['version'],
        'snmp_community': req['community'],
        'snmp_pdu': req['pdu_name'],
        'snmp_request_id': req['request_id'],
        'snmp_oid': oids[0] if oids else None,
        'snmp_oids': oids,
        'snmp_set_value': req.get('set_value'),
        'display_format': 'snmp',
    }
    if len(oids) > 1:
        knock['snmp_oid_count'] = len(oids)
    print(json.dumps({k: v for k, v in knock.items() if v is not None}), flush=True)


def udp_loop(sock, port):
    print(f'🚀 SNMP Honeypot Active on UDP Port {port}. Collecting knocks...', flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            client_ip = normalize_ip(addr[0])
            if is_blocked(client_ip):
                trace(client_ip, 'blocked')
                continue
            trace(client_ip, 'recv', bytes=len(data), raw_prefix=data[:40].hex())
            try:
                req = parse_snmp(data)
            except SNMPParseError as e:
                trace(client_ip, 'parse_error', reason=str(e))
                continue
            trace(
                client_ip,
                'parsed',
                version=req['version'],
                community=req['community'],
                pdu=req['pdu_name'],
                oid=oid_text(req['oids'][0]) if req['oids'] else None,
                oid_count=len(req['oids']),
            )
            emit_knock(client_ip, port, req)
            try:
                sock.sendto(build_response(req), addr)
                trace(client_ip, 'response_sent', oid_count=len(req['oids']))
            except OSError as e:
                trace(client_ip, 'response_error', reason=str(e))
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description='SNMP UDP honeypot')
    parser.add_argument('--port', type=int, default=SNMP_PORT)
    args = parser.parse_args()
    sock = create_dualstack_udp_listener(args.port)
    udp_loop(sock, args.port)


if __name__ == '__main__':
    main()

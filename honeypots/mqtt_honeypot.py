#!/usr/bin/env python3
"""
MQTT honeypot — captures MQTT CONNECT credentials/client metadata and emits
Knock-Knock JSON lines for monitor.py.

Examples:
    MQTT_PORT=1883 python mqtt_honeypot.py
    python mqtt_honeypot.py --port 8883 --ssl
"""

import argparse
import json
import os
import re
import socket
import ssl
import threading

from common import (
    create_dualstack_tcp_listener,
    ensure_self_signed_server_cert,
    is_blocked,
    normalize_ip,
)


MQTT_PORT = int(os.environ.get('MQTT_PORT', '1883'))
KNOCK_PROTO = os.environ.get('KNOCK_PROTO', 'MQTT').strip().upper() or 'MQTT'
MQTT_TLS_CERT_PATH = os.environ.get('MQTT_TLS_CERT_PATH', 'data/mqtt.crt')
MQTT_TLS_KEY_PATH = os.environ.get('MQTT_TLS_KEY_PATH', 'data/mqtt.key')
MAX_PACKET_SIZE = int(os.environ.get('MQTT_MAX_PACKET_SIZE', str(256 * 1024)))
READ_TIMEOUT = float(os.environ.get('MQTT_READ_TIMEOUT', '20'))
FOLLOWUP_PACKETS = int(os.environ.get('MQTT_FOLLOWUP_PACKETS', '10'))
PINGREQ_LOG_EVERY = max(1, int(os.environ.get('MQTT_PINGREQ_LOG_EVERY', '1')))
MQTT_TRACE = os.environ.get('MQTT_TRACE', '0').lower() not in ('0', 'false', 'no')
MQTT_TRACE_IP = os.environ.get('MQTT_TRACE_IP', '').strip()
MQTT_AUTH_MODE = os.environ.get('MQTT_AUTH_MODE', 'open').strip().lower()
if MQTT_AUTH_MODE not in ('open', 'require', 'reject'):
    MQTT_AUTH_MODE = 'open'

PACKET_TYPES = {
    1: 'CONNECT',
    2: 'CONNACK',
    3: 'PUBLISH',
    4: 'PUBACK',
    5: 'PUBREC',
    6: 'PUBREL',
    7: 'PUBCOMP',
    8: 'SUBSCRIBE',
    9: 'SUBACK',
    10: 'UNSUBSCRIBE',
    11: 'UNSUBACK',
    12: 'PINGREQ',
    13: 'PINGRESP',
    14: 'DISCONNECT',
    15: 'AUTH',
}


class MQTTParseError(Exception):
    pass


def _compile_signature_pattern(entry, key):
    pattern = entry.get(key)
    if not pattern:
        return None
    return re.compile(pattern, re.IGNORECASE)


def _load_signatures():
    path = os.path.join(os.path.dirname(__file__), 'mqtt_signatures.json')
    try:
        with open(path) as f:
            entries = json.load(f)
        compiled = []
        for idx, entry in enumerate(entries):
            compiled.append({
                'scanner': entry.get('scanner'),
                'exploit': entry.get('exploit'),
                'priority': int(entry.get('priority', 1000)),
                'order': idx,
                'stage_re': _compile_signature_pattern(entry, 'stage_pattern'),
                'packet_type_re': _compile_signature_pattern(entry, 'packet_type_pattern'),
                'client_id_re': _compile_signature_pattern(entry, 'client_id_pattern'),
                'protocol_name_re': _compile_signature_pattern(entry, 'protocol_name_pattern'),
                'topic_re': _compile_signature_pattern(entry, 'topic_pattern'),
            })
        compiled.sort(key=lambda e: (e['priority'], e['order']))
        print(f'[mqtt] Loaded {len(compiled)} signatures from {path}', flush=True)
        return compiled
    except Exception as ex:
        print(f'[mqtt] Failed to load mqtt_signatures.json: {ex}', flush=True)
        return []


_SIGNATURES = _load_signatures()


def _mqtt_topics(knock):
    topics = []
    if knock.get('mqtt_topic'):
        topics.append(knock['mqtt_topic'])
    for sub in knock.get('mqtt_subscriptions') or []:
        topic = sub.get('topic')
        if topic:
            topics.append(topic)
    return topics


def _match_signature(knock):
    for sig in _SIGNATURES:
        checks = []
        if sig['stage_re']:
            checks.append(bool(sig['stage_re'].search(knock.get('mqtt_stage') or '')))
        if sig['packet_type_re']:
            checks.append(bool(sig['packet_type_re'].search(knock.get('mqtt_packet_type') or '')))
        if sig['client_id_re']:
            checks.append(bool(sig['client_id_re'].search(knock.get('mqtt_client_id') or '')))
        if sig['protocol_name_re']:
            checks.append(bool(sig['protocol_name_re'].search(knock.get('mqtt_protocol_name') or '')))
        if sig['topic_re']:
            checks.append(any(sig['topic_re'].search(topic) for topic in _mqtt_topics(knock)))
        if checks and all(checks):
            return sig.get('scanner'), sig.get('exploit')
    return None, None


def annotate_signature(knock):
    scanner, exploit = _match_signature(knock)
    if scanner:
        knock['mqtt_scanner'] = scanner
    if exploit:
        knock['mqtt_exploit'] = exploit
    return knock


def set_display_format(knock):
    stage = str(knock.get('mqtt_stage') or '').lower()
    if stage in ('subscribe', 'publish', 'pingreq'):
        knock['display_format'] = 'session'
    elif stage in ('connect', 'malformed_connect', 'non_connect'):
        knock['display_format'] = stage
    else:
        knock['display_format'] = 'other'
    return knock


def safe_text(value, limit=300):
    if value is None:
        return None
    text = str(value)
    text = ''.join(ch if ch.isprintable() else '.' for ch in text)
    return text[:limit]


def read_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise MQTTParseError('peer closed')
        buf += chunk
    return buf


def read_remaining_length(sock):
    multiplier = 1
    value = 0
    encoded = []
    for _ in range(4):
        b = read_exact(sock, 1)[0]
        encoded.append(b)
        value += (b & 0x7F) * multiplier
        if value > MAX_PACKET_SIZE:
            raise MQTTParseError('packet too large')
        if (b & 0x80) == 0:
            return value, encoded
        multiplier *= 128
    raise MQTTParseError('malformed remaining length')


def read_packet(sock):
    first = read_exact(sock, 1)[0]
    remaining, encoded_rl = read_remaining_length(sock)
    body = read_exact(sock, remaining) if remaining else b''
    return first, first >> 4, first & 0x0F, remaining, encoded_rl, body


def mqtt_trace(client_ip, stage, **kwargs):
    if not MQTT_TRACE:
        return
    if MQTT_TRACE_IP and client_ip != MQTT_TRACE_IP:
        return
    parts = [f"MQTTTRACE ip={client_ip}", f"stage={stage}"]
    for k, v in kwargs.items():
        if v is not None:
            parts.append(f"{k}={v!r}")
    print(' '.join(parts), flush=True)


def packet_preview_hex(first, encoded_rl, body, limit=64):
    raw = bytes([first]) + bytes(encoded_rl or []) + (body or b'')[:limit]
    return raw.hex()


def validate_packet_shape(packet_type, flags, remaining):
    if packet_type < 1 or packet_type > 15:
        return False, 'unknown packet type'
    expected_flags = {
        1: 0,   # CONNECT
        2: 0,   # CONNACK
        4: 0,   # PUBACK
        5: 0,   # PUBREC
        6: 2,   # PUBREL
        7: 0,   # PUBCOMP
        8: 2,   # SUBSCRIBE
        9: 0,   # SUBACK
        10: 2,  # UNSUBSCRIBE
        11: 0,  # UNSUBACK
        12: 0,  # PINGREQ
        13: 0,  # PINGRESP
        14: 0,  # DISCONNECT
        15: 0,  # AUTH
    }
    if packet_type in expected_flags and flags != expected_flags[packet_type]:
        return False, f'invalid flags for {PACKET_TYPES.get(packet_type)}'
    if packet_type == 4 and remaining not in (2,) and remaining < 4:
        return False, 'invalid PUBACK remaining length'
    if packet_type in (5, 7) and remaining not in (2,) and remaining < 4:
        return False, f'invalid {PACKET_TYPES.get(packet_type)} remaining length'
    if packet_type == 12 and remaining != 0:
        return False, 'invalid PINGREQ remaining length'
    if packet_type == 13 and remaining != 0:
        return False, 'invalid PINGRESP remaining length'
    if packet_type == 1 and remaining < 10:
        return False, 'invalid CONNECT remaining length'
    return True, None


def read_u16(buf, pos):
    if pos + 2 > len(buf):
        raise MQTTParseError('truncated u16')
    return int.from_bytes(buf[pos:pos + 2], 'big'), pos + 2


def read_utf8(buf, pos):
    length, pos = read_u16(buf, pos)
    if pos + length > len(buf):
        raise MQTTParseError('truncated string')
    raw = buf[pos:pos + length]
    pos += length
    return raw.decode('utf-8', errors='replace'), pos


def skip_mqtt5_properties(buf, pos):
    multiplier = 1
    value = 0
    for _ in range(4):
        if pos >= len(buf):
            raise MQTTParseError('truncated properties')
        b = buf[pos]
        pos += 1
        value += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            end = pos + value
            if end > len(buf):
                raise MQTTParseError('truncated property body')
            return end
        multiplier *= 128
    raise MQTTParseError('malformed property length')


def parse_connect(body):
    pos = 0
    protocol_name, pos = read_utf8(body, pos)
    if pos >= len(body):
        raise MQTTParseError('missing protocol level')
    protocol_level = body[pos]
    pos += 1
    if pos >= len(body):
        raise MQTTParseError('missing connect flags')
    flags = body[pos]
    pos += 1
    keepalive, pos = read_u16(body, pos)

    version = {
        3: '3.1',
        4: '3.1.1',
        5: '5.0',
    }.get(protocol_level, str(protocol_level))

    if protocol_level == 5:
        pos = skip_mqtt5_properties(body, pos)

    client_id, pos = read_utf8(body, pos)

    username_flag = bool(flags & 0x80)
    password_flag = bool(flags & 0x40)
    will_retain = bool(flags & 0x20)
    will_qos = (flags >> 3) & 0x03
    will_flag = bool(flags & 0x04)
    clean_start = bool(flags & 0x02)

    will_topic = None
    will_payload_len = None
    if will_flag:
        if protocol_level == 5:
            pos = skip_mqtt5_properties(body, pos)
        will_topic, pos = read_utf8(body, pos)
        if protocol_level == 5:
            payload_len, pos = read_u16(body, pos)
            if pos + payload_len > len(body):
                raise MQTTParseError('truncated will payload')
            will_payload_len = payload_len
            pos += payload_len
        else:
            will_payload, pos = read_utf8(body, pos)
            will_payload_len = len(will_payload.encode('utf-8', errors='replace'))

    username = None
    password = None
    if username_flag:
        username, pos = read_utf8(body, pos)
    if password_flag:
        password, pos = read_utf8(body, pos)

    return {
        'mqtt_protocol_name': safe_text(protocol_name, 40),
        'mqtt_version': version,
        'mqtt_protocol_level': protocol_level,
        'mqtt_client_id': safe_text(client_id, 200),
        'mqtt_keepalive': keepalive,
        'mqtt_clean_start': clean_start,
        'mqtt_username_flag': username_flag,
        'mqtt_password_flag': password_flag,
        'mqtt_will_flag': will_flag,
        'mqtt_will_qos': will_qos,
        'mqtt_will_retain': will_retain,
        'mqtt_will_topic': safe_text(will_topic, 200),
        'mqtt_will_payload_len': will_payload_len,
        'user': safe_text(username, 200) if username is not None else None,
        'pass': safe_text(password, 300) if password is not None else None,
    }


def parse_subscribe_topics(body, protocol_level):
    pos = 0
    packet_id, pos = read_u16(body, pos)
    if protocol_level == 5:
        pos = skip_mqtt5_properties(body, pos)
    topics = []
    while pos < len(body):
        topic, pos = read_utf8(body, pos)
        if pos >= len(body):
            break
        qos = body[pos] & 0x03
        pos += 1
        topics.append({'topic': safe_text(topic, 200), 'qos': qos})
        if len(topics) >= 10:
            break
    return packet_id, topics


def parse_publish_topic(body, flags):
    pos = 0
    topic, pos = read_utf8(body, pos)
    qos = (flags >> 1) & 0x03
    if qos:
        _, pos = read_u16(body, pos)
    return safe_text(topic, 200), max(0, len(body) - pos), qos


def emit_knock(payload):
    if payload.get('proto') == KNOCK_PROTO and not payload.get('display_format'):
        set_display_format(payload)
    clean = {k: v for k, v in payload.items() if v is not None}
    print(json.dumps(clean), flush=True)


def send_suback(sock, protocol_level, packet_id, topic_count):
    if not packet_id:
        return
    topic_count = max(1, min(topic_count or 1, 10))
    if protocol_level == 5:
        body = packet_id.to_bytes(2, 'big') + b'\x00' + (b'\x00' * topic_count)
    else:
        body = packet_id.to_bytes(2, 'big') + (b'\x00' * topic_count)
    sock.sendall(b'\x90' + bytes([len(body)]) + body)


def send_connack(sock, protocol_level, accepted=True):
    if accepted:
        if protocol_level == 5:
            sock.sendall(b'\x20\x03\x00\x00\x00')
        else:
            sock.sendall(b'\x20\x02\x00\x00')
    else:
        if protocol_level == 5:
            sock.sendall(b'\x20\x03\x00\x86\x00')
        else:
            sock.sendall(b'\x20\x02\x00\x04')


def should_accept_connect(fields, auth_mode):
    if auth_mode == 'reject':
        return False
    if auth_mode == 'require':
        return fields.get('user') is not None or fields.get('pass') is not None
    return True


def handle_connection(client_sock, client_ip, port, tls_active=False):
    try:
        client_sock.settimeout(READ_TIMEOUT)
        print(f"🔌 MQTT connect {client_ip}", flush=True)

        first, packet_type, flags, remaining, encoded_rl, body = read_packet(client_sock)
        if packet_type != 1:
            packet_valid, invalid_reason = validate_packet_shape(packet_type, flags, remaining)
            packet_name = PACKET_TYPES.get(packet_type, str(packet_type)) if packet_valid else 'INVALID_MQTT_PACKET'
            trace_hex = packet_preview_hex(first, encoded_rl, body)
            if not packet_valid or MQTT_TRACE:
                mqtt_trace(
                    client_ip,
                    'non_connect_first_packet',
                    packet_type=packet_type,
                    claimed_packet=PACKET_TYPES.get(packet_type, str(packet_type)),
                    flags=flags,
                    remaining=remaining,
                    invalid_reason=invalid_reason,
                    first_bytes_hex=trace_hex,
                )
            emit_knock(annotate_signature({
                'type': 'KNOCK',
                'proto': KNOCK_PROTO,
                'ip': client_ip,
                'mqtt_port': port,
                'mqtt_tls': tls_active,
                'mqtt_stage': 'non_connect',
                'mqtt_packet_type': packet_name,
                'mqtt_claimed_packet_type': PACKET_TYPES.get(packet_type, str(packet_type)),
                'mqtt_packet_valid': packet_valid,
                'mqtt_packet_invalid_reason': invalid_reason,
                'mqtt_first_bytes_hex': None if packet_valid else trace_hex,
            }))
            return

        try:
            fields = parse_connect(body)
            stage = 'connect'
        except MQTTParseError as e:
            fields = {'mqtt_parse_error': safe_text(str(e), 120)}
            stage = 'malformed_connect'

        knock = {
            'type': 'KNOCK',
            'proto': KNOCK_PROTO,
            'ip': client_ip,
            'mqtt_port': port,
            'mqtt_tls': tls_active,
            'mqtt_stage': stage,
            'mqtt_auth_mode': MQTT_AUTH_MODE,
            **fields,
        }
        accepted = stage == 'connect' and should_accept_connect(fields, MQTT_AUTH_MODE)
        knock['mqtt_auth_result'] = 'accepted' if accepted else 'rejected'
        emit_knock(annotate_signature(knock))

        # CONNACK: connection accepted. This encourages simple scanners to reveal
        # early SUBSCRIBE/PUBLISH behavior without pretending to be a full broker.
        try:
            send_connack(client_sock, fields.get('mqtt_protocol_level'), accepted=accepted)
        except OSError:
            return
        if not accepted:
            return

        pingreq_count = 0
        for _ in range(FOLLOWUP_PACKETS):
            if is_blocked(client_ip):
                return
            try:
                first, packet_type, flags, remaining, encoded_rl, body = read_packet(client_sock)
            except (socket.timeout, MQTTParseError, OSError):
                return
            packet_name = PACKET_TYPES.get(packet_type, str(packet_type))
            packet_valid, invalid_reason = validate_packet_shape(packet_type, flags, remaining)
            if not packet_valid:
                packet_name = 'INVALID_MQTT_PACKET'
                mqtt_trace(
                    client_ip,
                    'invalid_followup_packet',
                    packet_type=packet_type,
                    claimed_packet=PACKET_TYPES.get(packet_type, str(packet_type)),
                    flags=flags,
                    remaining=remaining,
                    invalid_reason=invalid_reason,
                    first_bytes_hex=packet_preview_hex(first, encoded_rl, body),
                )
            followup = {
                'type': 'KNOCK',
                'proto': KNOCK_PROTO,
                'ip': client_ip,
                'mqtt_port': port,
                'mqtt_tls': tls_active,
                'mqtt_stage': packet_name.lower(),
                'mqtt_packet_type': packet_name,
                'mqtt_claimed_packet_type': PACKET_TYPES.get(packet_type, str(packet_type)) if not packet_valid else None,
                'mqtt_packet_valid': packet_valid,
                'mqtt_packet_invalid_reason': invalid_reason,
                'mqtt_client_id': fields.get('mqtt_client_id'),
                'mqtt_protocol_name': fields.get('mqtt_protocol_name'),
                'mqtt_version': fields.get('mqtt_version'),
            }
            level = fields.get('mqtt_protocol_level')
            try:
                if packet_valid and packet_type == 8:
                    packet_id, subscriptions = parse_subscribe_topics(body, level)
                    followup['mqtt_packet_id'] = packet_id
                    followup['mqtt_subscriptions'] = subscriptions
                    if subscriptions:
                        followup['mqtt_topic'] = subscriptions[0].get('topic')
                        followup['mqtt_qos'] = subscriptions[0].get('qos')
                elif packet_valid and packet_type == 3:
                    topic, payload_len, qos = parse_publish_topic(body, flags)
                    followup['mqtt_topic'] = topic
                    followup['mqtt_payload_len'] = payload_len
                    followup['mqtt_qos'] = qos
            except MQTTParseError as e:
                followup['mqtt_parse_error'] = safe_text(str(e), 120)
            if packet_valid and packet_type == 12:
                pingreq_count += 1
                followup['mqtt_pingreq_count'] = pingreq_count
                if pingreq_count == 1 or pingreq_count % PINGREQ_LOG_EVERY == 0:
                    emit_knock(annotate_signature(followup))
                try:
                    client_sock.sendall(b'\xd0\x00')
                except OSError:
                    return
            else:
                emit_knock(annotate_signature(followup))
            if packet_valid and packet_type == 8 and not followup.get('mqtt_parse_error'):
                try:
                    send_suback(client_sock, level, followup.get('mqtt_packet_id'), len(followup.get('mqtt_subscriptions', [])))
                except OSError:
                    return
    except (socket.timeout, MQTTParseError, OSError):
        pass
    finally:
        try:
            client_sock.close()
        except OSError:
            pass


def build_ssl_context(cert_path, key_path):
    ensure_self_signed_server_cert(
        cert_path=cert_path,
        key_path=key_path,
        subject='/CN=localhost/O=mosquitto/C=US',
        days=825,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def main():
    parser = argparse.ArgumentParser(description='MQTT honeypot')
    parser.add_argument('--port', type=int, default=MQTT_PORT)
    parser.add_argument('--ssl', dest='ssl', action='store_true', default=None)
    parser.add_argument('--no-ssl', dest='ssl', action='store_false')
    parser.add_argument('--ssl-cert', default=MQTT_TLS_CERT_PATH)
    parser.add_argument('--ssl-key', default=MQTT_TLS_KEY_PATH)
    args = parser.parse_args()

    use_ssl = args.ssl if args.ssl is not None else (args.port == 8883)
    ssl_context = build_ssl_context(args.ssl_cert, args.ssl_key) if use_ssl else None

    sock = create_dualstack_tcp_listener(args.port, backlog=100)
    label = 'MQTTS' if use_ssl else 'MQTT'
    print(f'🚀 {label} Honeypot Active on Port {args.port} (IPv4+IPv6). Collecting knocks...', flush=True)

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        if ssl_context:
            try:
                client = ssl_context.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError):
                client.close()
                continue
        threading.Thread(
            target=handle_connection,
            args=(client, client_ip, args.port, bool(ssl_context)),
            daemon=True,
        ).start()


if __name__ == '__main__':
    main()

import queue
import socket
import sys
import threading
import time

import pytest


def _udp_socket_or_skip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        return sock
    except PermissionError as e:
        pytest.skip(f'UDP sockets unavailable in this environment: {e}')


def _sip_invite():
    body = (
        'v=0\r\n'
        'o=- 1 1 IN IP4 127.0.0.1\r\n'
        's=test\r\n'
        'c=IN IP4 127.0.0.1\r\n'
        't=0 0\r\n'
        'm=audio 49170 RTP/AVP 0 8\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=rtpmap:8 PCMA/8000\r\n'
    )
    return {
        'method': 'INVITE',
        'uri': 'sip:+12025550123@example.net',
        'headers': {
            'via': ['SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKattacker'],
            'from': ['"caller" <sip:100@example.net>;tag=fromtag'],
            'to': ['<sip:+12025550123@example.net>'],
            'call-id': ['call-1@example.net'],
            'cseq': ['1 INVITE'],
            'contact': ['<sip:100@127.0.0.1>'],
        },
        'body': body,
    }


def _fake_pbx_response(invite, local_rtp_port):
    text = invite.decode('utf-8', errors='replace')
    call_id = _header_value(text, 'Call-ID') or 'missing'
    cseq = _header_value(text, 'CSeq') or '1 INVITE'
    from_h = _header_value(text, 'From') or '<sip:unknown@unknown>;tag=x'
    to_h = _header_value(text, 'To') or '<sip:s@127.0.0.1>'
    via = _header_value(text, 'Via') or 'SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKmissing'
    body = (
        'v=0\r\n'
        'o=- 2 2 IN IP4 127.0.0.1\r\n'
        's=pbx\r\n'
        'c=IN IP4 127.0.0.1\r\n'
        't=0 0\r\n'
        f'm=audio {local_rtp_port} RTP/AVP 0 8\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=rtpmap:8 PCMA/8000\r\n'
    ).encode()
    lines = [
        'SIP/2.0 200 OK',
        f'Via: {via}',
        f'From: {from_h}',
        f'To: {to_h};tag=pbxtag',
        f'Call-ID: {call_id}',
        f'CSeq: {cseq}',
        'Content-Type: application/sdp',
        f'Content-Length: {len(body)}',
    ]
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def _header_value(text, name):
    prefix = name.lower() + ':'
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.lower().startswith(prefix):
            return line.split(':', 1)[1].strip()
    return None


def test_sip_b2bua_fake_pbx_round_trip(monkeypatch):
    sys.path.insert(0, 'honeypots')
    import sip_b2bua

    pbx_sock = _udp_socket_or_skip()
    rtp_sock = _udp_socket_or_skip()
    sent_to_attacker = queue.Queue()
    pbx_invites = queue.Queue()
    stop = threading.Event()

    def fake_pbx():
        pbx_sock.settimeout(0.5)
        while not stop.is_set():
            try:
                data, addr = pbx_sock.recvfrom(65535)
            except socket.timeout:
                continue
            pbx_invites.put(data)
            pbx_sock.sendto(_fake_pbx_response(data, rtp_sock.getsockname()[1]), addr)
            return

    thread = threading.Thread(target=fake_pbx, daemon=True)
    thread.start()

    monkeypatch.setenv('PBX_HOST', '127.0.0.1')
    monkeypatch.setenv('PBX_PORT', str(pbx_sock.getsockname()[1]))
    monkeypatch.setenv('PBX_DIAL_POLICY', 'all')
    monkeypatch.setenv('SIP_PUBLIC_IP', '127.0.0.1')
    monkeypatch.setenv('PBX_RTP_PORT_START', '31000')
    monkeypatch.setenv('PBX_RTP_PORT_END', '31010')
    sip_b2bua.reload_config()

    bridge = sip_b2bua.maybe_start_bridge(
        req=_sip_invite(),
        client_ip='127.0.0.1',
        client_addr=('127.0.0.1', 5060),
        send_to_attacker=sent_to_attacker.put,
        dial_number='+12025550123',
        dial_country='US',
        bridge_id='testbridge',
    )
    try:
        assert bridge is not None
        outbound = pbx_invites.get(timeout=2).decode('utf-8', errors='replace')
        assert outbound.startswith('INVITE sip:12025550123@127.0.0.1 SIP/2.0')
        assert 'X-Knock-Bridge-ID: testbridge' in outbound
        assert 'X-Knock-Source-IP: 127.0.0.1' in outbound

        inbound = sent_to_attacker.get(timeout=2).decode('utf-8', errors='replace')
        assert inbound.startswith('SIP/2.0 200 OK')
        assert 'Call-ID: call-1@example.net' in inbound
        assert 'm=audio ' in inbound
        assert 'c=IN IP4 127.0.0.1' in inbound
    finally:
        stop.set()
        if bridge:
            bridge.close()
        pbx_sock.close()
        rtp_sock.close()

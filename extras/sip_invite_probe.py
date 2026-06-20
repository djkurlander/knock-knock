#!/usr/bin/env python3
"""Silent-prober SIP INVITE injector — drive a B2BUA live bridge on demand.

Sends ONE INVITE (with SDP) to the knock-knock SIP honeypot dialing a target
number, then deliberately sends NO ACK and NO RTP — exactly mimicking the
silent-abandon toll-fraud probers. With a matching live permit armed for the
printed source IP, this triggers the B2BUA's live dial-out + silence generator
without waiting for a real bot to show up. Pure test harness; sends nothing but
the one INVITE, then just listens and prints responses until --wait elapses.

Workflow:
  # 1. find the source IP this host will use toward the honeypot
  python extras/sip_invite_probe.py --host 127.0.0.1 --print-source
  # 2. arm a single-use permit for that IP + number
  python extras/sip_permit.py create <SRC_IP> +15108929741 --max-calls 1
  # 3. fire it
  python extras/sip_invite_probe.py --host 127.0.0.1 --number +15108929741
"""
import argparse
import random
import socket
import string
import time


def _token(n=10):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _source_ip(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host', default='127.0.0.1', help='honeypot SIP IP (default 127.0.0.1)')
    ap.add_argument('--port', type=int, default=5060)
    ap.add_argument('--number', default='+15108929741', help='target E.164 to dial')
    ap.add_argument('--from-user', default='1000')
    ap.add_argument('--media-port', type=int, default=40000, help='SDP audio port we advertise (we never use it)')
    ap.add_argument('--wait', type=float, default=100.0, help='seconds to listen for responses before exiting')
    ap.add_argument('--print-source', action='store_true', help='print the source IP toward --host and exit')
    args = ap.parse_args()

    if args.print_source:
        print(_source_ip(args.host, args.port))
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 0))
    s.connect((args.host, args.port))
    local_ip, local_port = s.getsockname()
    s.settimeout(1.0)

    call_id = f'{_token(16)}@silent-probe'
    branch = f'z9hG4bK{_token(12)}'
    from_tag = _token(8)
    sdp = (
        'v=0\r\n'
        f'o=- {random.randint(1, 2**31)} {random.randint(1, 2**31)} IN IP4 {local_ip}\r\n'
        's=silent-probe\r\n'
        f'c=IN IP4 {local_ip}\r\n'
        't=0 0\r\n'
        f'm=audio {args.media_port} RTP/AVP 0\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=sendrecv\r\n'
    )
    invite = (
        f'INVITE sip:{args.number}@{args.host} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n'
        'Max-Forwards: 70\r\n'
        f'From: <sip:{args.from_user}@{local_ip}>;tag={from_tag}\r\n'
        f'To: <sip:{args.number}@{args.host}>\r\n'
        f'Call-ID: {call_id}\r\n'
        'CSeq: 1 INVITE\r\n'
        f'Contact: <sip:{args.from_user}@{local_ip}:{local_port}>\r\n'
        'Content-Type: application/sdp\r\n'
        'User-Agent: silent-probe\r\n'
        f'Content-Length: {len(sdp)}\r\n'
        '\r\n'
        f'{sdp}'
    )

    print(f'source IP (permit THIS): {local_ip}   target: {args.host}:{args.port}  dial: {args.number}')
    print(f'Call-ID: {call_id}')
    print('--- sending one INVITE; will NOT ACK and will NOT send RTP (silent-abandon prober) ---')
    s.send(invite.encode())

    deadline = time.time() + args.wait
    while time.time() < deadline:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        first = data.split(b'\r\n', 1)[0].decode(errors='replace')
        print(f'[{time.strftime("%H:%M:%S")}] <- {first}')
    print('--- wait elapsed; stayed silent throughout (no ACK, no RTP) ---')


if __name__ == '__main__':
    main()

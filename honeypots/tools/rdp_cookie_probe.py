#!/usr/bin/env python3
"""Send repeated RDP X.224 cookie probes to a honeypot.

This is a manual diagnostic tool, not a CI test. It exercises the RDP cookie
fallback path by opening a fresh TCP connection for each probe and sending an
mstshash username without TLS or NLA.
"""

import argparse
import socket
import struct
import time


def build_x224_cookie_request(username):
    cookie = f"Cookie: mstshash={username}\r\n".encode("ascii")

    # X.224 Connection Request:
    # length indicator, CR TPDU, dst ref, src ref, class option
    x224 = b"\x06\xe0\x00\x00\x00\x00\x00" + cookie

    # TPKT header: version, reserved, total packet length
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def send_knock(host, port, username):
    payload = build_x224_cookie_request(username)

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload)
        try:
            response = sock.recv(1024)
            print(f"received {len(response)} response bytes")
        except socket.timeout:
            print("no response before timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=3389)
    parser.add_argument("--user", default="administrator")
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    for attempt in range(1, args.count + 1):
        try:
            send_knock(args.host, args.port, args.user)
            print(f"sent knock {attempt}/{args.count}: user={args.user!r}")
        except Exception as exc:
            print(f"knock {attempt}/{args.count} failed: {exc}")
        if attempt < args.count:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()

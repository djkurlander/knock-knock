#!/usr/bin/env python3
"""Send repeated RDP NLA authentication attempts over one TLS connection.

This is a manual diagnostic tool, not a CI test. It is useful for checking how
the RDP honeypot handles repeated CredSSP/NTLM attempts on one persistent
socket. The number of successful attempts depends on the server's
RDP_MAX_NLA_ATTEMPTS and retry timeout settings.
"""

import argparse
import socket
import ssl
import struct
import time

from impacket import ntlm


def asn1_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def asn1_seq(data):
    return b"\x30" + asn1_len(len(data)) + data


def asn1_ctx(tag, data):
    return bytes([0xA0 | tag]) + asn1_len(len(data)) + data


def asn1_int(n):
    return b"\x02\x01" + bytes([n])


def asn1_octet(data):
    return b"\x04" + asn1_len(len(data)) + data


def wrap_tsrequest(ntlm_token, version=6):
    token = asn1_ctx(0, asn1_octet(ntlm_token))
    nego = asn1_ctx(1, asn1_seq(asn1_seq(token)))
    ver = asn1_ctx(0, asn1_int(version))
    return asn1_seq(ver + nego)


def find_ntlmssp(data):
    pos = data.find(b"NTLMSSP\x00")
    return data[pos:] if pos >= 0 else None


def build_x224_request(username):
    cookie = f"Cookie: mstshash={username}\r\n".encode("ascii")
    # SSL + NLA/CredSSP
    rdp_neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x00000003)
    payload = cookie + rdp_neg
    x224 = bytes([6 + len(payload), 0xE0, 0, 0, 0, 0, 0]) + payload
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def run(host, port, username, password, domain, count, delay):
    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(build_x224_request(username))
    response = sock.recv(4096)
    print(f"received X.224 response: {len(response)} bytes")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(sock, server_hostname=host)
    tls.settimeout(10)
    print("TLS handshake complete")

    for attempt in range(1, count + 1):
        type1 = ntlm.getNTLMSSPType1("", "")
        tls.sendall(wrap_tsrequest(type1.getData()))

        challenge_data = tls.recv(4096)
        challenge = find_ntlmssp(challenge_data)
        if not challenge:
            raise RuntimeError(f"attempt {attempt}: no NTLM challenge received")

        type3, _ = ntlm.getNTLMSSPType3(
            type1, challenge, username, password, domain
        )
        tls.sendall(wrap_tsrequest(type3.getData()))

        failure = tls.recv(4096)
        print(
            f"attempt {attempt}/{count}: sent user={username!r} "
            f"domain={domain!r}; received {len(failure)} failure bytes"
        )

        if attempt < count:
            time.sleep(delay)

    tls.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=3389)
    parser.add_argument("--user", default="administrator")
    parser.add_argument("--password", default="test-password")
    parser.add_argument("--domain", default="")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    run(
        args.host,
        args.port,
        args.user,
        args.password,
        args.domain,
        args.count,
        args.delay,
    )

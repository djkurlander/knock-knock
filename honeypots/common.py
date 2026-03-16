#!/usr/bin/env python3
import os
import socket
import subprocess

import redis


def get_redis_client():
    return redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)


def is_blocked(redis_client, ip):
    try:
        return redis_client.sismember('knock:blocked', ip)
    except Exception:
        return False


def normalize_ip(ip):
    if not ip:
        return ip
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip


def create_dualstack_tcp_listener(port, backlog=100):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', port))
    sock.listen(backlog)
    return sock


def create_dualstack_udp_listener(port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', port))
    return sock


def ensure_self_signed_server_cert(cert_path, key_path, subject, san_dns=None, days=825, digest='sha256'):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    os.makedirs(os.path.dirname(cert_path) or '.', exist_ok=True)
    os.makedirs(os.path.dirname(key_path) or '.', exist_ok=True)
    addext = [
        '-addext', 'basicConstraints=critical,CA:FALSE',
        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
        '-addext', 'extendedKeyUsage=serverAuth',
    ]
    if san_dns:
        addext.extend(['-addext', f'subjectAltName=DNS:{san_dns}'])

    digest_flag = '-sha1' if digest and digest.lower() == 'sha1' else '-sha256'
    cmd = [
        'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
        digest_flag,
        '-keyout', key_path, '-x509', '-days', str(days),
        '-out', cert_path, '-subj', subject,
    ] + addext
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        fallback = [
            'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
            digest_flag,
            '-keyout', key_path, '-x509', '-days', str(days),
            '-out', cert_path, '-subj', subject,
        ]
        subprocess.run(fallback, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

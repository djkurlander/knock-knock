#!/usr/bin/env python3
import os
import socket
import subprocess

import redis


def get_redis_client():
    return redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=int(os.environ.get('REDIS_DB', '0')), decode_responses=True)


_redis = get_redis_client()


def is_blocked(ip_or_client, ip=None):
    """Check if IP is blocked. Supports both is_blocked(ip) and legacy is_blocked(redis_client, ip)."""
    if ip is None:
        # New calling convention: is_blocked(ip)
        try:
            return bool(_redis.exists(f'knock:blocked:{ip_or_client}'))
        except Exception:
            return False
    else:
        # Legacy calling convention: is_blocked(redis_client, ip)
        try:
            return bool(ip_or_client.exists(f'knock:blocked:{ip}'))
        except Exception:
            return False


def recv_line(sock, timeout=30):
    """Read one line terminated by \\r\\n or \\n. Returns decoded string."""
    sock.settimeout(timeout)
    buf = b''
    try:
        while True:
            ch = sock.recv(1)
            if not ch:
                break
            if ch == b'\n':
                break
            if ch == b'\r':
                continue
            buf += ch
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    return buf.decode('utf-8', errors='replace').strip()


def smtp_recv_line(sock, timeout=30):
    """Read one SMTP line terminated by \\r\\n or \\n, with status.
    Returns (line, status) where status is 'ok', 'timeout', 'peer_closed', or 'recv_error:...'."""
    sock.settimeout(timeout)
    buf = b''
    while True:
        try:
            ch = sock.recv(1)
        except socket.timeout:
            return '', 'timeout'
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            return '', f"recv_error:{type(e).__name__}"
        if not ch:
            line = buf.decode('utf-8', errors='replace').strip()
            return line, ('peer_closed' if not line else 'ok')
        if ch == b'\n':
            return buf.decode('utf-8', errors='replace').strip(), 'ok'
        if ch == b'\r':
            continue
        buf += ch


def get_smtp_hostname():
    """Return SMTP_HOSTNAME env var if set, otherwise resolve reverse DNS; fall back to IP."""
    override = os.environ.get('SMTP_HOSTNAME', '').strip()
    if override:
        return override
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip
    except Exception:
        return 'localhost'


def smtp_tls_cert_subject(hostname):
    cn = (hostname or 'mail.local').strip()
    if len(cn) > 64:
        cn = cn[:64]
    return f"/CN={cn}/O=Postfix/C=US"


def ensure_smtp_cert(hostname, cert_path=None, key_path=None):
    """Generate a self-signed SMTP TLS certificate if it doesn't exist."""
    cert_path = cert_path or os.environ.get('SMTP_TLS_CERT_PATH', 'data/smtp.crt')
    key_path = key_path or os.environ.get('SMTP_TLS_KEY_PATH', 'data/smtp.key')
    ensure_self_signed_server_cert(
        cert_path=cert_path,
        key_path=key_path,
        subject=smtp_tls_cert_subject(hostname),
        san_dns=hostname,
        days=825,
    )


def extract_addr(raw):
    """Pull address out of 'MAIL FROM:<addr>' or 'RCPT TO:<addr>' line."""
    raw = raw.strip()
    if '<' in raw and '>' in raw:
        addr = raw[raw.index('<') + 1:raw.index('>')]
        return '<none>' if addr == '' else addr
    return raw


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

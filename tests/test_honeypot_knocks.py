"""
Integration smoke tests: start each honeypot on a high port, drive it with
a credential attempt over a real socket, and assert that a KNOCK JSON line
appears on stdout.

These tests start honeypot subprocesses directly — they bypass monitor.py
entirely, so no Redis/SQLite/UI is touched.
"""
import asyncio
import base64
import socket

import asyncssh
import pytest

from helpers import read_knock

# High ports — avoid collisions with production and each other
_FTP_PORT   = 12121
_TNET_PORT  = 12023
_SMTP_PORT  = 12025
_HTTP_PORT  = 12080
_SSH_PORT   = 12022


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------

def test_ftp_knock(honeypot_proc):
    _, q = honeypot_proc('ftp_honeypot.py', _FTP_PORT, args=['--port', str(_FTP_PORT)])

    s = socket.create_connection(('127.0.0.1', _FTP_PORT), timeout=5)
    s.recv(256)                          # 220 banner
    s.sendall(b'USER scanbot\r\n')
    s.recv(256)                          # 331 Please specify password
    s.sendall(b'PASS hunter2\r\n')
    s.recv(256)                          # 530 Login incorrect
    s.close()

    knock = read_knock(q, 'FTP')
    assert knock['user'] == 'scanbot'
    assert knock['pass'] == 'hunter2'
    assert knock['ip']


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

def test_telnet_knock(honeypot_proc):
    _, q = honeypot_proc(
        'telnet_honeypot.py', _TNET_PORT,
        args=['--port', str(_TNET_PORT)],
        env={'TNET_DEDUP_WINDOW_SEC': '0'},   # disable dedup so 127.0.0.1 isn't suppressed
    )

    s = socket.create_connection(('127.0.0.1', _TNET_PORT), timeout=5)
    s.settimeout(3)
    # Drain IAC negotiation + login banner (may arrive in multiple chunks)
    buf = b''
    try:
        while b'login:' not in buf.lower():
            buf += s.recv(256)
    except socket.timeout:
        pass
    s.sendall(b'admin\r\n')
    # Drain echoed username chars + "Password:" prompt
    buf = b''
    try:
        while b'password:' not in buf.lower():
            buf += s.recv(256)
    except socket.timeout:
        pass
    s.sendall(b'admin123\r\n')
    # Wait for "Login incorrect" — server sends this only after emitting the KNOCK
    try:
        s.recv(256)
    except socket.timeout:
        pass
    s.close()

    knock = read_knock(q, 'TNET')
    assert knock['user'] == 'admin'
    assert knock['pass'] == 'admin123'
    assert knock['ip']


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def test_smtp_knock(honeypot_proc):
    _, q = honeypot_proc('smtp_honeypot.py', _SMTP_PORT, args=['--port', str(_SMTP_PORT)])

    s = socket.create_connection(('127.0.0.1', _SMTP_PORT), timeout=5)
    s.recv(512)                          # 220 banner
    s.sendall(b'EHLO test.local\r\n')
    s.recv(512)                          # 250 capabilities

    # AUTH LOGIN: two-step base64 exchange
    s.sendall(b'AUTH LOGIN\r\n')
    s.recv(256)                          # 334 VXNlcm5hbWU6 (Username:)
    s.sendall(base64.b64encode(b'spambot') + b'\r\n')
    s.recv(256)                          # 334 UGFzc3dvcmQ6 (Password:)
    s.sendall(base64.b64encode(b'password1') + b'\r\n')
    s.recv(256)                          # 235 Authentication successful
    s.close()

    knock = read_knock(q, 'SMTP')
    assert knock['user'] == 'spambot'
    assert knock['pass'] == 'password1'
    assert knock['ip']


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def test_http_knock(honeypot_proc):
    _, q = honeypot_proc('http_honeypot.py', _HTTP_PORT, args=['--port', str(_HTTP_PORT)])

    s = socket.create_connection(('127.0.0.1', _HTTP_PORT), timeout=5)
    creds = base64.b64encode(b'admin:password').decode()
    request = (
        f'POST /wp-login.php HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{_HTTP_PORT}\r\n'
        f'Authorization: Basic {creds}\r\n'
        f'Content-Length: 0\r\n'
        f'Connection: close\r\n'
        f'\r\n'
    )
    s.sendall(request.encode())
    s.recv(512)
    s.close()

    knock = read_knock(q, 'HTTP')
    assert knock['http_method'] == 'POST'
    assert knock['http_path'] == '/wp-login.php'
    assert knock['ip']


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def test_ssh_knock(honeypot_proc):
    tmp_dir = None  # captured via closure from the fixture's tmp_path
    _, q = honeypot_proc(
        'ssh_honeypot_asyncssh.py', _SSH_PORT,
        env={
            'SSH_PORT': str(_SSH_PORT),
            'SSH_LOGIN_TIMEOUT': '10',
            'SSH_MAX_AUTH_ATTEMPTS': '3',
        },
    )

    async def _attempt():
        try:
            await asyncssh.connect(
                '127.0.0.1', port=_SSH_PORT,
                username='root', password='toor',
                known_hosts=None,
                preferred_auth='password',
            )
        except (asyncssh.PermissionDenied, asyncssh.DisconnectError):
            pass  # expected — honeypot always rejects

    asyncio.run(_attempt())

    knock = read_knock(q, 'SSH')
    assert knock['user'] == 'root'
    assert knock['pass'] == 'toor'
    assert knock['ip']

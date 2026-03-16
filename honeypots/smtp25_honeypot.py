#!/usr/bin/env python3
import socket
import threading
import json
import os
import random
import string
import ssl
from common import (
    create_dualstack_tcp_listener,
    ensure_self_signed_server_cert,
    get_redis_client,
    is_blocked as is_blocked_common,
    normalize_ip,
)

MAX_MESSAGES_PER_SESSION = 10

_r = get_redis_client()


def is_blocked(ip):
    return is_blocked_common(_r, ip)

def _get_smtp_hostname():
    """Resolve our own reverse DNS for a realistic SMTP banner; fall back to IP."""
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

_SMTP_HOSTNAME = _get_smtp_hostname()
_BANNER = f"220 {_SMTP_HOSTNAME} ESMTP Postfix\r\n".encode()
_EHLO_RESP = (
    f"250-{_SMTP_HOSTNAME}\r\n"
    "250-SIZE 10240000\r\n"
    "250-STARTTLS\r\n"
    "250-ENHANCEDSTATUSCODES\r\n"
    "250-8BITMIME\r\n"
    "250 PIPELINING\r\n"
).encode()
_EHLO_RESP_TLS = (
    f"250-{_SMTP_HOSTNAME}\r\n"
    "250-SIZE 10240000\r\n"
    "250-ENHANCEDSTATUSCODES\r\n"
    "250-8BITMIME\r\n"
    "250 PIPELINING\r\n"
).encode()

SMTP_TLS_CERT_PATH = os.environ.get('SMTP_TLS_CERT_PATH', 'data/smtp.crt')
SMTP_TLS_KEY_PATH = os.environ.get('SMTP_TLS_KEY_PATH', 'data/smtp.key')


def _smtp_tls_cert_subject(hostname):
    cn = (hostname or 'mail.local').strip()
    if len(cn) > 64:
        cn = cn[:64]
    return f"/CN={cn}/O=Postfix/C=US"


def ensure_smtp_cert():
    ensure_self_signed_server_cert(
        cert_path=SMTP_TLS_CERT_PATH,
        key_path=SMTP_TLS_KEY_PATH,
        subject=_smtp_tls_cert_subject(_SMTP_HOSTNAME),
        san_dns=_SMTP_HOSTNAME,
        days=825,
    )


def recv_line(sock, timeout=30):
    """Read one SMTP line terminated by \\r\\n or \\n, with status."""
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

def extract_addr(raw):
    """Pull address out of 'MAIL FROM:<addr>' or 'RCPT TO:<addr>' line."""
    raw = raw.strip()
    if '<' in raw and '>' in raw:
        addr = raw[raw.index('<') + 1:raw.index('>')]
        return '<none>' if addr == '' else addr
    return raw

def handle_connection(client_sock, client_ip):
    mail_from = None
    rcpt_to = None
    subject = None
    messages = 0
    tls_active = False
    try:
        client_sock.settimeout(30)
        print(f"🔌 MAIL connect {client_ip}", flush=True)

        # Postfix-style banner
        client_sock.sendall(_BANNER)

        while True:
            line, recv_status = recv_line(client_sock)
            if recv_status != 'ok':
                break
            if not line:
                break
            upper = line.upper()

            if upper.startswith('EHLO') or upper.startswith('HELO'):
                client_sock.sendall(_EHLO_RESP_TLS if tls_active else _EHLO_RESP)

            elif upper == 'STARTTLS':
                if tls_active:
                    client_sock.sendall(b"503 5.5.1 TLS already active\r\n")
                    continue
                try:
                    client_sock.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    tls_ctx.load_cert_chain(certfile=SMTP_TLS_CERT_PATH, keyfile=SMTP_TLS_KEY_PATH)
                    client_sock = tls_ctx.wrap_socket(client_sock, server_side=True)
                    client_sock.settimeout(30)
                    tls_active = True
                    # RFC-wise client should issue EHLO again after STARTTLS.
                    continue
                except Exception:
                    break

            elif upper.startswith('MAIL FROM:'):
                mail_from = extract_addr(line[10:])
                client_sock.sendall(b"250 2.1.0 Ok\r\n")

            elif upper.startswith('RCPT TO:'):
                if rcpt_to is None:  # capture first recipient only
                    rcpt_to = extract_addr(line[8:])
                client_sock.sendall(b"250 2.1.5 Ok\r\n")

            elif upper == 'DATA':
                if mail_from is None:
                    client_sock.sendall(b"503 5.5.1 Error: need MAIL command\r\n")
                    continue
                client_sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")

                # Read email headers until blank line, pick up Subject
                client_sock.settimeout(15)
                for _ in range(200):  # cap header lines
                    hdr, hdr_status = recv_line(client_sock, timeout=15)
                    if hdr_status != 'ok':
                        break
                    if not hdr or hdr == '.':
                        break
                    if hdr.upper().startswith('SUBJECT:'):
                        subject = hdr[8:].strip()[:200]

                # Capture message body (up to 2000 chars)
                body_lines = []
                for _ in range(500):  # cap body lines
                    body_line, body_status = recv_line(client_sock, timeout=10)
                    if body_status != 'ok':
                        break
                    if body_line == '.':
                        break
                    body_lines.append(body_line)
                body = '\n'.join(body_lines)[:2000] or None

                queue_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                client_sock.sendall(f"250 2.0.0 Ok: queued as {queue_id}\r\n".encode())

                # Emit knock for this message, then reset for next MAIL FROM
                knock = {"type": "KNOCK", "proto": "MAIL", "ip": client_ip}
                if mail_from is not None:
                    knock["mail_from"] = mail_from
                if rcpt_to is not None:
                    knock["mail_to"] = rcpt_to
                if subject:
                    knock["subject"] = subject
                if body:
                    knock["body"] = body
                print(json.dumps(knock), flush=True)
                mail_from = rcpt_to = subject = None  # ready for next message

                messages += 1
                if messages >= MAX_MESSAGES_PER_SESSION:
                    client_sock.sendall(b"421 4.7.0 Try again later\r\n")
                    break

            elif upper == 'QUIT':
                client_sock.sendall(b"221 Bye\r\n")
                break

            else:
                client_sock.sendall(b"502 5.5.2 Command not implemented\r\n")

    except Exception:
        pass
    finally:
        # Emit for incomplete sessions (MAIL FROM set but DATA never reached)
        if mail_from is not None:
            knock = {"type": "KNOCK", "proto": "MAIL", "ip": client_ip, "mail_from": mail_from}
            if rcpt_to is not None:
                knock["mail_to"] = rcpt_to
            if subject:
                knock["subject"] = subject
            print(json.dumps(knock), flush=True)
        try:
            client_sock.close()
        except:
            pass

def start_honeypot():
    ensure_smtp_cert()
    sock = create_dualstack_tcp_listener(25, backlog=100)
    print("🚀 MAIL Honeypot Active on Port 25 (IPv4+IPv6). Collecting radiation...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

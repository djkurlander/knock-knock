#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import base64
import random
import string
import redis

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

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
    "250-PIPELINING\r\n"
    "250-SIZE 10240000\r\n"
    "250-VRFY\r\n"
    "250-ETRN\r\n"
    "250-STARTTLS\r\n"
    "250-AUTH LOGIN PLAIN\r\n"
    "250-AUTH=LOGIN PLAIN\r\n"
    "250-ENHANCEDSTATUSCODES\r\n"
    "250-8BITMIME\r\n"
    "250 DSN\r\n"
).encode()

def recv_line(sock, timeout=30):
    """Read one SMTP line terminated by \\r\\n or \\n."""
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

def b64decode(s):
    """Decode a base64 string, returning '' on any error."""
    try:
        return base64.b64decode(s.strip()).decode('utf-8', errors='replace')
    except Exception:
        return ''

def extract_addr(raw):
    """Pull address out of 'MAIL FROM:<addr>' or 'RCPT TO:<addr>' line."""
    raw = raw.strip()
    if '<' in raw and '>' in raw:
        return raw[raw.index('<') + 1:raw.index('>')]
    return raw

def handle_connection(client_sock, client_ip):
    username = None
    password = None
    mail_from = None
    rcpt_to = None

    try:
        client_sock.settimeout(30)
        print(f"🔌 SMTP connect {client_ip}", flush=True)
        client_sock.sendall(_BANNER)

        while True:
            line = recv_line(client_sock)
            if not line:
                break

            cmd = line.upper()

            if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                client_sock.sendall(_EHLO_RESP)

            elif cmd == 'STARTTLS':
                # Advertise STARTTLS but report unavailable — bots fall back to plain AUTH
                client_sock.sendall(b"454 4.7.0 TLS not available due to local problem\r\n")

            elif cmd.startswith('AUTH PLAIN'):
                parts = line.split(' ', 2)
                if len(parts) == 3 and parts[2].strip():
                    decoded = b64decode(parts[2])
                else:
                    client_sock.sendall(b"334 \r\n")
                    decoded = b64decode(recv_line(client_sock))
                fields = decoded.split('\x00')
                if len(fields) >= 3:
                    username, password = fields[1], fields[2]
                elif len(fields) == 2:
                    username, password = fields[0], fields[1]
                else:
                    username, password = decoded, ''
                break

            elif cmd.startswith('AUTH LOGIN'):
                client_sock.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                username = b64decode(recv_line(client_sock))
                client_sock.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                password = b64decode(recv_line(client_sock))
                break

            elif cmd.startswith('MAIL FROM:'):
                # Auth is required on submission port — always reject unauthenticated senders
                client_sock.sendall(b"530 5.5.1 Authentication required\r\n")

            elif cmd.startswith('RCPT TO:'):
                client_sock.sendall(b"530 5.5.1 Authentication required\r\n")

            elif cmd == 'DATA':
                client_sock.sendall(b"530 5.5.1 Authentication required\r\n")

            elif cmd == 'NOOP':
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd == 'RSET':
                mail_from = rcpt_to = None
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd.startswith('VRFY'):
                client_sock.sendall(b"252 2.0.0 Send some mail, I'll try my best\r\n")

            elif cmd == 'QUIT':
                client_sock.sendall(b"221 Bye\r\n")
                break

            else:
                client_sock.sendall(b"502 5.5.2 Error: command not recognized\r\n")

        if username is not None:
            print(json.dumps({"type": "KNOCK", "proto": "SMTP",
                              "ip": client_ip, "user": username, "pass": password or ''}), flush=True)
            client_sock.sendall(b"535 5.7.8 Error: authentication failed\r\n")

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def normalize_ip(ip):
    """Normalize IPv4-mapped IPv6 addresses to plain IPv4."""
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def start_honeypot():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 587))
    sock.listen(100)
    print("🚀 SMTP Honeypot Active on Port 587 (IPv4+IPv6). Collecting radiation...", flush=True)

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

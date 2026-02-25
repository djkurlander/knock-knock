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

MAX_MESSAGES_PER_SESSION = 10

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
    authed = False
    mail_from = None
    rcpt_to = None
    subject = None
    messages = 0

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
                authed = True
                client_sock.sendall(b"235 2.7.0 Authentication successful\r\n")

            elif cmd.startswith('AUTH LOGIN'):
                client_sock.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                username = b64decode(recv_line(client_sock))
                client_sock.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                password = b64decode(recv_line(client_sock))
                authed = True
                client_sock.sendall(b"235 2.7.0 Authentication successful\r\n")

            elif cmd.startswith('MAIL FROM:'):
                if not authed:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    mail_from = extract_addr(line[10:])
                    client_sock.sendall(b"250 2.1.0 Ok\r\n")

            elif cmd.startswith('RCPT TO:'):
                if not authed:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    if rcpt_to is None:
                        rcpt_to = extract_addr(line[8:])
                    client_sock.sendall(b"250 2.1.5 Ok\r\n")

            elif cmd == 'DATA':
                if not authed or mail_from is None:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    client_sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")

                    # Read headers, capture Subject
                    client_sock.settimeout(15)
                    for _ in range(200):
                        hdr = recv_line(client_sock, timeout=15)
                        if not hdr or hdr == '.':
                            break
                        if hdr.upper().startswith('SUBJECT:'):
                            subject = hdr[8:].strip()[:200]

                    # Capture message body (up to 2000 chars)
                    body_lines = []
                    for _ in range(500):
                        body_line = recv_line(client_sock, timeout=10)
                        if body_line == '.' or not body_line:
                            break
                        body_lines.append(body_line)
                    body = '\n'.join(body_lines)[:2000] or None

                    queue_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                    client_sock.sendall(f"250 2.0.0 Ok: queued as {queue_id}\r\n".encode())

                    # Emit knock with full context
                    knock = {"type": "KNOCK", "proto": "SMTP",
                             "ip": client_ip, "user": username, "pass": password or ''}
                    if subject:
                        knock["subject"] = subject
                    if body:
                        knock["body"] = body
                    if mail_from:
                        knock["mail_from"] = mail_from
                    if rcpt_to:
                        knock["rcpt_to"] = rcpt_to
                    print(json.dumps(knock), flush=True)

                    # Reset for next message in same session
                    mail_from = rcpt_to = subject = None
                    messages += 1
                    if messages >= MAX_MESSAGES_PER_SESSION:
                        client_sock.sendall(b"421 4.7.0 Try again later\r\n")
                        break

            elif cmd == 'NOOP':
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd == 'RSET':
                mail_from = rcpt_to = subject = None
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd.startswith('VRFY'):
                client_sock.sendall(b"252 2.0.0 Send some mail, I'll try my best\r\n")

            elif cmd == 'QUIT':
                client_sock.sendall(b"221 Bye\r\n")
                break

            else:
                client_sock.sendall(b"502 5.5.2 Error: command not recognized\r\n")

    except Exception:
        pass
    finally:
        # Emit for sessions where auth succeeded but DATA never completed
        if authed and username is not None and messages == 0:
            knock = {"type": "KNOCK", "proto": "SMTP",
                     "ip": client_ip, "user": username, "pass": password or ''}
            if mail_from:
                knock["mail_from"] = mail_from
            if rcpt_to:
                knock["rcpt_to"] = rcpt_to
            print(json.dumps(knock), flush=True)
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

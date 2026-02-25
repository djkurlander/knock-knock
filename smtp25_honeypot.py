#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import random
import string
import redis

MAX_MESSAGES_PER_SESSION = 10

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
    "250-SIZE 10240000\r\n"
    "250-STARTTLS\r\n"
    "250-ENHANCEDSTATUSCODES\r\n"
    "250-8BITMIME\r\n"
    "250 PIPELINING\r\n"
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

def extract_addr(raw):
    """Pull address out of 'MAIL FROM:<addr>' or 'RCPT TO:<addr>' line."""
    raw = raw.strip()
    if '<' in raw and '>' in raw:
        return raw[raw.index('<') + 1:raw.index('>')]
    return raw

def handle_connection(client_sock, client_ip):
    mail_from = None
    rcpt_to = None
    subject = None
    messages = 0
    try:
        client_sock.settimeout(30)
        print(f"🔌 MAIL connect {client_ip}", flush=True)

        # Postfix-style banner
        client_sock.sendall(_BANNER)

        while True:
            line = recv_line(client_sock)
            if not line:
                break
            upper = line.upper()

            if upper.startswith('EHLO') or upper.startswith('HELO'):
                client_sock.sendall(_EHLO_RESP)

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
                    hdr = recv_line(client_sock, timeout=15)
                    if not hdr or hdr == '.':
                        break
                    if hdr.upper().startswith('SUBJECT:'):
                        subject = hdr[8:].strip()[:200]

                # Capture message body (up to 2000 chars)
                body_lines = []
                for _ in range(500):  # cap body lines
                    body_line = recv_line(client_sock, timeout=10)
                    if body_line == '.' or not body_line:
                        break
                    body_lines.append(body_line)
                body = '\n'.join(body_lines)[:2000] or None

                queue_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                client_sock.sendall(f"250 2.0.0 Ok: queued as {queue_id}\r\n".encode())

                # Emit knock for this message, then reset for next MAIL FROM
                knock = {"type": "KNOCK", "proto": "MAIL",
                         "ip": client_ip, "user": mail_from, "pass": rcpt_to or ''}
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
            knock = {"type": "KNOCK", "proto": "MAIL",
                     "ip": client_ip, "user": mail_from, "pass": rcpt_to or ''}
            if subject:
                knock["subject"] = subject
            print(json.dumps(knock), flush=True)
        try:
            client_sock.close()
        except:
            pass

def normalize_ip(ip):
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def start_honeypot():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 25))
    sock.listen(100)
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

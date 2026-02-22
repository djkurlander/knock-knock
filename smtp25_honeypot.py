#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import time

BLOCKLIST_FILE = os.environ.get('DB_DIR', 'data') + '/blocklist.txt'
BLOCKLIST_RELOAD_INTERVAL = 60
MAX_MESSAGES_PER_SESSION = 10

_blocklist_cache = set()
_blocklist_last_load = 0

def get_blocklist():
    global _blocklist_cache, _blocklist_last_load
    now = time.time()
    if now - _blocklist_last_load > BLOCKLIST_RELOAD_INTERVAL:
        _blocklist_last_load = now
        if os.path.exists(BLOCKLIST_FILE):
            try:
                with open(BLOCKLIST_FILE, 'r') as f:
                    _blocklist_cache = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
            except:
                pass
    return _blocklist_cache

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
        client_sock.sendall(b"220 mail.example.com ESMTP Postfix\r\n")

        while True:
            line = recv_line(client_sock)
            if not line:
                break
            upper = line.upper()

            if upper.startswith('EHLO') or upper.startswith('HELO'):
                client_sock.sendall(
                    b"250-mail.example.com\r\n"
                    b"250-SIZE 10240000\r\n"
                    b"250 ENHANCEDSTATUSCODES\r\n"
                )

            elif upper.startswith('MAIL FROM:'):
                mail_from = extract_addr(line[10:])
                client_sock.sendall(b"250 OK\r\n")

            elif upper.startswith('RCPT TO:'):
                if rcpt_to is None:  # capture first recipient only
                    rcpt_to = extract_addr(line[8:])
                client_sock.sendall(b"250 OK\r\n")

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

                # Drain message body
                for _ in range(500):  # cap body lines
                    body = recv_line(client_sock, timeout=10)
                    if body == '.' or not body:
                        break

                client_sock.sendall(b"250 OK: Message queued\r\n")

                # Emit knock for this message, then reset for next MAIL FROM
                knock = {"type": "KNOCK", "proto": "MAIL",
                         "ip": client_ip, "user": mail_from, "pass": rcpt_to or ''}
                if subject:
                    knock["subject"] = subject
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
        if client_ip in get_blocklist():
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

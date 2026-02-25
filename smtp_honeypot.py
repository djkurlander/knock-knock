#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import base64
import redis

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

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

def handle_connection(client_sock, client_ip):
    try:
        client_sock.settimeout(30)
        print(f"🔌 SMTP connect {client_ip}", flush=True)

        # Realistic Postfix banner
        client_sock.sendall(b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")

        username = None
        password = None

        while True:
            line = recv_line(client_sock)
            if not line:
                break

            cmd = line.upper()

            if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                client_sock.sendall(
                    b"250-mail.example.com\r\n"
                    b"250-SIZE 10240000\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n"
                    b"250 ENHANCEDSTATUSCODES\r\n"
                )

            elif cmd.startswith('AUTH PLAIN'):
                # Two forms:
                #   AUTH PLAIN <base64>          — credentials inline
                #   AUTH PLAIN + blank challenge — credentials on next line
                parts = line.split(' ', 2)
                if len(parts) == 3 and parts[2].strip():
                    decoded = b64decode(parts[2])
                else:
                    client_sock.sendall(b"334 \r\n")
                    decoded = b64decode(recv_line(client_sock))

                # Wire format: \x00username\x00password  (authzid may precede)
                fields = decoded.split('\x00')
                if len(fields) >= 3:
                    username, password = fields[1], fields[2]
                elif len(fields) == 2:
                    username, password = fields[0], fields[1]
                else:
                    username, password = decoded, ''
                break

            elif cmd.startswith('AUTH LOGIN'):
                # Challenge-response: base64("Username:") then base64("Password:")
                client_sock.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                username = b64decode(recv_line(client_sock))
                client_sock.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                password = b64decode(recv_line(client_sock))
                break

            elif cmd.startswith('QUIT'):
                client_sock.sendall(b"221 Bye\r\n")
                break

            else:
                # Covers STARTTLS, MAIL FROM, RCPT TO, etc. — not supported
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
    # Dual-stack socket: accepts both IPv4 and IPv6
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

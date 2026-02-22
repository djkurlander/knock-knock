#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import time

BLOCKLIST_FILE = os.environ.get('DB_DIR', 'data') + '/blocklist.txt'
BLOCKLIST_RELOAD_INTERVAL = 60

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

MAX_LOGIN_ATTEMPTS = 3

def handle_connection(client_sock, client_ip):
    username = None
    attempts = 0
    try:
        client_sock.settimeout(30)
        print(f"🔌 FTP connect {client_ip}", flush=True)
        client_sock.sendall(b"220 (vsFTPd 3.0.3)\r\n")

        while True:
            line = recv_line(client_sock)
            if not line:
                break
            upper = line.upper()

            if upper.startswith('USER '):
                username = line[5:].strip()
                client_sock.sendall(b"331 Please specify the password.\r\n")

            elif upper.startswith('PASS '):
                password = line[5:].strip()
                knock = {"type": "KNOCK", "proto": "FTP",
                         "ip": client_ip, "user": username or '', "pass": password}
                print(json.dumps(knock), flush=True)
                attempts += 1
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    client_sock.sendall(b"421 Service not available, remote server has closed connection\r\n")
                    break
                client_sock.sendall(b"530 Login incorrect.\r\n")
                username = None  # reset for next attempt

            elif upper == 'QUIT':
                client_sock.sendall(b"221 Goodbye.\r\n")
                break

            else:
                client_sock.sendall(b"530 Please login with USER and PASS.\r\n")

    except Exception:
        pass
    finally:
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
    sock.bind(('::', 21))
    sock.listen(100)
    print("🚀 FTP Honeypot Active on Port 21 (IPv4+IPv6). Collecting radiation...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if client_ip in get_blocklist():
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

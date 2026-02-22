#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import time
import struct

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

def read_initial_packet(sock, timeout=10):
    """Read the initial RDP TPKT/X.224 Connection Request."""
    sock.settimeout(timeout)
    try:
        # Read TPKT header (4 bytes): version, reserved, length (big-endian)
        header = b''
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return b''
            header += chunk
        if header[0] != 0x03:  # Not a valid TPKT packet
            return header
        pkt_len = struct.unpack('>H', header[2:4])[0]
        # Read remainder, capped at 4096 bytes
        body = b''
        remaining = min(pkt_len - 4, 4092)
        while len(body) < remaining:
            chunk = sock.recv(remaining - len(body))
            if not chunk:
                break
            body += chunk
        return header + body
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        return b''

def extract_username(data):
    """
    Extract username and domain from the RDP X.224 Connection Request cookie.
    Cookie format: 'Cookie: mstshvcookie: msts=DOMAIN\\username\\r\\n'
    Returns (username, domain) or (None, None) if not present.
    """
    try:
        text = data.decode('ascii', errors='replace')
        marker = 'mstshvcookie: msts='
        if marker not in text:
            return None, None
        start = text.index(marker) + len(marker)
        end = text.find('\r\n', start)
        if end == -1:
            end = start + 128
        value = text[start:end].strip()
        if '\\' in value:
            domain, username = value.split('\\', 1)
            return username, domain
        return value, ''
    except Exception:
        return None, None

def handle_connection(client_sock, client_ip):
    try:
        print(f"🔌 RDP connect {client_ip}", flush=True)
        data = read_initial_packet(client_sock)
        if data:
            username, domain = extract_username(data)
            if username:
                knock = {"type": "KNOCK", "proto": "RDP",
                         "ip": client_ip, "user": username, "pass": domain}
                print(json.dumps(knock), flush=True)
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
    sock.bind(('::', 3389))
    sock.listen(100)
    print("🚀 RDP Honeypot Active on Port 3389 (IPv4+IPv6). Collecting radiation...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if client_ip in get_blocklist():
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()

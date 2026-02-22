#!/root/knock-knock/.venv/bin/python
import socket
import threading
import os
import time
import argparse

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

def normalize_ip(ip):
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def handle_connection(client_sock, client_ip, proto):
    try:
        print(f"🔌 {proto} connect {client_ip}", flush=True)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_honeypot(port, proto):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', port))
    sock.listen(100)
    print(f"🚀 {proto} Stub Honeypot Active on Port {port} (IPv4+IPv6)", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if client_ip in get_blocklist():
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip, proto), daemon=True).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generic connection-logging honeypot stub")
    parser.add_argument('--port', type=int, required=True, help="Port to listen on")
    parser.add_argument('--proto', required=True, help="Protocol name for log messages")
    args = parser.parse_args()
    start_honeypot(args.port, args.proto)
